from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .config import AppConfig
from .db import Registry
from .executor import ExecutorClient


def _parse_db_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except ValueError:
        return None


def _stopped_reference_time(vm: dict[str, Any]) -> datetime | None:
    stopped_at = _parse_db_timestamp(vm.get("stopped_at"))
    if stopped_at is not None:
        return stopped_at
    try:
        layer3 = Path(vm["layer3_path"])
        if layer3.exists():
            return datetime.fromtimestamp(layer3.stat().st_mtime, UTC)
    except OSError:
        pass
    return _parse_db_timestamp(vm.get("updated_at")) or _parse_db_timestamp(vm.get("created_at"))


def stop_vm_for_cleanup(executor: ExecutorClient, vm: dict[str, Any], operation_id: int, *, enforce_poweroff: bool) -> dict[str, Any]:
    payload = {
        "operation_id": operation_id,
        "namespace": vm["namespace"],
        "vm_id": vm["vm_id"],
        "layer2_path": vm["layer2_path"],
        "layer3_path": vm["layer3_path"],
    }
    try:
        return executor.run("stop-vm", payload)
    except Exception as exc:
        if not enforce_poweroff:
            raise
        result = executor.run("poweroff-vm", payload)
        result["forced_after_stop_error"] = str(exc)
        return result


def cleanup_stale_stopped_ephemeral_vms(config: AppConfig, registry: Registry, executor: ExecutorClient) -> dict[str, Any]:
    ttl_seconds = config.cleanup.stopped_ephemeral_vm_ttl_seconds
    now = datetime.now(UTC)
    candidates = []
    for vm in registry.list_stopped_ephemeral_vms():
        delete_requested = vm.get("status") == "deleting"
        reference_time = _stopped_reference_time(vm)
        if reference_time is None and not delete_requested:
            continue
        if delete_requested or (ttl_seconds > 0 and reference_time is not None and reference_time <= now - timedelta(seconds=ttl_seconds)):
            vm = dict(vm)
            vm["stopped_reference_at"] = reference_time.isoformat() if reference_time is not None else None
            vm["cleanup_reason"] = "vm_delete_deferred" if delete_requested else "stopped_ephemeral_vm_ttl_expired"
            candidates.append(vm)
    cleaned: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for vm in candidates:
        vm_id = vm["vm_id"]
        operation_id = registry.create_operation(
            "cleanup-stale-ephemeral-vm",
            vm_id,
            vm["namespace"],
            "running",
            details={"stopped_reference_at": vm["stopped_reference_at"], "ttl_seconds": ttl_seconds, "cleanup_reason": vm["cleanup_reason"]},
        )
        try:
            stop_vm_for_cleanup(executor, vm, operation_id, enforce_poweroff=vm["cleanup_reason"] == "vm_delete_deferred")
            layer3_delete_result = executor.run(
                "delete-layer3",
                {
                    "operation_id": operation_id,
                    "vm_id": vm_id,
                    "layer2_path": vm["layer2_path"],
                    "layer3_path": vm["layer3_path"],
                },
            )
            trashed_path = layer3_delete_result.get("trashed_path")
            if trashed_path:
                registry.record_archived_vm(
                    vm,
                    trashed_path=trashed_path,
                    reason=vm["cleanup_reason"],
                    metadata={
                        "operation_id": operation_id,
                        "ttl_seconds": ttl_seconds,
                        "stopped_reference_at": vm["stopped_reference_at"],
                        "cleanup_reason": vm["cleanup_reason"],
                    },
                )
            executor.run(
                "delete-runtime",
                {
                    "namespace": vm["namespace"],
                    "vm_id": vm_id,
                    "layer2_path": vm["layer2_path"],
                    "layer3_path": vm["layer3_path"],
                },
            )
            registry.delete_vm(vm_id)
            registry.update_operation(operation_id, "completed")
            registry.record_status_event(
                kind="cleanup",
                level="info",
                status="deleted",
                namespace=vm["namespace"],
                vm_id=vm_id,
                operation_id=operation_id,
                summary=f"deleted stale stopped ephemeral vm {vm_id}",
                details={"stopped_reference_at": vm["stopped_reference_at"], "ttl_seconds": ttl_seconds},
            )
            cleaned.append({"vm_id": vm_id, "namespace": vm["namespace"], "stopped_reference_at": vm["stopped_reference_at"], "cleanup_reason": vm["cleanup_reason"]})
        except Exception as exc:
            registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            registry.record_status_event(
                kind="cleanup",
                level="error",
                status="failed",
                namespace=vm["namespace"],
                vm_id=vm_id,
                operation_id=operation_id,
                summary=f"failed to delete stale stopped ephemeral vm {vm_id}",
                details={"error": str(exc), "stopped_reference_at": vm["stopped_reference_at"], "ttl_seconds": ttl_seconds},
            )
            failed.append({"vm_id": vm_id, "namespace": vm["namespace"], "error": str(exc)})
    return {"ttl_seconds": ttl_seconds, "candidates": len(candidates), "cleaned": cleaned, "failed": failed}


def cleanup_stale_trash_files(config: AppConfig, registry: Registry, executor: ExecutorClient) -> dict[str, Any]:
    ttl_seconds = config.cleanup.trash_file_ttl_seconds
    if ttl_seconds <= 0:
        return {"ttl_seconds": ttl_seconds, "deleted": [], "failed": [], "skipped": "disabled"}
    try:
        result = executor.run("cleanup-trash", {"ttl_seconds": ttl_seconds})
    except Exception as exc:
        registry.record_status_event(
            kind="cleanup",
            level="error",
            status="failed",
            summary="failed to clean stale trash files",
            details={"ttl_seconds": ttl_seconds, "error": str(exc)},
        )
        return {"ttl_seconds": ttl_seconds, "deleted": [], "failed": [{"error": str(exc)}]}

    deleted = result.get("deleted_files") or []
    failed = result.get("failed_files") or []
    if deleted or failed:
        registry.record_status_event(
            kind="cleanup",
            level="error" if failed else "info",
            status="failed" if failed else "deleted",
            summary=f"cleaned {len(deleted)} stale trash file(s)",
            details={"ttl_seconds": ttl_seconds, "deleted_files": deleted, "failed_files": failed},
        )
    return {"ttl_seconds": ttl_seconds, "deleted": deleted, "failed": failed}
