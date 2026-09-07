from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .service import build_services
from .vm_cleanup import cleanup_stale_stopped_ephemeral_vms, cleanup_stale_trash_files


ACTIVE_POWER_STATES = {"starting", "running", "paused"}
STOPPED_POWER_STATES = {"stopped", "failed"}


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except ValueError:
        return None


def _db_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")


def _layer3_mtime(vm: dict[str, Any]) -> datetime | None:
    try:
        path = Path(vm["layer3_path"])
        if path.exists():
            return datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError:
        return None
    return None


def _stopped_at_for_inspected_state(vm: dict[str, Any], result: dict[str, Any]) -> str | None:
    power_state = result.get("power_state")
    if power_state not in STOPPED_POWER_STATES:
        return None
    if vm.get("stopped_at"):
        return str(vm["stopped_at"])
    previous_state = vm.get("power_state")
    host_booted_at = _parse_timestamp(result.get("host_booted_at"))
    updated_at = _parse_timestamp(vm.get("updated_at"))
    inspected_at = _parse_timestamp(result.get("inspected_at")) or datetime.now(UTC)
    if previous_state in ACTIVE_POWER_STATES:
        if host_booted_at is not None and (updated_at is None or updated_at <= host_booted_at):
            return _db_timestamp(host_booted_at)
        return _db_timestamp(inspected_at)
    reference = _layer3_mtime(vm) or updated_at or inspected_at
    return _db_timestamp(reference)


def reconcile_registered_vm_runtime_states(services) -> dict[str, Any]:
    inspected: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for vm in services.registry.list_vms():
        if vm["power_state"] not in ACTIVE_POWER_STATES and vm.get("stopped_at"):
            continue
        operation_id = services.registry.create_operation("reconcile-runtime-state", vm["vm_id"], vm["namespace"], "running")
        try:
            result = services.executor.run(
                "inspect-vm",
                {
                    "operation_id": operation_id,
                    "namespace": vm["namespace"],
                    "vm_id": vm["vm_id"],
                    "layer2_path": vm["layer2_path"],
                    "layer3_path": vm["layer3_path"],
                    "reserved_mac": vm["reserved_mac"],
                },
            )
            updates: dict[str, Any] = {}
            power_state = result.get("power_state")
            if power_state == "running":
                updates.update(power_state="running", status="running", stopped_at=None)
            elif power_state == "paused":
                updates.update(power_state="paused", status="paused", stopped_at=None)
            elif power_state == "stopped":
                stopped_at = _stopped_at_for_inspected_state(vm, result)
                updates.update(power_state="stopped", status="stopped", readiness_state="configuring", stopped_at=stopped_at)
            elif power_state == "failed":
                stopped_at = _stopped_at_for_inspected_state(vm, result)
                updates.update(power_state="failed", status="failed", readiness_state="failed", stopped_at=stopped_at)
            if updates:
                services.registry.patch_vm(vm["vm_id"], **updates)
            services.registry.update_operation(operation_id, "completed", details=result)
            inspected.append({"vm_id": vm["vm_id"], "power_state": power_state, "stopped_at": updates.get("stopped_at")})
        except Exception as exc:
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            failed.append({"vm_id": vm["vm_id"], "error": str(exc)})
    return {"inspected": inspected, "failed": failed}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config")
    args = parser.parse_args()

    services = build_services(args.config, start_monitor=False)
    tracked_vm_ids = [vm["vm_id"] for vm in services.registry.list_vms()]
    services.executor.run("reconcile-runtime", {"tracked_vm_ids": tracked_vm_ids})
    reconcile_registered_vm_runtime_states(services)
    cleanup_stale_stopped_ephemeral_vms(services.config, services.registry, services.executor)
    cleanup_stale_trash_files(services.config, services.registry, services.executor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
