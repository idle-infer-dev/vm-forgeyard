from __future__ import annotations

import json
import shutil
import threading
import time
from pathlib import Path

from .db import Registry
from .executor import ExecutorClient


class RunMonitor:
    def __init__(self, registry: Registry, executor: ExecutorClient, interval_s: float = 5.0):
        self.registry = registry
        self.executor = executor
        self.interval_s = interval_s
        self._thread: threading.Thread | None = None
        self._started = False
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._disk_full_state: dict[tuple[int, str], bool] = {}
        self._run_disk_pressure_active: dict[int, bool] = {}

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run, name="kvm-control-run-monitor", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            if not self._started:
                return
            self._started = False
            self._stop_event.set()
            thread = self._thread
            self._thread = None
        if thread is not None:
            thread.join(timeout=max(1.0, self.interval_s + 0.5))

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.sample_all_runs()
            except Exception:
                # Keep the monitor alive; failures are surfaced through explicit API calls.
                pass
            self._stop_event.wait(self.interval_s)

    def sample_all_runs(self) -> None:
        self._shutdown_expired_namespace_leases()
        for run in self.registry.active_runs():
            disk_bytes, ram_mb, vms = self._measure_run(run)
            self.registry.record_run_usage_sample(run["id"], disk_bytes, ram_mb)
            self._detect_disk_full(run, vms)

    def _shutdown_expired_namespace_leases(self) -> None:
        for lock in self.registry.list_expired_namespace_lock_leases():
            namespace = lock["namespace"]
            self.registry.mark_lock_lease_expired(int(lock["id"]))
            vms = [
                vm
                for vm in self.registry.list_vms_for_namespace(namespace)
                if vm["network_id"] != "live" and vm["power_state"] in {"starting", "running", "paused"}
            ]
            self.registry.record_status_event(
                kind="lease",
                level="warning",
                status="expired",
                namespace=namespace,
                resource_id=lock["resource_id"],
                summary=f"namespace lock lease expired for {namespace}; shutting down {len(vms)} VM(s)",
                details={
                    "request_id": lock["id"],
                    "resource_id": lock["resource_id"],
                    "lease_expires_at": lock["lease_expires_at"],
                    "vm_ids": [vm["vm_id"] for vm in vms],
                },
            )
            for vm in vms:
                try:
                    self.executor.run(
                        "stop-vm",
                        {
                            "namespace": namespace,
                            "vm_id": vm["vm_id"],
                            "layer2_path": vm["layer2_path"],
                            "layer3_path": vm["layer3_path"],
                        },
                    )
                    self.registry.patch_vm(
                        vm["vm_id"],
                        power_state="stopped",
                        readiness_state="configuring",
                        status="stopped",
                        pause_reason=None,
                    )
                    self.registry.record_status_event(
                        kind="lease",
                        level="info",
                        status="shutdown",
                        namespace=namespace,
                        vm_id=vm["vm_id"],
                        resource_id=lock["resource_id"],
                        summary=f"vm {vm['vm_id']} stopped after namespace lock lease expiry",
                        details={"request_id": lock["id"], "resource_id": lock["resource_id"]},
                    )
                except Exception as exc:
                    self.registry.record_status_event(
                        kind="lease",
                        level="error",
                        status="shutdown_failed",
                        namespace=namespace,
                        vm_id=vm["vm_id"],
                        resource_id=lock["resource_id"],
                        summary=f"failed to stop vm {vm['vm_id']} after namespace lock lease expiry",
                        details={"request_id": lock["id"], "resource_id": lock["resource_id"], "error": str(exc)},
                    )

    def _measure_run(self, run: dict) -> tuple[int, int, list[dict]]:
        vm_ids = run.get("vm_ids") or []
        vms = self.registry.list_vms_for_ids(vm_ids) if vm_ids else self.registry.list_vms_for_namespace(run["namespace"])
        layer2_paths = {vm["layer2_path"] for vm in vms if vm["layer2_presence"] == "present"}
        layer3_paths = [vm["layer3_path"] for vm in vms if vm["layer3_presence"] == "present"]
        disk_bytes = sum(_safe_size(Path(path)) for path in layer2_paths)
        disk_bytes += sum(_safe_size(Path(path)) for path in layer3_paths)
        ram_mb = sum(int(vm["memory_mb"]) for vm in vms if vm["power_state"] in {"starting", "running", "paused"})
        return disk_bytes, ram_mb, vms

    def _detect_disk_full(self, run: dict, vms: list[dict]) -> None:
        threshold = self.registry.config.storage.disk_full_threshold_bytes
        pools = {
            "layer2": any(vm["layer2_presence"] == "present" for vm in vms),
            "layer3": any(vm["layer3_presence"] == "present" for vm in vms),
        }
        paths = {
            "layer2": self.registry.config.storage.layer2_dir,
            "layer3": self.registry.config.storage.layer3_dir,
        }
        pressure_now = False
        for pool_name, in_use in pools.items():
            state_key = (int(run["id"]), pool_name)
            if not in_use:
                self._disk_full_state.pop(state_key, None)
                continue
            free_bytes = self._pool_free_bytes(pool_name, paths[pool_name])
            if free_bytes <= threshold:
                pressure_now = True
                if not self._disk_full_state.get(state_key):
                    self.registry.create_run_event(
                        run_id=int(run["id"]),
                        stage_id=None,
                        event_type="disk_full",
                        message=f"host monitor detected low free space in {pool_name} pool",
                        details={
                            "source": "host_monitor",
                            "pool": pool_name,
                            "free_bytes": free_bytes,
                            "threshold_bytes": threshold,
                            "namespace": run["namespace"],
                        },
                    )
                    self._disk_full_state[state_key] = True
            else:
                if self._disk_full_state.pop(state_key, None):
                    self.registry.create_run_event(
                        run_id=int(run["id"]),
                        stage_id=None,
                        event_type="info",
                        message=f"host monitor detected free space recovery in {pool_name} pool",
                        details={
                            "source": "host_monitor",
                            "pool": pool_name,
                            "free_bytes": free_bytes,
                            "threshold_bytes": threshold,
                            "namespace": run["namespace"],
                        },
                    )
        run_id = int(run["id"])
        if pressure_now and not self._run_disk_pressure_active.get(run_id):
            self._pause_vms_for_disk_pressure(run, vms, threshold)
            self._run_disk_pressure_active[run_id] = True
        elif not pressure_now and self._run_disk_pressure_active.pop(run_id, None):
            self._resume_vms_after_disk_recovery(run, vms, threshold)

    def _pause_vms_for_disk_pressure(
        self,
        run: dict,
        vms: list[dict],
        threshold: int,
    ) -> None:
        active_stage = self.registry.get_active_run_stage(int(run["id"]))
        self.registry.start_run_pause(int(run["id"]), "disk_full", active_stage["stage_id"] if active_stage else None)
        for vm in vms:
            current = self.registry.get_vm(vm["vm_id"])
            if current is None or current["power_state"] != "running":
                continue
            self.executor.run(
                "pause-vm",
                {
                    "vm_id": current["vm_id"],
                    "layer2_path": current["layer2_path"],
                    "layer3_path": current["layer3_path"],
                },
            )
            self.registry.patch_vm(current["vm_id"], power_state="paused", status="paused", pause_reason="disk_full")
            self.registry.create_run_event(
                run_id=int(run["id"]),
                stage_id=None,
                event_type="warning",
                message=f"vm {current['vm_id']} paused due to low free space",
                details={
                    "source": "host_monitor",
                    "vm_id": current["vm_id"],
                    "threshold_bytes": threshold,
                    "namespace": run["namespace"],
                    "reason": "disk_full",
                },
            )

    def _resume_vms_after_disk_recovery(
        self,
        run: dict,
        vms: list[dict],
        threshold: int,
    ) -> None:
        self.registry.finish_run_pause(int(run["id"]), "disk_full")
        for vm in vms:
            current = self.registry.get_vm(vm["vm_id"])
            if current is None or current["power_state"] != "paused" or current.get("pause_reason") != "disk_full":
                continue
            self.executor.run(
                "resume-vm",
                {
                    "vm_id": current["vm_id"],
                    "layer2_path": current["layer2_path"],
                    "layer3_path": current["layer3_path"],
                },
            )
            self.registry.patch_vm(current["vm_id"], power_state="running", status="running", pause_reason=None)
            self.registry.create_run_event(
                run_id=int(run["id"]),
                stage_id=None,
                event_type="info",
                message=f"vm {current['vm_id']} resumed after free space recovered",
                details={
                    "source": "host_monitor",
                    "vm_id": current["vm_id"],
                    "threshold_bytes": threshold,
                    "namespace": run["namespace"],
                    "reason": "disk_full",
                },
            )

    def _pool_free_bytes(self, pool_name: str, pool_path: Path) -> int:
        override = self._read_disk_usage_override(pool_name)
        if override is not None:
            return override
        return shutil.disk_usage(pool_path).free

    def _read_disk_usage_override(self, pool_name: str) -> int | None:
        if not self.registry.config.dry_run:
            return None
        override_path = self.registry.config.storage.state_dir / "disk-usage-overrides.json"
        try:
            payload = json.loads(override_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError, TypeError):
            return None
        pool_override = payload.get(pool_name)
        if isinstance(pool_override, dict):
            free_bytes = pool_override.get("free_bytes")
        else:
            free_bytes = pool_override
        try:
            return int(free_bytes) if free_bytes is not None else None
        except (TypeError, ValueError):
            return None


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0
