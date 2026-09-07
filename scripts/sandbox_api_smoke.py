#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def _write_config(root: Path, control_port: int, lock_port: int, disk_full_threshold_bytes: int | None = None) -> Path:
    base_dir = root / "base"
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "ubuntu-24.04-base.qcow2").write_text(json.dumps({"format": "qcow2"}), encoding="utf-8")
    config = {
        "host": {
            "vm_cpu_set": [0, 1, 2, 3],
            "max_vms": 8,
            "max_total_vcpus": 16,
            "max_total_memory_mb": 16384,
            "max_layer3_per_layer2": 6,
        },
        "network": {
            "cidr": "10.92.0.0/20",
            "gateway": "10.92.0.1",
            "dhcp_cidr": "10.93.0.0/24",
            "mac_prefix": "52:54:00",
        },
        "storage": {
            "base_dir": str(root / "base"),
            "layer2_dir": str(root / "layer2"),
            "layer3_dir": str(root / "layer3"),
            "trash_dir": str(root / "trash"),
            "state_dir": str(root / "state"),
            "requests_dir": str(root / "requests"),
            "runtime_dir": str(root / "runtime"),
            "audit_log": str(root / "state" / "audit.log"),
        },
        "executor_bin": f"{sys.executable} -m kvm_control.root_vm_exec",
        "dry_run": True,
        "templates": [
            {
                "id": "ubuntu-24.04",
                "base_image": "ubuntu-24.04-base.qcow2",
                "max_vcpus": 8,
                "max_memory_mb": 8192,
                "default_vcpus": 2,
                "default_memory_mb": 2048,
            }
        ],
    }
    if disk_full_threshold_bytes is not None:
        config["storage"]["disk_full_threshold_bytes"] = disk_full_threshold_bytes
    path = root / "config.json"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def _request(method: str, url: str, payload: dict | None = None, expected_status: int = 200) -> dict | list | None:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read().decode("utf-8")
            status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        status = exc.code
        if status != expected_status:
            raise AssertionError(f"{method} {url} returned {status}: {body}") from exc
        return json.loads(body) if body else None
    if status != expected_status:
        raise AssertionError(f"{method} {url} returned {status}, expected {expected_status}: {body}")
    return json.loads(body) if body else None


def _wait_ready(url: str, timeout_s: float = 20.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            _request("GET", url)
            return
        except Exception:
            time.sleep(0.2)
    raise TimeoutError(f"service did not become ready: {url}")


def _wait_until(predicate, timeout_s: float = 20.0, description: str = "condition") -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise TimeoutError(f"timed out waiting for {description}")


def _start_service(config_path: Path, service: str, port: int) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-m", "kvm_control", "--config", str(config_path), service, "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _stop_service(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _restart_services(config_path: Path, control_port: int, lock_port: int) -> tuple[subprocess.Popen[str], subprocess.Popen[str]]:
    control_proc = _start_service(config_path, "control-api", control_port)
    lock_proc = _start_service(config_path, "lock-api", lock_port)
    control_base = f"http://127.0.0.1:{control_port}"
    lock_base = f"http://127.0.0.1:{lock_port}"
    _wait_ready(f"{control_base}/v1/templates")
    _wait_ready(f"{lock_base}/v1/locks/resources")
    return control_proc, lock_proc


def _write_disk_usage_override(root: Path, layer2_free: int | None = None, layer3_free: int | None = None) -> None:
    payload: dict[str, dict[str, int]] = {}
    if layer2_free is not None:
        payload["layer2"] = {"free_bytes": layer2_free}
    if layer3_free is not None:
        payload["layer3"] = {"free_bytes": layer3_free}
    (root / "state" / "disk-usage-overrides.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _assert_command(entries: list[dict], action: str, startswith: str) -> None:
    for entry in entries:
        if entry["action"] != action:
            continue
        if any(" ".join(command).startswith(startswith) for command in entry["commands"]):
            return
    raise AssertionError(f"missing logged command for action={action!r} prefix={startswith!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Dry-run smoke test for the kvm-control APIs")
    parser.add_argument("--control-port", type=int, default=18080)
    parser.add_argument("--lock-port", type=int, default=18081)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="kvm-control-smoke-") as tmp:
        root = Path(tmp)
        healthy_threshold = 1
        print("starting services in healthy mode", flush=True)
        config_path = _write_config(root, args.control_port, args.lock_port, disk_full_threshold_bytes=healthy_threshold)
        control_proc, lock_proc = _restart_services(config_path, args.control_port, args.lock_port)
        try:
            control_base = f"http://127.0.0.1:{args.control_port}"
            lock_base = f"http://127.0.0.1:{args.lock_port}"

            first_lock = _request("POST", f"{lock_base}/v1/locks/requests", {"resource_id": "shared-db", "namespace": "repo-a"}, 201)
            second_lock = _request("POST", f"{lock_base}/v1/locks/requests", {"resource_id": "shared-db", "namespace": "repo-b"}, 201)
            assert isinstance(first_lock, dict)
            assert isinstance(second_lock, dict)
            assert first_lock["status"] == "granted"
            assert second_lock["status"] == "queued"

            rejected = _request(
                "POST",
                f"{control_base}/v1/vms",
                {
                    "namespace": "repo-b",
                    "template_id": "ubuntu-24.04",
                    "vm_slot": "node1",
                    "lock_resource_id": "shared-db",
                },
                423,
            )
            assert isinstance(rejected, dict)

            vm_create = _request(
                "POST",
                f"{control_base}/v1/vms",
                {
                    "namespace": "repo-a",
                    "template_id": "ubuntu-24.04",
                    "vm_slot": "node1",
                    "vcpus": 2,
                    "memory_mb": 1024,
                    "lock_resource_id": "shared-db",
                },
                202,
            )
            assert isinstance(vm_create, dict)
            vm_id = vm_create["vm_id"]
            reserved_ip = vm_create["reserved_ip"]

            vm = _request("GET", f"{control_base}/v1/vms/{vm_id}")
            assert isinstance(vm, dict)
            assert vm["power_state"] == "running"
            assert vm["reserved_ip"] == reserved_ip

            _request("POST", f"{control_base}/v1/vms/{vm_id}/stop", expected_status=202)
            _request("POST", f"{control_base}/v1/vms/{vm_id}/start", expected_status=202)
            _request("POST", f"{control_base}/v1/vms/{vm_id}/restart", expected_status=202)
            _request("POST", f"{control_base}/v1/vms/{vm_id}/revert", expected_status=202)
            _request("POST", f"{control_base}/v1/vms/{vm_id}/start", expected_status=202)

            ready = _request(
                "POST",
                f"{control_base}/v1/vms/{vm_id}/wait-ready",
                {"timeout_s": 2, "poll_interval_s": 1, "check_ssh": True},
            )
            assert isinstance(ready, dict)
            assert ready["ready"] is True
            assert ready["readiness_state"] == "ready"
            assert ready["ssh_target"] == f"root@{reserved_ip}"
            assert ready["readiness_probe"] == "root_ssh_command"
            assert ready["ssh_login_verified"] is True
            assert ready["scp_verified"] is False

            run = _request(
                "POST",
                f"{control_base}/v1/runs",
                {
                    "namespace": "repo-a",
                    "workflow_name": "sandbox-smoke",
                    "workflow_version": "v1",
                    "git_ref": "refs/heads/main",
                    "vm_ids": [vm_id],
                    "declared_tests": ["prep", "smoke"],
                    "selected_tests": ["prep", "smoke"],
                },
                201,
            )
            assert isinstance(run, dict)
            run_id = run["id"]

            _request(
                "POST",
                f"{control_base}/v1/runs/{run_id}/estimate",
                {
                    "estimated_disk_mb": 1024,
                    "estimated_ram_mb": 1024,
                    "estimated_duration_s": 300,
                    "source": "manual",
                    "confidence": 0.5,
                },
            )
            _request("POST", f"{control_base}/v1/runs/{run_id}/stages/prep/start", {"name": "prep", "order_index": 1})
            time.sleep(0.2)
            _request("POST", f"{control_base}/v1/runs/{run_id}/stages/prep/finish", {"status": "completed"})
            _request(
                "POST",
                f"{control_base}/v1/runs/{run_id}/events",
                {
                    "event_type": "info",
                    "message": "sandbox smoke reached telemetry phase",
                    "stage_id": "prep",
                    "details": {"source": "sandbox_api_smoke"},
                },
                201,
            )
            usage = _request("GET", f"{control_base}/v1/runs/{run_id}/usage")
            assert isinstance(usage, dict)
            assert usage["sample_count"] >= 1

            print("simulating disk-full mode for host monitor", flush=True)
            _write_disk_usage_override(root, layer2_free=0, layer3_free=0)
            _request("POST", f"{control_base}/v1/admin/monitor/sample")

            def _vm_paused() -> bool:
                vm_state = _request("GET", f"{control_base}/v1/vms/{vm_id}")
                assert isinstance(vm_state, dict)
                return vm_state["power_state"] == "paused" and vm_state["pause_reason"] == "disk_full"

            _wait_until(_vm_paused, timeout_s=15.0, description="disk pressure pause")
            print("disk pressure pause observed", flush=True)

            paused_events = _request("GET", f"{control_base}/v1/runs/{run_id}/events")
            assert isinstance(paused_events, list)
            assert any(event["event_type"] == "disk_full" and event["details"]["source"] == "host_monitor" for event in paused_events)
            assert any(event["message"].startswith(f"vm {vm_id} paused") for event in paused_events)

            print("clearing simulated disk-full mode", flush=True)
            _write_disk_usage_override(root, layer2_free=1024**3, layer3_free=1024**3)
            _request("POST", f"{control_base}/v1/admin/monitor/sample")

            def _vm_resumed() -> bool:
                vm_state = _request("GET", f"{control_base}/v1/vms/{vm_id}")
                assert isinstance(vm_state, dict)
                return vm_state["power_state"] == "running" and vm_state["pause_reason"] is None

            _wait_until(_vm_resumed, timeout_s=15.0, description="disk pressure recovery")
            print("disk pressure recovery observed", flush=True)

            recovered_events = _request("GET", f"{control_base}/v1/runs/{run_id}/events")
            assert isinstance(recovered_events, list)
            assert any(
                event["message"] == "host monitor detected free space recovery in layer2 pool"
                or event["message"] == "host monitor detected free space recovery in layer3 pool"
                for event in recovered_events
            )
            assert any(event["message"].startswith(f"vm {vm_id} resumed") for event in recovered_events)

            _request("POST", f"{control_base}/v1/runs/{run_id}/stages/smoke/start", {"name": "smoke", "order_index": 2})
            time.sleep(0.2)
            _request("POST", f"{control_base}/v1/runs/{run_id}/stages/smoke/finish", {"status": "completed"})
            summary = _request("POST", f"{control_base}/v1/runs/{run_id}/finish", {"status": "completed"})
            _request(
                "POST",
                f"{control_base}/v1/runs/{run_id}/ignore-for-learning",
                {"reason": "manual smoke run", "bug_reference": "SMOKE-IGNORE"},
            )
            summary = _request("GET", f"{control_base}/v1/runs/{run_id}/summary")
            assert isinstance(summary, dict)
            assert summary["run"]["status"] == "completed"
            assert summary["usage"]["sample_count"] >= 1
            assert summary["run"]["paused_duration_s"] >= 0
            assert summary["run"]["duration_s"] >= summary["run"]["effective_duration_s"]
            smoke_stage = next(stage for stage in summary["stages"] if stage["stage_id"] == "smoke")
            assert smoke_stage["effective_duration_s"] <= smoke_stage["duration_s"]

            ips = _request("GET", f"{control_base}/v1/namespaces/repo-a/ips")
            assert isinstance(ips, list)
            assert any(entry["ip_address"] == reserved_ip for entry in ips)

            deleted = _request("DELETE", f"{control_base}/v1/vms/{vm_id}", expected_status=202)
            assert isinstance(deleted, dict)
            assert deleted["action"] == "delete"
            assert deleted["status"] == "completed"
            _request(
                "POST",
                f"{lock_base}/v1/locks/requests/{first_lock['id']}/release",
                {"released_by": "repo-a"},
            )

            entries = [
                json.loads(line)
                for line in (root / "state" / "audit.log").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            assert entries, "dry-run audit log is empty"
            assert all(entry["dry_run"] is True for entry in entries)
            _assert_command(entries, "create-layer2", "qemu-img create")
            _assert_command(entries, "create-layer3", "qemu-img create")
            _assert_command(entries, "start-vm", "virsh start")
            _assert_command(entries, "stop-vm", "virsh shutdown")
            _assert_command(entries, "restart-vm", "virsh reboot")
            _assert_command(entries, "revert-vm", "mv ")
            _assert_command(entries, "wait-ssh", "ssh ")
            _assert_command(entries, "delete-layer3", "mv ")
            _assert_command(entries, "pause-vm", "virsh suspend")
            _assert_command(entries, "resume-vm", "virsh resume")

            print("sandbox smoke test passed")
            print(
                json.dumps(
                    {
                        "vm_id": vm_id,
                        "run_id": run_id,
                        "reserved_ip": reserved_ip,
                        "command_log_entries": len(entries),
                        "paused_duration_s": summary["run"]["paused_duration_s"],
                    }
                )
            )
            return 0
        finally:
            for proc in (control_proc, lock_proc):
                _stop_service(proc)
            for proc, name in ((control_proc, "control-api"), (lock_proc, "lock-api")):
                if proc.returncode not in (0, -15):
                    stderr = proc.stderr.read() if proc.stderr else ""
                    raise RuntimeError(f"{name} exited unexpectedly with {proc.returncode}: {stderr}")


if __name__ == "__main__":
    raise SystemExit(main())
