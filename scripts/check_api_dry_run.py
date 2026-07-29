#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def write_config(root: Path, control_port: int, lock_port: int) -> Path:
    (root / "base").mkdir(parents=True, exist_ok=True)
    (root / "base" / "ubuntu-24.04-base.qcow2").write_text(json.dumps({"format": "qcow2", "seed": "test-base"}))
    (root / "webroot").mkdir(parents=True, exist_ok=True)
    (root / "webroot" / "repo-a@setup_2nd_stage.sh").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    config = {
        "host": {
            "vm_cpu_set": [0, 1, 2, 3],
            "max_vms": 8,
            "max_total_vcpus": 16,
            "max_total_memory_mb": 16384,
            "max_layer3_per_layer2": 6,
        },
        "network": {
            "cidr": "10.94.0.0/20",
            "gateway": "10.94.0.1",
            "dhcp_cidr": "10.95.0.0/24",
            "mac_prefix": "52:54:00",
        },
        "storage": {
            "base_dir": str(root / "base"),
            "layer2_dir": str(root / "layer2"),
            "layer3_dir": str(root / "layer3"),
            "trash_dir": str(root / "trash"),
            "webroot_dir": str(root / "webroot"),
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
    path = root / "config.json"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def request(method: str, url: str, payload: dict | None = None, expected_status: int = 200, parse_json: bool = True):
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
        return json.loads(body) if body and parse_json else body
    if status != expected_status:
        raise AssertionError(f"{method} {url} returned {status}, expected {expected_status}: {body}")
    return json.loads(body) if body and parse_json else body


def wait_ready(url: str, timeout_s: float = 20.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            request("GET", url)
            return
        except Exception:
            time.sleep(0.2)
    raise TimeoutError(f"service did not become ready: {url}")


def start_service(config_path: Path, service: str, port: int) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-m", "kvm_control", "--config", str(config_path), service, "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def stop_service(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def assert_dry_run_action(payload: dict, action: str, command_prefixes: list[str]) -> None:
    assert payload["action"] == action, payload
    assert payload["dry_run"] is True, payload
    flattened = [" ".join(command) for command in payload["planned_commands"]]
    for prefix in command_prefixes:
        assert any(command.startswith(prefix) for command in flattened), (prefix, flattened)


def main() -> int:
    control_port = 18180
    lock_port = 18181
    with tempfile.TemporaryDirectory(prefix="kvm-control-dryrun-check-") as tmp:
        root = Path(tmp)
        config_path = write_config(root, control_port, lock_port)
        control_proc = start_service(config_path, "control-api", control_port)
        lock_proc = start_service(config_path, "lock-api", lock_port)
        try:
            control_base = f"http://127.0.0.1:{control_port}"
            lock_base = f"http://127.0.0.1:{lock_port}"
            wait_ready(f"{control_base}/v1/templates")
            wait_ready(f"{lock_base}/v1/locks/resources")

            assert request("GET", f"{control_base}/repo-a@setup_2nd_stage.sh", parse_json=False) == "#!/bin/sh\necho ok\n"
            assert isinstance(request("GET", f"{control_base}/v1/templates"), list)
            assert isinstance(request("GET", f"{control_base}/v1/capacity"), dict)
            assert request("GET", f"{control_base}/v1/vms") == []
            assert request("GET", f"{control_base}/v1/runs") == []
            assert request("GET", f"{lock_base}/v1/locks/resources") == []

            first_lock = request("POST", f"{lock_base}/v1/locks/requests", {"resource_id": "shared-db", "namespace": "repo-a"}, 201)
            second_lock = request("POST", f"{lock_base}/v1/locks/requests", {"resource_id": "shared-db", "namespace": "repo-b"}, 201)
            assert first_lock["status"] == "granted"
            assert second_lock["status"] == "queued"
            assert isinstance(request("GET", f"{lock_base}/v1/locks/resources/shared-db/queue"), list)
            assert isinstance(request("GET", f"{lock_base}/v1/locks/requests/{first_lock['id']}"), dict)

            create = request(
                "POST",
                f"{control_base}/v1/vms",
                {
                    "namespace": "repo-a",
                    "template_id": "ubuntu-24.04",
                    "vm_slot": "node1",
                    "network_id": "dev",
                    "vcpus": 2,
                    "memory_mb": 1024,
                    "lock_resource_id": "shared-db",
                },
                202,
            )
            vm_id = create["vm_id"]
            assert_dry_run_action(create, "create", ["qemu-img create", "virsh define", "virsh start"])
            assert isinstance(request("GET", f"{control_base}/v1/vms/{vm_id}"), dict)
            assert isinstance(request("GET", f"{control_base}/v1/operations/{create['operation_id']}"), dict)
            assert isinstance(request("GET", f"{control_base}/v1/namespaces/repo-a/disk-usage"), dict)
            assert isinstance(request("GET", f"{control_base}/v1/namespaces/repo-a/ips"), list)

            stop = request("POST", f"{control_base}/v1/vms/{vm_id}/stop", expected_status=202)
            assert_dry_run_action(stop, "stop", ["virsh shutdown"])
            pause = request("POST", f"{control_base}/v1/vms/{vm_id}/pause", expected_status=202)
            assert_dry_run_action(pause, "pause", ["virsh suspend"])
            resume = request("POST", f"{control_base}/v1/vms/{vm_id}/resume", expected_status=202)
            assert_dry_run_action(resume, "resume", ["virsh resume"])
            poweroff = request("POST", f"{control_base}/v1/vms/{vm_id}/poweroff", expected_status=202)
            assert_dry_run_action(poweroff, "poweroff", ["virsh destroy"])
            start = request("POST", f"{control_base}/v1/vms/{vm_id}/start", expected_status=202)
            assert_dry_run_action(start, "start", ["virsh define", "virsh start"])
            restart = request("POST", f"{control_base}/v1/vms/{vm_id}/restart", expected_status=202)
            assert_dry_run_action(restart, "restart", ["virsh reboot"])
            revert = request("POST", f"{control_base}/v1/vms/{vm_id}/revert", expected_status=202)
            assert_dry_run_action(revert, "revert", ["mv ", "qemu-img create"])

            stop_again = request("POST", f"{control_base}/v1/vms/{vm_id}/stop", expected_status=202)
            assert_dry_run_action(stop_again, "stop", ["virsh shutdown"])
            resize = request("POST", f"{control_base}/v1/vms/{vm_id}/resize-layer3", {"new_size_mb": 2048}, 202)
            assert_dry_run_action(resize, "resize-layer3", ["qemu-img resize"])
            promote = request("POST", f"{control_base}/v1/vms/{vm_id}/promote-layer2", expected_status=202)
            assert promote["dry_run"] is True
            assert any("qemu-img convert" in " ".join(command) for command in promote["planned_commands"])

            run = request(
                "POST",
                f"{control_base}/v1/runs",
                {
                    "namespace": "repo-a",
                    "workflow_name": "dryrun-check",
                    "workflow_version": "v1",
                    "git_ref": "refs/heads/main",
                    "vm_ids": [vm_id],
                    "declared_tests": ["prep", "smoke"],
                    "selected_tests": ["prep", "smoke"],
                },
                201,
            )
            run_id = run["id"]
            assert isinstance(request("GET", f"{control_base}/v1/runs/{run_id}"), dict)
            request(
                "POST",
                f"{control_base}/v1/runs/{run_id}/estimate",
                {
                    "estimated_disk_mb": 256,
                    "estimated_ram_mb": 512,
                    "estimated_duration_s": 60,
                    "source": "manual",
                },
            )
            request("POST", f"{control_base}/v1/runs/{run_id}/stages/prep/start", {"name": "prep", "order_index": 1})
            request("POST", f"{control_base}/v1/runs/{run_id}/stages/prep/finish", {"status": "completed"})
            request(
                "POST",
                f"{control_base}/v1/runs/{run_id}/events",
                {"event_type": "info", "message": "dry-run event", "stage_id": "prep", "details": {"source": "check_api_dry_run"}},
                201,
            )
            assert isinstance(request("GET", f"{control_base}/v1/runs/{run_id}/usage"), dict)
            assert isinstance(request("GET", f"{control_base}/v1/runs/{run_id}/events"), list)
            assert isinstance(request("GET", f"{control_base}/v1/runs/{run_id}/summary"), dict)
            request("POST", f"{control_base}/v1/runs/{run_id}/finish", {"status": "completed"})
            request("POST", f"{control_base}/v1/runs/{run_id}/ignore-for-learning", {"reason": "smoke", "bug_reference": "none"})
            assert request("POST", f"{control_base}/v1/admin/monitor/sample")["status"] == "ok"

            released = request("POST", f"{lock_base}/v1/locks/requests/{first_lock['id']}/release", {"released_by": "repo-a"})
            assert released["status"] == "released"
            promoted = request("GET", f"{lock_base}/v1/locks/requests/{second_lock['id']}")
            assert promoted["status"] == "granted"

            delete = request("DELETE", f"{control_base}/v1/vms/{vm_id}", expected_status=202)
            assert_dry_run_action(delete, "delete", ["virsh shutdown", "mv "])

            print("dry-run API check passed", flush=True)
            return 0
        finally:
            stop_service(control_proc)
            stop_service(lock_proc)


if __name__ == "__main__":
    raise SystemExit(main())
