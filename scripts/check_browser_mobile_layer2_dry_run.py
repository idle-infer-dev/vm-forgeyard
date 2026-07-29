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


RECIPE_ID = "browser-mobile-test-devuan-6-excalibur-amd64"
CATALOG_IMAGE_ID = "default.browser-mobile-test.devuan-6-excalibur-amd64.layer2"
ADMIN_TOKEN = "browser-mobile-dry-run-admin"


def write_config(root: Path, control_port: int) -> Path:
    base_dir = root / "base"
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "devuan-6-excalibur-amd64.raw").write_text(json.dumps({"format": "raw", "seed": "browser-mobile-test"}), encoding="utf-8")
    config = {
        "host": {
            "vm_cpu_set": [0, 1, 2, 3],
            "max_vms": 4,
            "max_total_vcpus": 8,
            "max_total_memory_mb": 8192,
            "max_layer3_per_layer2": 4,
        },
        "network": {
            "cidr": "10.96.0.0/20",
            "gateway": "10.96.0.1",
            "dhcp_cidr": "10.97.0.0/24",
            "mac_prefix": "52:54:00",
        },
        "storage": {
            "base_dir": str(base_dir),
            "layer2_dir": str(root / "layer2"),
            "layer3_dir": str(root / "layer3"),
            "image_remote_dir": str(root / "image-remote"),
            "trash_dir": str(root / "trash"),
            "webroot_dir": str(root / "webroot"),
            "state_dir": str(root / "state"),
            "requests_dir": str(root / "requests"),
            "runtime_dir": str(root / "runtime"),
            "audit_log": str(root / "state" / "audit.log"),
        },
        "auth": {"admin_token": ADMIN_TOKEN},
        "executor_bin": f"{sys.executable} -m kvm_control.root_vm_exec",
        "dry_run": True,
        "templates": [
            {
                "id": "devuan-excalibur",
                "base_image": "devuan-6-excalibur-amd64.raw",
                "base_image_format": "raw",
                "architecture": "x86_64",
                "boot_mode": "direct_kernel",
                "kernel_path": "/var/lib/kvm-control-reference/vm-kernels/excalibur/vmlinuz",
                "initrd_path": "/var/lib/kvm-control-reference/vm-kernels/excalibur/initrd.img",
                "kernel_append": "root=/dev/vda rw console=ttyS0 ip=dhcp",
                "max_vcpus": 4,
                "max_memory_mb": 4096,
                "default_vcpus": 1,
                "default_memory_mb": 1024,
            }
        ],
    }
    path = root / "config.json"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def request(method: str, url: str, payload: dict | None = None, expected_status: int = 200) -> dict | list:
    data = None
    headers = {"Accept": "application/json", "Authorization": f"Bearer {ADMIN_TOKEN}"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            body = response.read().decode("utf-8")
            status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        if exc.code != expected_status:
            raise AssertionError(f"{method} {url} returned {exc.code}: {body}") from exc
        return json.loads(body) if body else {}
    if status != expected_status:
        raise AssertionError(f"{method} {url} returned {status}, expected {expected_status}: {body}")
    return json.loads(body) if body else {}


def wait_ready(url: str, timeout_s: float = 20.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            request("GET", url)
            return
        except Exception:
            time.sleep(0.2)
    raise TimeoutError(f"service did not become ready: {url}")


def start_control_api(config_path: Path, port: int) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-m", "kvm_control", "--config", str(config_path), "control-api", "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def stop_process(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def main() -> int:
    control_port = 18182
    with tempfile.TemporaryDirectory(prefix="kvm-control-browser-layer2-dryrun-") as tmp:
        root = Path(tmp)
        config_path = write_config(root, control_port)
        control_proc = start_control_api(config_path, control_port)
        try:
            control_base = f"http://127.0.0.1:{control_port}"
            wait_ready(f"{control_base}/v1/auth/whoami")
            recipe = request("GET", f"{control_base}/v1/layer2-image-recipes/{RECIPE_ID}")
            assert recipe["catalog_image_id"] == CATALOG_IMAGE_ID, recipe
            assert recipe["auto_build_after_base_image"] is False, recipe
            assert recipe["layer2_size_mb"] == 8192, recipe
            payload = request(
                "POST",
                f"{control_base}/v1/admin/layer2-image-recipes/{RECIPE_ID}/build",
                {"publish": True, "force": True, "notes": "browser mobile dry-run validation"},
                expected_status=202,
            )
            assert payload["recipe_id"] == RECIPE_ID, payload
            assert payload["catalog_image_id"] == CATALOG_IMAGE_ID, payload
            assert payload["architecture"] == "amd64", payload
            assert payload["builder_implemented"] is True, payload
            assert payload["would_publish"] is True, payload
            planned = "\n".join(payload["planned_steps"])
            for expected in ("qemu-img create", "virt-customize", "chromium", "firefox-esr", "xvfb", "playwright", "pytest-playwright"):
                assert expected in planned, (expected, payload["planned_steps"])
            assert str(8192 * 1024 * 1024) in planned, payload["planned_steps"]
            image = request("GET", f"{control_base}/v1/images/{CATALOG_IMAGE_ID}")
            assert image["cache_state"] == "present", image
            assert image["metadata"]["layer2_recipe_id"] == RECIPE_ID, image
            print(json.dumps({"ok": True, "recipe_id": RECIPE_ID, "planned_step_count": len(payload["planned_steps"])}, sort_keys=True))
            return 0
        finally:
            stop_process(control_proc)
            stdout, stderr = control_proc.communicate(timeout=5)
            if control_proc.returncode not in (0, -15):
                sys.stderr.write(stdout)
                sys.stderr.write(stderr)


if __name__ == "__main__":
    sys.exit(main())
