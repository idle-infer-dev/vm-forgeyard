from __future__ import annotations

import asyncio
import json
import hashlib
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import fastapi.dependencies.utils
import fastapi.routing
import httpx
import anyio.to_thread
import starlette.concurrency

from kvm_control.control_api import create_app as create_control_app
from kvm_control.firewall import reconcile_firewall_access
from kvm_control.lock_api import create_app as create_lock_app
from kvm_control.reconcile import reconcile_registered_vm_runtime_states
from kvm_control.service import build_services
from kvm_control.status_bus import StatusEventBus
from kvm_control.vm_cleanup import cleanup_stale_stopped_ephemeral_vms


# The local sandbox can stall asyncio/anyio worker-thread portals used by
# Starlette's synchronous TestClient. Keep these API tests in-process and
# deterministic by running sync route callables inline.
async def _run_in_threadpool_inline(func, *args, **kwargs):
    return func(*args, **kwargs)


async def _to_thread(func, *args, **kwargs):
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def runner() -> None:
        try:
            result = func(*args, **kwargs)
        except BaseException as exc:
            loop.call_soon_threadsafe(future.set_exception, exc)
        else:
            loop.call_soon_threadsafe(future.set_result, result)

    threading.Thread(target=runner, daemon=True).start()
    return await future


async def _anyio_run_sync(func, *args, cancellable=False, limiter=None):
    return func(*args)


asyncio.to_thread = _to_thread
anyio.to_thread.run_sync = _anyio_run_sync
fastapi.dependencies.utils.run_in_threadpool = _run_in_threadpool_inline
fastapi.routing.run_in_threadpool = _run_in_threadpool_inline
starlette.concurrency.run_in_threadpool = _run_in_threadpool_inline


class _ApiTestClient:
    __test__ = False

    def __init__(self, app, base_url: str = "http://testserver") -> None:
        self.app = app
        self.base_url = base_url

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        async def send() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url=self.base_url,
                follow_redirects=True,
            ) as client:
                return await client.request(method, url, **kwargs)

        return asyncio.run(send())

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> httpx.Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> httpx.Response:
        return self.request("DELETE", url, **kwargs)

    def websocket_connect(self, url: str):
        return _WebSocketSession(self.app, url)


class _WebSocketSession:
    def __init__(self, app, url: str) -> None:
        self.app = app
        self.url = url
        self.subscription = None
        self.replay: list[dict] = []

    def __enter__(self):
        parsed = urlsplit(self.url)
        params = parse_qs(parsed.query)
        after_values = params.get("after_id", [])
        after_id = int(after_values[0]) if after_values and after_values[0].isdigit() else None
        self.subscription = self.app.state.services.status_bus.subscribe(after_id=after_id)
        self.replay = list(self.subscription.replay)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.subscription is not None:
            self.app.state.services.status_bus.unsubscribe(self.subscription.subscriber_id)

    def receive_json(self, timeout: float = 2.0) -> dict:
        if self.replay:
            return self.replay.pop(0)
        if self.subscription is None:
            raise AssertionError("websocket session is not connected")
        event = self.subscription.queue.get(timeout=timeout)
        if event is None:
            raise queue.Empty
        return event


TestClient = _ApiTestClient


def write_config(root: Path, dry_run: bool = True) -> Path:
    base_dir = root / "base"
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "ubuntu-24.04-base.qcow2").write_text(json.dumps({"format": "qcow2", "seed": "test-base"}))
    config = {
        "host": {
            "vm_cpu_set": [0, 1, 2, 3],
            "max_vms": 8,
            "max_total_vcpus": 16,
            "max_total_memory_mb": 16384,
            "max_layer3_per_layer2": 6,
        },
        "network": {
            "cidr": "10.90.0.0/20",
            "gateway": "10.90.0.1",
            "dhcp_cidr": "10.91.0.0/24",
            "mac_prefix": "52:54:00",
            "segments": [
                {
                    "id": "dev",
                    "bridge": "dev",
                    "address": "10.90.1.1/24",
                    "dhcp_range_start": "10.90.1.100",
                    "dhcp_range_end": "10.90.1.199",
                },
                {
                    "id": "stage",
                    "bridge": "stage",
                    "address": "10.90.2.1/24",
                    "dhcp_range_start": "10.90.2.100",
                    "dhcp_range_end": "10.90.2.199",
                },
                {
                    "id": "misc",
                    "bridge": "misc",
                    "address": "10.90.3.1/24",
                    "dhcp_range_start": "10.90.3.100",
                    "dhcp_range_end": "10.90.3.199",
                },
                {
                    "id": "live",
                    "bridge": "live",
                    "address": "10.90.4.1/24",
                    "dhcp_range_start": "10.90.4.100",
                    "dhcp_range_end": "10.90.4.199",
                },
            ],
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
        "executor_bin": f"{sys.executable} -m kvm_control.root_vm_exec",
        "dry_run": dry_run,
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
    path.write_text(json.dumps(config))
    return path


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))

    def tearDown(self) -> None:
        self.services.monitor.stop()
        self.tmp.cleanup()

    def test_lock_api_fifo(self) -> None:
        first = self.lock.post("/v1/locks/requests", json={"resource_id": "lab-a", "namespace": "repo-a"})
        second = self.lock.post("/v1/locks/requests", json={"resource_id": "lab-a", "namespace": "repo-b"})
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 201)
        self.assertEqual(first.json()["status"], "granted")
        self.assertEqual(second.json()["status"], "queued")

        release = self.lock.post(f"/v1/locks/requests/{first.json()['id']}/release", json={"released_by": "repo-a"})
        self.assertEqual(release.status_code, 200)
        promoted = self.lock.get(f"/v1/locks/requests/{second.json()['id']}")
        self.assertEqual(promoted.json()["status"], "granted")

    def test_vm_lifecycle_and_reserved_ip(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node1",
                "network_id": "dev",
                "vcpus": 2,
                "memory_mb": 1024,
                "retention": "keep_stopped",
                "retention_reason": "debug lifecycle test",
                "purpose": "exercise vm lifecycle",
                "agent_session_id": "codex-test-session",
                "agent_label": "codex",
                "handoff": "retain state if lifecycle test fails",
                "ssh_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey codex-test",
                "nested_virtualization": True,
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]
        reserved_ip = create.json()["reserved_ip"]
        self.assertTrue(reserved_ip.startswith("10.90.1."))
        self.assertEqual(create.json()["retention"], "keep_stopped")
        self.assertEqual(create.json()["purpose"], "exercise vm lifecycle")
        self.assertEqual(create.json()["agent_session_id"], "codex-test-session")
        self.assertTrue(create.json()["nested_virtualization"])
        self.assertEqual(self.services.registry.get_vm(vm_id)["ssh_public_key"], "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey codex-test")
        self.assertEqual(self.services.registry.get_vm(vm_id)["nested_virtualization"], 1)

        vm = self.control.get(f"/v1/vms/{vm_id}")
        self.assertEqual(vm.status_code, 200)
        self.assertEqual(vm.json()["power_state"], "running")
        self.assertEqual(vm.json()["readiness_state"], "booting")
        self.assertEqual(vm.json()["reserved_ip"], reserved_ip)
        self.assertEqual(vm.json()["retention"], "keep_stopped")
        self.assertTrue(vm.json()["nested_virtualization"])

        retention = self.control.post(
            f"/v1/vms/{vm_id}/retention",
            json={"retention": "archive", "reason": "archive after debugging"},
        )
        self.assertEqual(retention.status_code, 200)
        self.assertEqual(retention.json()["retention"], "archive")
        self.assertEqual(retention.json()["retention_reason"], "archive after debugging")

        revert = self.control.post(f"/v1/vms/{vm_id}/revert")
        self.assertEqual(revert.status_code, 202)
        reverted_vm = self.control.get(f"/v1/vms/{vm_id}")
        self.assertEqual(reverted_vm.json()["layer3_presence"], "present")
        self.assertEqual(reverted_vm.json()["reserved_ip"], reserved_ip)

        stop = self.control.post(f"/v1/vms/{vm_id}/stop")
        self.assertEqual(stop.status_code, 202)
        start = self.control.post(f"/v1/vms/{vm_id}/start")
        self.assertEqual(start.status_code, 202)
        self.assertEqual(start.json()["readiness_state"], "booting")
        self.assertEqual(start.json()["reserved_ip"], reserved_ip)

    def test_reserved_ip_uses_requested_network_segment(self) -> None:
        cases = [
            ("dev", "10.90.1."),
            ("stage", "10.90.2."),
            ("misc", "10.90.3."),
        ]
        for network_id, expected_prefix in cases:
            create = self.control.post(
                "/v1/vms",
                json={
                    "namespace": "repo-segments",
                    "template_id": "ubuntu-24.04",
                    "vm_slot": network_id,
                    "network_id": network_id,
                    "autostart": False,
                },
            )
            self.assertEqual(create.status_code, 202)
            self.assertTrue(create.json()["reserved_ip"].startswith(expected_prefix))

    def test_reserved_ip_skips_configured_dhcp_pool(self) -> None:
        reservations = [
            self.services.registry.reserve_ip("repo-dhcp", f"node-{index}", "dev")
            for index in range(90)
        ]
        self.assertEqual(reservations[0]["reserved_ip"], "10.90.1.11")
        self.assertEqual(reservations[88]["reserved_ip"], "10.90.1.99")
        self.assertEqual(reservations[89]["reserved_ip"], "10.90.1.200")
        self.assertFalse(any(reservation["reserved_ip"].startswith("10.90.1.1") for reservation in reservations[89:]))
        self.assertNotIn("10.90.1.120", {reservation["reserved_ip"] for reservation in reservations})

    def test_existing_reserved_ip_in_dhcp_pool_is_reallocated(self) -> None:
        with self.services.registry.tx() as conn:
            conn.execute(
                """
                INSERT INTO ip_reservations(namespace, vm_slot, ip_address, mac_address)
                VALUES(?, ?, ?, ?)
                """,
                ("repo-dhcp", "node-stale", "10.90.1.120", "52:54:00:00:00:20"),
            )

        reservation = self.services.registry.reserve_ip("repo-dhcp", "node-stale", "dev")

        self.assertEqual(reservation["reserved_ip"], "10.90.1.11")
        self.assertEqual(reservation["reserved_mac"], "52:54:00:00:00:20")

    def test_vm_mark_ready_is_disabled_for_api_owned_readiness(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-ready",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node1",
                "network_id": "dev",
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]

        rejected = self.control.post(f"/v1/vms/{vm_id}/mark-ready", json={"observed_ip": create.json()["reserved_ip"]})
        self.assertEqual(rejected.status_code, 410)
        self.assertIn("wait-ready", rejected.json()["detail"]["reason"])

        vm = self.control.get(f"/v1/vms/{vm_id}")
        self.assertEqual(vm.json()["readiness_state"], "booting")

        restart = self.control.post(f"/v1/vms/{vm_id}/restart")
        self.assertEqual(restart.status_code, 202)
        self.assertEqual(restart.json()["readiness_state"], "booting")

    def test_wait_vm_ready_marks_ready_after_reserved_ip_ssh_reachable(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-wait-ready",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node1",
                "network_id": "dev",
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]
        reserved_ip = create.json()["reserved_ip"]

        with patch.object(
            self.services.executor,
            "run",
            return_value={"result": "not-ready", "readiness_probe": "root_ssh_command", "ssh_login_verified": False, "error": "connection refused"},
        ):
            timed_out = self.control.post(
                f"/v1/vms/{vm_id}/wait-ready",
                json={"timeout_s": 0, "poll_interval_s": 1},
            )
        self.assertEqual(timed_out.status_code, 200)
        self.assertFalse(timed_out.json()["ready"])
        self.assertTrue(timed_out.json()["timed_out"])
        self.assertEqual(timed_out.json()["ssh_target"], f"root@{reserved_ip}")
        self.assertIn("root SSH login", timed_out.json()["reason"])
        self.assertIn("connection refused", timed_out.json()["reason"])

        with patch.object(
            self.services.executor,
            "run",
            return_value={"result": "ok", "readiness_probe": "root_ssh_command", "ssh_login_verified": True, "scp_verified": False},
        ) as wait_ssh:
            ready = self.control.post(
                f"/v1/vms/{vm_id}/wait-ready",
                json={"timeout_s": 1, "poll_interval_s": 1},
            )
        wait_ssh.assert_called()
        self.assertEqual(ready.status_code, 200)
        self.assertTrue(ready.json()["ready"])
        self.assertFalse(ready.json()["timed_out"])
        self.assertEqual(ready.json()["readiness_state"], "ready")
        self.assertEqual(ready.json()["ssh_target"], f"root@{reserved_ip}")
        self.assertEqual(ready.json()["readiness_probe"], "root_ssh_command")
        self.assertTrue(ready.json()["ssh_login_verified"])
        self.assertFalse(ready.json()["scp_verified"])

        with patch.object(
            self.services.executor,
            "run",
            return_value={"result": "not-ready", "readiness_probe": "root_ssh_command", "ssh_login_verified": False, "error": "connection refused"},
        ) as cached_ready_wait_ssh:
            cached_ready_probe = self.control.post(
                f"/v1/vms/{vm_id}/wait-ready",
                json={"timeout_s": 0, "poll_interval_s": 1},
            )
        cached_ready_wait_ssh.assert_called()
        self.assertEqual(cached_ready_probe.status_code, 200)
        self.assertFalse(cached_ready_probe.json()["ready"])
        self.assertTrue(cached_ready_probe.json()["timed_out"])
        self.assertIn("root SSH login", cached_ready_probe.json()["reason"])

        already_ready = self.control.post(
            f"/v1/vms/{vm_id}/wait-ready",
            json={"timeout_s": 0, "check_ssh": False},
        )
        self.assertEqual(already_ready.status_code, 200)
        self.assertTrue(already_ready.json()["ready"])

    def test_pause_resume_and_poweroff_endpoints(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node2",
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]

        pause = self.control.post(f"/v1/vms/{vm_id}/pause")
        self.assertEqual(pause.status_code, 202)
        self.assertEqual(pause.json()["power_state"], "paused")
        paused = self.control.get(f"/v1/vms/{vm_id}")
        self.assertEqual(paused.json()["power_state"], "paused")

        resume = self.control.post(f"/v1/vms/{vm_id}/resume")
        self.assertEqual(resume.status_code, 202)
        self.assertEqual(resume.json()["power_state"], "running")

        poweroff = self.control.post(f"/v1/vms/{vm_id}/poweroff")
        self.assertEqual(poweroff.status_code, 202)
        self.assertEqual(poweroff.json()["power_state"], "stopped")

    def test_vm_delete_reports_layer3_disposition(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node-delete-proof",
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]

        stop = self.control.post(f"/v1/vms/{vm_id}/stop")
        self.assertEqual(stop.status_code, 202)

        deleted = self.control.delete(f"/v1/vms/{vm_id}")
        self.assertEqual(deleted.status_code, 202)
        disposition = deleted.json()["layer3_disposition"]
        self.assertEqual(disposition["mode"], "trashed")
        self.assertFalse(disposition["layer3_path_exists_after"])
        self.assertTrue(disposition["trash_path_exists_after"])
        archived = self.control.get("/v1/archived-vms?namespace=repo-a")
        self.assertEqual(archived.status_code, 200)
        self.assertTrue(any(item["vm_id"] == vm_id and item["namespace"] == "repo-a" for item in archived.json()))

    def test_vm_create_fails_when_base_image_is_missing(self) -> None:
        missing_root = Path(self.tmp.name) / "missing-base"
        missing_root.mkdir(parents=True, exist_ok=True)
        self.config_path = write_config(missing_root)
        (missing_root / "base" / "ubuntu-24.04-base.qcow2").unlink()
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))

        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node1",
            },
        )
        self.assertEqual(create.status_code, 503)
        self.assertIn("missing base image", create.json()["detail"]["reason"])

        ips = self.control.get("/v1/namespaces/repo-a/ips")
        self.assertEqual(ips.status_code, 200)
        self.assertEqual(ips.json(), [])

    def test_promote_layer3_creates_candidate_layer2(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "golden-seed",
                "vcpus": 2,
                "memory_mb": 1024,
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]

        stop = self.control.post(f"/v1/vms/{vm_id}/stop")
        self.assertEqual(stop.status_code, 202)

        promote = self.control.post(
            f"/v1/vms/{vm_id}/promote-layer2",
            json={
                "description": "Reusable golden seed image for API tests",
                "keywords": ["golden", "seed"],
                "visible_name": "Golden seed",
            },
        )
        self.assertEqual(promote.status_code, 202)
        payload = promote.json()
        self.assertEqual(payload["vm_id"], vm_id)
        self.assertEqual(payload["image_id"], "repo-a.golden-seed.layer2")
        target_layer2 = Path(payload["target_layer2_path"])
        self.assertTrue(target_layer2.exists())
        self.assertEqual(target_layer2.parent, self.root / "layer2")
        self.assertEqual(payload["source_layer3_path"], str(self.root / "layer3" / "repo-a--golden-seed.qcow2"))

        images = self.control.get("/v1/images", params={"q": "golden"})
        self.assertEqual(images.status_code, 200)
        self.assertEqual([image["image_id"] for image in images.json()], ["repo-a.golden-seed.layer2"])
        image = images.json()[0]
        self.assertEqual(image["metadata"]["description"], "Reusable golden seed image for API tests")
        self.assertEqual(image["metadata"]["keywords"], ["golden", "seed"])
        self.assertEqual(image["metadata"]["visible_name"], "Golden seed")

        keyword_images = self.control.get("/v1/images", params={"keyword": "seed"})
        self.assertEqual(keyword_images.status_code, 200)
        self.assertEqual([image["image_id"] for image in keyword_images.json()], ["repo-a.golden-seed.layer2"])

        stale_temp = self.root / "layer2" / "repo-a--golden-seed--promoted.tmp-123.qcow2"
        stale_temp.write_text("stale")
        second = self.control.post(f"/v1/vms/{vm_id}/promote-layer2")
        self.assertEqual(second.status_code, 202)
        self.assertTrue(second.json()["executor_results"][0]["idempotent"])
        self.assertEqual(second.json()["planned_commands"], [])
        self.assertFalse(stale_temp.exists())
        preserved = self.control.get("/v1/images/repo-a.golden-seed.layer2")
        self.assertEqual(preserved.status_code, 200)
        self.assertEqual(preserved.json()["metadata"]["description"], "Reusable golden seed image for API tests")
        self.assertEqual(preserved.json()["metadata"]["keywords"], ["golden", "seed"])

        updated = self.control.post(
            f"/v1/vms/{vm_id}/promote-layer2",
            json={"description": "Updated reusable layer2 description", "keywords": ["updated", "golden"]},
        )
        self.assertEqual(updated.status_code, 202)
        updated_image = self.control.get("/v1/images/repo-a.golden-seed.layer2")
        self.assertEqual(updated_image.json()["metadata"]["description"], "Updated reusable layer2 description")
        self.assertEqual(updated_image.json()["metadata"]["keywords"], ["updated", "golden"])

    def test_promote_layer3_requires_stopped_vm(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node1",
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]

        promote = self.control.post(f"/v1/vms/{vm_id}/promote-layer2")
        self.assertEqual(promote.status_code, 422)

    def test_publish_fetch_and_delete_prepared_image(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "golden-seed",
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]
        self.assertEqual(self.control.post(f"/v1/vms/{vm_id}/stop").status_code, 202)
        self.assertEqual(self.control.post(f"/v1/vms/{vm_id}/promote-layer2").status_code, 202)

        publish = self.control.post(
            "/v1/images/publish",
            json={
                "image_id": "basic-vm-handling.v1.seed",
                "source_vm_id": vm_id,
                "workflow_name": "basic-vm-handling",
                "workflow_version": "v1",
                "git_ref": "refs/heads/main",
                "visible_name": "basic-vm-handling.v1 seed",
                "tags": ["e2e", "prepared"],
            },
        )
        self.assertEqual(publish.status_code, 202)
        published = publish.json()
        self.assertEqual(published["image_id"], "basic-vm-handling.v1.seed")
        self.assertEqual(published["cache_state"], "present")
        self.assertEqual(published["remote_backend"], "local")
        remote_path = Path(published["remote_path"])
        self.assertTrue(remote_path.exists())
        self.assertTrue(remote_path.with_suffix(remote_path.suffix + ".meta").exists())

        listed = self.control.get("/v1/images")
        self.assertEqual(listed.status_code, 200)
        self.assertIn("basic-vm-handling.v1.seed", {image["image_id"] for image in listed.json()})
        self.assertEqual(listed.json()[0]["remote_backend"], "local")

        retire = self.control.post("/v1/images/basic-vm-handling.v1.seed/retire")
        self.assertEqual(retire.status_code, 202)
        self.assertEqual(retire.json()["cache_state"], "known")

        fetch = self.control.post("/v1/images/basic-vm-handling.v1.seed/fetch")
        self.assertEqual(fetch.status_code, 202)
        self.assertEqual(fetch.json()["cache_state"], "present")
        self.assertTrue(Path(fetch.json()["local_path"]).exists())

        delete = self.control.delete("/v1/images/basic-vm-handling.v1.seed")
        self.assertEqual(delete.status_code, 202)
        self.assertFalse(remote_path.exists())
        self.assertEqual(self.control.get("/v1/images/basic-vm-handling.v1.seed").status_code, 404)

    def test_base_image_recipes_are_readable_but_build_plans_require_admin_token(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {"admin_token": "admin-secret"}
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        admin_headers = {"Authorization": "Bearer admin-secret"}

        created_token = self.control.post(
            "/v1/admin/auth/tokens",
            json={"username": "git.repo-a"},
            headers=admin_headers,
        )
        self.assertEqual(created_token.status_code, 201)
        repo_headers = {"Authorization": f"Bearer {created_token.json()['token']}"}

        listed = self.control.get("/v1/base-image-recipes", headers=repo_headers)
        self.assertEqual(listed.status_code, 200)
        recipe_ids = [recipe["id"] for recipe in listed.json()]
        self.assertEqual(
            recipe_ids,
            ["devuan-6-excalibur-amd64", "openbsd-7.9-amd64", "ubuntu-24.04-noble-amd64"],
        )
        ubuntu = self.control.get("/v1/base-image-recipes/ubuntu-24.04-noble-amd64", headers=repo_headers)
        self.assertEqual(ubuntu.status_code, 200)
        self.assertEqual(ubuntu.json()["suite"], "noble")
        self.assertEqual(ubuntu.json()["method"], "debootstrap")

        layer2 = self.control.get("/v1/layer2-image-recipes", headers=repo_headers)
        self.assertEqual(layer2.status_code, 200)
        layer2_ids = [recipe["id"] for recipe in layer2.json()]
        self.assertEqual(
            layer2_ids,
            [
                "agent-sandbox-tools-devuan-6-excalibur-amd64",
                "agent-sandbox-tools-ubuntu-24.04-noble-amd64",
                "browser-mobile-test-devuan-6-excalibur-amd64",
                "network-service-lab-devuan-6-excalibur-amd64",
            ],
        )
        agent_layer2 = self.control.get(
            "/v1/layer2-image-recipes",
            params={"keyword": "ubuntu"},
            headers=repo_headers,
        )
        self.assertEqual([recipe["id"] for recipe in agent_layer2.json()], ["agent-sandbox-tools-ubuntu-24.04-noble-amd64"])
        self.assertEqual(agent_layer2.json()[0]["default_access"], "user-only")
        self.assertIn("dnsmasq", agent_layer2.json()[0]["system_packages"])
        self.assertIn("nfs-common", agent_layer2.json()[0]["system_packages"])
        self.assertIn("python3-fastapi", agent_layer2.json()[0]["system_packages"])
        self.assertIn("python3-pydantic", agent_layer2.json()[0]["system_packages"])
        self.assertIn("python3-uvicorn", agent_layer2.json()[0]["system_packages"])
        self.assertIn("python3-yaml", agent_layer2.json()[0]["system_packages"])
        self.assertIn("libvirt-clients", agent_layer2.json()[0]["system_packages"])
        self.assertIn("libvirt-daemon-system", agent_layer2.json()[0]["system_packages"])
        self.assertIn("qemu-system-x86", agent_layer2.json()[0]["system_packages"])
        self.assertIn("qemu-utils", agent_layer2.json()[0]["system_packages"])
        browser_layer2 = self.control.get(
            "/v1/layer2-image-recipes",
            params={"keyword": "playwright"},
            headers=repo_headers,
        )
        self.assertEqual([recipe["id"] for recipe in browser_layer2.json()], ["browser-mobile-test-devuan-6-excalibur-amd64"])
        self.assertFalse(browser_layer2.json()[0]["auto_build_after_base_image"])
        self.assertEqual(browser_layer2.json()[0]["layer2_size_mb"], 8192)
        self.assertIn("chromium", browser_layer2.json()[0]["system_packages"])
        self.assertIn("playwright", browser_layer2.json()[0]["python_venv_tools"])
        network_layer2 = self.control.get(
            "/v1/layer2-image-recipes/network-service-lab-devuan-6-excalibur-amd64",
            headers=repo_headers,
        )
        self.assertEqual(network_layer2.status_code, 200)
        self.assertIn("imap", network_layer2.json()["keywords"])
        self.assertEqual(network_layer2.json()["network_interfaces"], 2)
        self.assertTrue(all(not service["enabled_by_default"] for service in network_layer2.json()["services"]))

        denied_build = self.control.post(
            "/v1/admin/base-image-recipes/ubuntu-24.04-noble-amd64/build",
            json={},
            headers=repo_headers,
        )
        self.assertEqual(denied_build.status_code, 403)
        denied_layer2_build = self.control.post(
            "/v1/admin/layer2-image-recipes/agent-sandbox-tools-devuan-6-excalibur-amd64/build",
            json={},
            headers=repo_headers,
        )
        self.assertEqual(denied_layer2_build.status_code, 403)

        denied_publish = self.control.post(
            "/v1/images/publish",
            json={
                "image_id": "repo-token-denied",
                "source_vm_id": "missing",
                "workflow_name": "basic-vm-handling",
                "workflow_version": "v1",
            },
            headers=repo_headers,
        )
        self.assertEqual(denied_publish.status_code, 403)

        def fake_build(action: str, executor_payload: dict) -> dict:
            if action == "build-layer2-image":
                self.assertEqual(executor_payload["recipe"]["id"], "agent-sandbox-tools-ubuntu-24.04-noble-amd64")
                self.assertEqual(executor_payload["base_image_recipe"]["id"], "ubuntu-24.04-noble-amd64")
                return {
                    "result": "ok",
                    "image_id": executor_payload["image_id"],
                    "layer2_path": executor_payload["layer2_path"],
                    "base_image_path": executor_payload["base_image_path"],
                    "checksum_sha256": "4" * 64,
                    "size_bytes": 222,
                    "planned_commands": [["virt-customize", executor_payload["recipe"]["id"]]],
                    "idempotent": False,
                    "dry_run": True,
                }
            self.assertEqual(action, "build-base-image")
            self.assertEqual(executor_payload["recipe"]["id"], "ubuntu-24.04-noble-amd64")
            self.assertEqual(executor_payload["image_size_mb"], 2048)
            return {
                "result": "ok",
                "image_path": executor_payload["image_path"],
                "metadata_path": executor_payload["metadata_path"],
                "kernel_dir": executor_payload["kernel_dir"],
                "kernel_path": f"{executor_payload['kernel_dir']}/vmlinuz",
                "initrd_path": f"{executor_payload['kernel_dir']}/initrd.img",
                "checksum_sha256": "0" * 64,
                "size_bytes": 123,
                "planned_commands": [["debootstrap", "noble"]],
                "dry_run": True,
            }

        with patch.object(self.services.executor, "run", side_effect=fake_build):
            planned = self.control.post(
                "/v1/admin/base-image-recipes/ubuntu-24.04-noble-amd64/build",
                json={"publish": True, "image_size_mb": 2048, "notes": "first implementation slice"},
                headers=admin_headers,
            )
        self.assertEqual(planned.status_code, 202)
        payload = planned.json()
        self.assertEqual(payload["recipe_id"], "ubuntu-24.04-noble-amd64")
        self.assertEqual(payload["status"], "completed")
        self.assertTrue(payload["builder_implemented"])
        self.assertEqual(payload["required_role"], "admin")
        self.assertEqual(payload["method"], "debootstrap")
        self.assertEqual(payload["image_size_mb"], 2048)
        self.assertEqual(payload["checksum_sha256"], "0" * 64)
        self.assertIn("debootstrap noble", payload["planned_steps"])
        self.assertEqual([build["recipe_id"] for build in payload["layer2_builds"]], ["agent-sandbox-tools-ubuntu-24.04-noble-amd64"])

        def fake_layer2_build(action: str, executor_payload: dict) -> dict:
            self.assertEqual(action, "build-layer2-image")
            self.assertEqual(executor_payload["recipe"]["id"], "agent-sandbox-tools-devuan-6-excalibur-amd64")
            self.assertEqual(executor_payload["base_image_recipe"]["id"], "devuan-6-excalibur-amd64")
            return {
                "result": "ok",
                "image_id": executor_payload["image_id"],
                "layer2_path": executor_payload["layer2_path"],
                "base_image_path": executor_payload["base_image_path"],
                "checksum_sha256": "1" * 64,
                "size_bytes": 456,
                "planned_commands": [["virt-customize", "--install", "ripgrep"]],
                "idempotent": False,
                "dry_run": True,
            }

        with patch.object(self.services.executor, "run", side_effect=fake_layer2_build):
            layer2_build = self.control.post(
                "/v1/admin/layer2-image-recipes/agent-sandbox-tools-devuan-6-excalibur-amd64/build",
                json={"publish": True, "notes": "default agent tools"},
                headers=admin_headers,
            )
        self.assertEqual(layer2_build.status_code, 202)
        layer2_payload = layer2_build.json()
        self.assertEqual(layer2_payload["recipe_id"], "agent-sandbox-tools-devuan-6-excalibur-amd64")
        self.assertEqual(layer2_payload["catalog_image_id"], "default.agent-sandbox-tools.devuan-6-excalibur-amd64.layer2")
        self.assertEqual(layer2_payload["checksum_sha256"], "1" * 64)
        self.assertIn("virt-customize --install ripgrep", layer2_payload["planned_steps"])
        catalog = self.control.get("/v1/images/default.agent-sandbox-tools.devuan-6-excalibur-amd64.layer2", headers=admin_headers)
        self.assertEqual(catalog.status_code, 200)
        self.assertEqual(catalog.json()["namespace"], "default")
        self.assertEqual(catalog.json()["source_template_id"], "devuan-excalibur")
        self.assertIn("ripgrep", catalog.json()["metadata"]["keywords"])

        def fake_devuan_build(action: str, executor_payload: dict) -> dict:
            if action == "build-base-image":
                self.assertEqual(executor_payload["recipe"]["id"], "devuan-6-excalibur-amd64")
                return {
                    "result": "ok",
                    "image_path": executor_payload["image_path"],
                    "metadata_path": executor_payload["metadata_path"],
                    "kernel_dir": executor_payload["kernel_dir"],
                    "kernel_path": f"{executor_payload['kernel_dir']}/vmlinuz",
                    "initrd_path": f"{executor_payload['kernel_dir']}/initrd.img",
                    "checksum_sha256": "2" * 64,
                    "size_bytes": 789,
                    "planned_commands": [["debootstrap", "excalibur"]],
                    "dry_run": True,
                }
            self.assertEqual(action, "build-layer2-image")
            return {
                "result": "ok",
                "image_id": executor_payload["image_id"],
                "layer2_path": executor_payload["layer2_path"],
                "base_image_path": executor_payload["base_image_path"],
                "checksum_sha256": "3" * 64,
                "size_bytes": 111,
                "planned_commands": [["virt-customize", executor_payload["recipe"]["id"]]],
                "idempotent": False,
                "dry_run": True,
            }

        with patch.object(self.services.executor, "run", side_effect=fake_devuan_build):
            devuan = self.control.post(
                "/v1/admin/base-image-recipes/devuan-6-excalibur-amd64/build",
                json={},
                headers=admin_headers,
        )
        self.assertEqual(devuan.status_code, 202)
        self.assertEqual(devuan.json()["recipe_id"], "devuan-6-excalibur-amd64")
        self.assertEqual(devuan.json()["checksum_sha256"], "2" * 64)
        self.assertEqual(
            [build["recipe_id"] for build in devuan.json()["layer2_builds"]],
            ["agent-sandbox-tools-devuan-6-excalibur-amd64", "network-service-lab-devuan-6-excalibur-amd64"],
        )

        unsupported = self.control.post(
            "/v1/admin/base-image-recipes/openbsd-7.9-amd64/build",
            json={},
            headers=admin_headers,
        )
        self.assertEqual(unsupported.status_code, 501)

    def test_open_auth_mode_base_image_build_requires_supplied_admin_token(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {"mode": "open", "admin_token": "admin-secret"}
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))

        anonymous = self.control.post("/v1/admin/base-image-recipes/ubuntu-24.04-noble-amd64/build", json={})
        self.assertEqual(anonymous.status_code, 401)

        with patch.object(
            self.services.executor,
            "run",
            return_value={
                "result": "ok",
                "image_path": str(self.root / "base" / "ubuntu-24.04-noble-amd64.raw"),
                "metadata_path": str(self.root / "base" / "ubuntu-24.04-noble-amd64.raw.meta"),
                "kernel_dir": str(self.root / "vm-kernels" / "noble"),
                "planned_commands": [],
                "dry_run": True,
            },
        ):
            admin = self.control.post(
                "/v1/admin/base-image-recipes/ubuntu-24.04-noble-amd64/build",
                json={},
                headers={"Authorization": "Bearer admin-secret"},
            )
        self.assertEqual(admin.status_code, 202)

    def test_create_vm_from_published_image(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "seed",
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]
        self.assertEqual(self.control.post(f"/v1/vms/{vm_id}/stop").status_code, 202)
        self.assertEqual(self.control.post(f"/v1/vms/{vm_id}/promote-layer2").status_code, 202)
        publish = self.control.post(
            "/v1/images/publish",
            json={
                "image_id": "basic-vm-handling.v1.prepared",
                "source_vm_id": vm_id,
                "workflow_name": "basic-vm-handling",
                "workflow_version": "v1",
            },
        )
        self.assertEqual(publish.status_code, 202)
        self.assertEqual(self.control.post("/v1/images/basic-vm-handling.v1.prepared/retire").status_code, 202)
        self.assertEqual(self.control.post("/v1/images/basic-vm-handling.v1.prepared/fetch").status_code, 202)

        second = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node-from-image",
                "image_id": "basic-vm-handling.v1.prepared",
            },
        )
        self.assertEqual(second.status_code, 202)
        vm = self.control.get(f"/v1/vms/{second.json()['vm_id']}")
        self.assertEqual(vm.status_code, 200)
        self.assertEqual(vm.json()["source_image_id"], "basic-vm-handling.v1.prepared")

    def test_testsuite_dependency_documents_track_image_and_artifact_usage(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "seed-with-artifacts",
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]
        self.assertEqual(self.control.post(f"/v1/vms/{vm_id}/stop").status_code, 202)
        self.assertEqual(self.control.post(f"/v1/vms/{vm_id}/promote-layer2").status_code, 202)
        publish = self.control.post(
            "/v1/images/publish",
            json={
                "image_id": "basic-vm-handling.v1.dependency-linked",
                "source_vm_id": vm_id,
                "workflow_name": "basic-vm-handling",
                "workflow_version": "v1",
            },
        )
        self.assertEqual(publish.status_code, 202)

        document = self.control.post(
            "/v1/testsuite-dependencies",
            json={
                "namespace": "repo-a",
                "testsuite_id": "basic-vm-handling",
                "testsuite_version": "v1",
                "git_ref": "refs/heads/main",
                "image_ids": ["basic-vm-handling.v1.dependency-linked"],
                "artifacts": [
                    {
                        "artifact_id": "basic-vm-handling/setup-bundle",
                        "artifact_uri": "artifact://testsuite/basic-vm-handling/v1/setup-bundle.tar.zst",
                        "kind": "test_bundle",
                        "version": "v1",
                        "checksum_sha256": "A" * 64,
                        "signature_uri": "artifact://testsuite/basic-vm-handling/v1/setup-bundle.tar.zst.sig",
                        "signer_id": "ci-artifact-signer",
                        "validation_status": "verified",
                        "metadata": {"entrypoint": "setup.sh"},
                    },
                    {
                        "artifact_id": "basic-vm-handling/http-fixtures",
                        "artifact_uri": "artifact://datasets/basic-vm-handling/http-fixtures-v1.tar.zst",
                        "kind": "test_dataset",
                        "version": "v1",
                    },
                ],
            },
        )
        self.assertEqual(document.status_code, 201)
        payload = document.json()
        self.assertEqual(payload["testsuite_id"], "basic-vm-handling")
        self.assertEqual(payload["image_ids"], ["basic-vm-handling.v1.dependency-linked"])
        self.assertEqual([artifact["kind"] for artifact in payload["artifacts"]], ["test_bundle", "test_dataset"])
        self.assertEqual(payload["status"], "active")

        obsolete = self.control.post(
            "/v1/testsuite-dependencies",
            json={
                "namespace": "repo-a",
                "testsuite_id": "basic-vm-handling",
                "testsuite_version": "v1",
                "git_ref": "refs/heads/main",
                "image_ids": ["basic-vm-handling.v1.dependency-linked"],
                "artifacts": payload["artifacts"],
                "status": "obsolete",
                "notes": "superseded by basic-vm-handling v2",
            },
        )
        self.assertEqual(obsolete.status_code, 201)
        self.assertEqual(obsolete.json()["id"], payload["id"])
        self.assertEqual(obsolete.json()["status"], "obsolete")

        listed = self.control.get("/v1/testsuite-dependencies?testsuite_id=basic-vm-handling")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual([row["id"] for row in listed.json()], [payload["id"]])

        by_image = self.control.get("/v1/testsuite-dependencies?image_id=basic-vm-handling.v1.dependency-linked")
        self.assertEqual(by_image.status_code, 200)
        self.assertEqual([row["testsuite_id"] for row in by_image.json()], ["basic-vm-handling"])

        by_artifact = self.control.get("/v1/testsuite-dependencies?artifact_id=basic-vm-handling/http-fixtures")
        self.assertEqual(by_artifact.status_code, 200)
        self.assertEqual([row["testsuite_version"] for row in by_artifact.json()], ["v1"])

        active_only = self.control.get("/v1/testsuite-dependencies?status=active")
        self.assertEqual(active_only.status_code, 200)
        self.assertEqual(active_only.json(), [])

        unknown_image = self.control.post(
            "/v1/testsuite-dependencies",
            json={
                "namespace": "repo-a",
                "testsuite_id": "missing-image-suite",
                "testsuite_version": "v1",
                "image_ids": ["missing-image"],
            },
        )
        self.assertEqual(unknown_image.status_code, 422)

        run = self.control.post(
            "/v1/runs",
            json={
                "namespace": "repo-a",
                "workflow_name": "basic-vm-handling",
                "workflow_version": "v1",
                "vm_ids": [],
                "declared_tests": ["smoke"],
                "selected_tests": ["smoke"],
            },
        )
        self.assertEqual(run.status_code, 201)
        report = self.control.post(
            f"/v1/runs/{run.json()['id']}/report",
            json={
                "report_id": "basic-vm-handling.v1.run-1",
                "report_uri": "artifact://results/basic-vm-handling/v1/run-1/report.json",
                "schema_version": "v1",
                "checksum_sha256": "B" * 64,
                "signature_uri": "artifact://results/basic-vm-handling/v1/run-1/report.json.sig",
                "signer_id": "pending-signer-policy",
                "validation_status": "verified",
                "result_userdata": [
                    {
                        "artifact_id": "basic-vm-handling.v1.run-1.db-dump",
                        "artifact_uri": "artifact://results/basic-vm-handling/v1/run-1/db.sql.zst",
                        "kind": "db_dump",
                        "checksum_sha256": "C" * 64,
                        "signature_uri": "artifact://results/basic-vm-handling/v1/run-1/db.sql.zst.sig",
                        "signer_id": "pending-signer-policy",
                        "validation_status": "verified",
                        "size_bytes": 1234,
                        "retention_class": "debug",
                        "sensitivity": "internal",
                        "format": "sql+zstd",
                    }
                ],
            },
        )
        self.assertEqual(report.status_code, 201)
        self.assertEqual(report.json()["checksum_sha256"], "b" * 64)
        self.assertEqual(report.json()["result_userdata"][0]["checksum_sha256"], "c" * 64)

        fetched_report = self.control.get(f"/v1/runs/{run.json()['id']}/report")
        self.assertEqual(fetched_report.status_code, 200)
        self.assertEqual(fetched_report.json()["report_id"], "basic-vm-handling.v1.run-1")

        graph = self.control.get("/v1/testsuite-dependencies/graph?testsuite_id=basic-vm-handling")
        self.assertEqual(graph.status_code, 200)
        self.assertEqual(graph.json()["documents"][0]["run_reports"][0]["report_id"], "basic-vm-handling.v1.run-1")
        self.assertEqual(graph.json()["documents"][0]["images"][0]["image_id"], "basic-vm-handling.v1.dependency-linked")

    def test_firewall_access_rules_cover_all_target_zones(self) -> None:
        lock = self.lock.post("/v1/locks/requests", json={"resource_id": "namespace:repo-a", "namespace": "repo-a"})
        self.assertEqual(lock.status_code, 201)
        self.assertEqual(lock.json()["status"], "granted")

        created = []
        for target_zone in ["net", "dev", "stage", "misc"]:
            response = self.control.post(
                "/v1/firewall/access-rules",
                json={
                    "namespace": "repo-a",
                    "lock_resource_id": "namespace:repo-a",
                    "target_zone": target_zone,
                    "source_cidr": "192.0.2.42",
                },
            )
            self.assertEqual(response.status_code, 201)
            created.append(response.json())

        listed = self.control.get("/v1/firewall/access-rules?namespace=repo-a")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual([row["target_zone"] for row in listed.json()], ["net", "dev", "stage", "misc"])

        deleted = self.control.delete(f"/v1/firewall/access-rules/{created[0]['id']}")
        self.assertEqual(deleted.status_code, 200)

        release = self.lock.post(f"/v1/locks/requests/{lock.json()['id']}/release", json={"released_by": "repo-a"})
        self.assertEqual(release.status_code, 200)

        listed_after = self.control.get("/v1/firewall/access-rules?namespace=repo-a")
        self.assertEqual(listed_after.status_code, 200)
        self.assertEqual(listed_after.json(), [])

    def test_default_internal_ingress_sources_are_reconciled_to_test_networks(self) -> None:
        with patch("kvm_control.root_vm_exec.shutil.which", return_value=None):
            reconcile_firewall_access(self.services)

        for ipset_name in ["kvmIngressDevV4", "kvmIngressStageV4", "kvmIngressMiscV4", "kvmIngressLiveV4"]:
            state_file = self.root / "state" / f"{ipset_name}.json"
            self.assertTrue(state_file.exists())
            state = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertEqual(state["entries"], ["10.0.0.0/8"])

    def test_firewall_access_rules_keep_overlapping_grants_until_last_owner_releases(self) -> None:
        first_lock = self.lock.post("/v1/locks/requests", json={"resource_id": "namespace:repo-a", "namespace": "repo-a"})
        second_lock = self.lock.post("/v1/locks/requests", json={"resource_id": "namespace:repo-b", "namespace": "repo-b"})
        self.assertEqual(first_lock.status_code, 201)
        self.assertEqual(second_lock.status_code, 201)

        first_rule = self.control.post(
            "/v1/firewall/access-rules",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "target_zone": "dev",
                "source_cidr": "192.0.2.42",
            },
        )
        second_rule = self.control.post(
            "/v1/firewall/access-rules",
            json={
                "namespace": "repo-b",
                "lock_resource_id": "namespace:repo-b",
                "target_zone": "dev",
                "source_cidr": "192.0.2.42/32",
            },
        )
        self.assertEqual(first_rule.status_code, 201)
        self.assertEqual(second_rule.status_code, 201)
        self.assertEqual(second_rule.json()["source_cidr"], "192.0.2.42")
        self.assertEqual(self.services.registry.effective_firewall_access_entries()["dev"], ["192.0.2.42"])

        release_first = self.lock.post(f"/v1/locks/requests/{first_lock.json()['id']}/release", json={"released_by": "repo-a"})
        self.assertEqual(release_first.status_code, 200)
        self.assertEqual(self.services.registry.effective_firewall_access_entries()["dev"], ["192.0.2.42"])
        listed_second = self.control.get("/v1/firewall/access-rules?namespace=repo-b")
        self.assertEqual(len(listed_second.json()), 1)

        release_second = self.lock.post(f"/v1/locks/requests/{second_lock.json()['id']}/release", json={"released_by": "repo-b"})
        self.assertEqual(release_second.status_code, 200)
        self.assertEqual(self.services.registry.effective_firewall_access_entries()["dev"], [])

    def test_firewall_access_rules_accept_ipv4_cidrs_and_reject_ipv6(self) -> None:
        lock = self.lock.post("/v1/locks/requests", json={"resource_id": "namespace:repo-a", "namespace": "repo-a"})
        self.assertEqual(lock.status_code, 201)

        cidr = self.control.post(
            "/v1/firewall/access-rules",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "target_zone": "stage",
                "source_cidr": "192.0.2.0/24",
            },
        )
        self.assertEqual(cidr.status_code, 201)
        self.assertEqual(cidr.json()["source_cidr"], "192.0.2.0/24")

        invalid = self.control.post(
            "/v1/firewall/access-rules",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "target_zone": "stage",
                "source_cidr": "192.0.2.999/24",
            },
        )
        self.assertEqual(invalid.status_code, 422)

        ipv6 = self.control.post(
            "/v1/firewall/access-rules",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "target_zone": "stage",
                "source_cidr": "2001:db8::/64",
            },
        )
        self.assertEqual(ipv6.status_code, 422)

    def test_firewall_egress_rules_follow_lock_lifecycle(self) -> None:
        lock = self.lock.post("/v1/locks/requests", json={"resource_id": "namespace:repo-a", "namespace": "repo-a"})
        self.assertEqual(lock.status_code, 201)
        self.assertEqual(lock.json()["status"], "granted")

        allow_all = self.control.post(
            "/v1/firewall/egress-rules",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "mode": "allow_all",
            },
        )
        self.assertEqual(allow_all.status_code, 201)

        allow_ip = self.control.post(
            "/v1/firewall/egress-rules",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "mode": "cidr",
                "target_cidr": "192.0.2.42",
            },
        )
        self.assertEqual(allow_ip.status_code, 201)

        listed = self.control.get("/v1/firewall/egress-rules?namespace=repo-a")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual([row["mode"] for row in listed.json()], ["allow_all", "cidr"])
        self.assertEqual(listed.json()[1]["target_cidr"], "192.0.2.42")
        self.assertEqual(self.services.registry.effective_firewall_egress_entries(), ["0.0.0.0/1", "128.0.0.0/1", "192.0.2.42"])

        deleted = self.control.delete(f"/v1/firewall/egress-rules/{allow_all.json()['id']}")
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(self.services.registry.effective_firewall_egress_entries(), ["192.0.2.42"])

        release = self.lock.post(f"/v1/locks/requests/{lock.json()['id']}/release", json={"released_by": "repo-a"})
        self.assertEqual(release.status_code, 200)

        listed_after = self.control.get("/v1/firewall/egress-rules?namespace=repo-a")
        self.assertEqual(listed_after.status_code, 200)
        self.assertEqual(listed_after.json(), [])
        self.assertEqual(self.services.registry.effective_firewall_egress_entries(), [])

    def test_firewall_egress_rules_accept_cidrs_and_legacy_single_ip_input(self) -> None:
        lock = self.lock.post("/v1/locks/requests", json={"resource_id": "namespace:repo-a", "namespace": "repo-a"})
        self.assertEqual(lock.status_code, 201)

        cidr = self.control.post(
            "/v1/firewall/egress-rules",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "mode": "cidr",
                "target_cidr": "192.0.2.0/24",
            },
        )
        self.assertEqual(cidr.status_code, 201)
        self.assertEqual(cidr.json()["mode"], "cidr")
        self.assertEqual(cidr.json()["target_cidr"], "192.0.2.0/24")

        legacy = self.control.post(
            "/v1/firewall/egress-rules",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "mode": "single_ip",
                "target_ip": "192.0.2.42/32",
            },
        )
        self.assertEqual(legacy.status_code, 201)
        self.assertEqual(legacy.json()["mode"], "cidr")
        self.assertEqual(legacy.json()["target_cidr"], "192.0.2.42")

        listed = self.control.get("/v1/firewall/egress-rules?namespace=repo-a")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual([row["target_cidr"] for row in listed.json()], ["192.0.2.0/24", "192.0.2.42"])

    def test_firewall_egress_rules_validate_mode_and_target_cidr(self) -> None:
        lock = self.lock.post("/v1/locks/requests", json={"resource_id": "namespace:repo-a", "namespace": "repo-a"})
        self.assertEqual(lock.status_code, 201)

        missing = self.control.post(
            "/v1/firewall/egress-rules",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "mode": "cidr",
            },
        )
        self.assertEqual(missing.status_code, 422)

        invalid = self.control.post(
            "/v1/firewall/egress-rules",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "mode": "cidr",
                "target_cidr": "192.0.2.999/24",
            },
        )
        self.assertEqual(invalid.status_code, 422)

        ipv6 = self.control.post(
            "/v1/firewall/egress-rules",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "mode": "cidr",
                "target_cidr": "2001:db8::/64",
            },
        )
        self.assertEqual(ipv6.status_code, 422)

        reject_target_on_allow_all = self.control.post(
            "/v1/firewall/egress-rules",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "mode": "allow_all",
                "target_cidr": "192.0.2.42",
            },
        )
        self.assertEqual(reject_target_on_allow_all.status_code, 422)

    def test_endpoint_workaround_rules_follow_lock_lifecycle(self) -> None:
        lock = self.lock.post("/v1/locks/requests", json={"resource_id": "namespace:repo-a", "namespace": "repo-a"})
        self.assertEqual(lock.status_code, 201)
        self.assertEqual(lock.json()["status"], "granted")

        fqdn = self.control.post(
            "/v1/endpoint-workarounds",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "kind": "fqdn",
                "value": "Updates.Example.Test.",
                "workaround_type": "hosts_entry",
                "target_ip": "192.0.2.42",
                "apply_on": ["appliance", "appliance"],
                "maps_to_service": "update_repository",
                "manifest_id": "appliance-smoke",
                "constraint_id": "legacy-update-fqdn",
            },
        )
        self.assertEqual(fqdn.status_code, 201)
        self.assertEqual(fqdn.json()["value"], "updates.example.test")
        self.assertEqual(fqdn.json()["apply_on"], ["appliance"])

        dnat = self.control.post(
            "/v1/endpoint-workarounds",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "kind": "ip",
                "value": "203.0.113.10",
                "workaround_type": "dnat",
                "target_ip": "192.0.2.43",
                "apply_on": ["appliance"],
                "maps_to_service": "payment_simulator",
            },
        )
        self.assertEqual(dnat.status_code, 201)

        listed = self.control.get("/v1/endpoint-workarounds?namespace=repo-a")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual([row["workaround_type"] for row in listed.json()], ["hosts_entry", "dnat"])

        release = self.lock.post(f"/v1/locks/requests/{lock.json()['id']}/release", json={"released_by": "repo-a"})
        self.assertEqual(release.status_code, 200)

        listed_after = self.control.get("/v1/endpoint-workarounds?namespace=repo-a")
        self.assertEqual(listed_after.status_code, 200)
        self.assertEqual(listed_after.json(), [])

    def test_endpoint_workaround_rules_validate_fixed_endpoint_shape(self) -> None:
        lock = self.lock.post("/v1/locks/requests", json={"resource_id": "namespace:repo-a", "namespace": "repo-a"})
        self.assertEqual(lock.status_code, 201)

        invalid_fqdn_workaround = self.control.post(
            "/v1/endpoint-workarounds",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "kind": "fqdn",
                "value": "updates.example.test",
                "workaround_type": "dnat",
                "target_ip": "192.0.2.42",
                "apply_on": ["appliance"],
            },
        )
        self.assertEqual(invalid_fqdn_workaround.status_code, 422)

        invalid_ip_workaround = self.control.post(
            "/v1/endpoint-workarounds",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "kind": "ip",
                "value": "203.0.113.10",
                "workaround_type": "hosts_entry",
                "target_ip": "192.0.2.42",
                "apply_on": ["appliance"],
            },
        )
        self.assertEqual(invalid_ip_workaround.status_code, 422)

        invalid_ip_literal = self.control.post(
            "/v1/endpoint-workarounds",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "kind": "ip",
                "value": "not-an-ip",
                "workaround_type": "dnat",
                "target_ip": "192.0.2.42",
                "apply_on": ["appliance"],
            },
        )
        self.assertEqual(invalid_ip_literal.status_code, 422)

        invalid_target = self.control.post(
            "/v1/endpoint-workarounds",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "kind": "fqdn",
                "value": "updates.example.test",
                "workaround_type": "hosts_entry",
                "target_ip": "2001:db8::1",
                "apply_on": ["appliance"],
            },
        )
        self.assertEqual(invalid_target.status_code, 422)

    def test_endpoint_workaround_evidence_is_reported_through_run_events(self) -> None:
        lock = self.lock.post("/v1/locks/requests", json={"resource_id": "namespace:repo-a", "namespace": "repo-a"})
        self.assertEqual(lock.status_code, 201)
        rule = self.control.post(
            "/v1/endpoint-workarounds",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "kind": "fqdn",
                "value": "updates.example.test",
                "workaround_type": "hosts_entry",
                "target_ip": "192.0.2.42",
                "apply_on": ["appliance"],
                "maps_to_service": "update_repository",
                "constraint_id": "legacy-update-fqdn",
            },
        )
        self.assertEqual(rule.status_code, 201)

        run = self.control.post(
            "/v1/runs",
            json={
                "namespace": "repo-a",
                "workflow_name": "endpoint-workaround-smoke",
                "workflow_version": "v1",
                "declared_tests": ["apply-endpoints"],
                "selected_tests": ["apply-endpoints"],
            },
        )
        self.assertEqual(run.status_code, 201)
        run_id = run.json()["id"]

        event = self.control.post(
            f"/v1/runs/{run_id}/events",
            json={
                "event_type": "info",
                "message": "applied fixed update endpoint workaround",
                "details": {
                    "type": "endpoint_workaround_applied",
                    "rule_id": rule.json()["id"],
                    "constraint_id": "legacy-update-fqdn",
                    "kind": "fqdn",
                    "value": "updates.example.test",
                    "workaround_type": "hosts_entry",
                    "target_ip": "192.0.2.42",
                    "apply_on": "appliance",
                    "status": "completed",
                    "observed_state": {
                        "file": "/etc/hosts",
                        "line": "192.0.2.42 updates.example.test",
                    },
                    "evidence": {"exit_code": 0},
                },
            },
        )
        self.assertEqual(event.status_code, 201)
        self.assertEqual(event.json()["details"]["type"], "endpoint_workaround_applied")
        self.assertEqual(event.json()["details"]["rule_id"], rule.json()["id"])

        events = self.control.get(f"/v1/runs/{run_id}/events")
        self.assertEqual(events.status_code, 200)
        self.assertEqual(events.json()[0]["details"]["observed_state"]["line"], "192.0.2.42 updates.example.test")

    def test_endpoint_workaround_evidence_must_match_declared_rule(self) -> None:
        lock = self.lock.post("/v1/locks/requests", json={"resource_id": "namespace:repo-a", "namespace": "repo-a"})
        self.assertEqual(lock.status_code, 201)
        rule = self.control.post(
            "/v1/endpoint-workarounds",
            json={
                "namespace": "repo-a",
                "lock_resource_id": "namespace:repo-a",
                "kind": "ip",
                "value": "203.0.113.10",
                "workaround_type": "dnat",
                "target_ip": "192.0.2.42",
                "apply_on": ["appliance"],
            },
        )
        self.assertEqual(rule.status_code, 201)
        run = self.control.post(
            "/v1/runs",
            json={
                "namespace": "repo-a",
                "workflow_name": "endpoint-workaround-smoke",
                "workflow_version": "v1",
            },
        )
        self.assertEqual(run.status_code, 201)

        mismatch = self.control.post(
            f"/v1/runs/{run.json()['id']}/events",
            json={
                "event_type": "info",
                "message": "applied fixed IP endpoint workaround",
                "details": {
                    "type": "endpoint_workaround_applied",
                    "rule_id": rule.json()["id"],
                    "kind": "ip",
                    "value": "203.0.113.10",
                    "workaround_type": "dnat",
                    "target_ip": "192.0.2.99",
                    "apply_on": "appliance",
                    "status": "completed",
                },
            },
        )
        self.assertEqual(mismatch.status_code, 422)
        self.assertIn("target_ip", mismatch.json()["detail"])

    def test_resize_layer3_requires_stopped_vm(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node-resize-running",
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]

        resize = self.control.post(f"/v1/vms/{vm_id}/resize-layer3", json={"new_size_mb": 2048})
        self.assertEqual(resize.status_code, 422)
        self.assertIn("must be stopped", resize.json()["detail"]["reason"])

    def test_create_vm_can_request_initial_layer3_size(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node-large-root",
                "layer3_size_mb": 4096,
                "autostart": False,
            },
        )
        self.assertEqual(create.status_code, 202)
        payload = create.json()
        self.assertTrue(
            any(
                "qemu-img create" in " ".join(command) and str(4096 * 1024 * 1024) in command
                for command in payload["planned_commands"]
            )
        )

        layer3_path = self.root / "layer3" / "repo-a--node-large-root.qcow2"
        data = json.loads(layer3_path.read_text())
        self.assertEqual(data["virtual_size_bytes"], 4096 * 1024 * 1024)

    def test_resize_layer3_grows_stopped_vm_disk(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node-resize-stopped",
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]

        stop = self.control.post(f"/v1/vms/{vm_id}/stop")
        self.assertEqual(stop.status_code, 202)

        resize = self.control.post(f"/v1/vms/{vm_id}/resize-layer3", json={"new_size_mb": 2048})
        self.assertEqual(resize.status_code, 202)
        payload = resize.json()
        self.assertEqual(payload["action"], "resize-layer3")
        self.assertEqual(payload["previous_virtual_size_bytes"], 1024 * 1024 * 1024)
        self.assertEqual(payload["new_virtual_size_bytes"], 2048 * 1024 * 1024)
        self.assertTrue(any("qemu-img resize" in " ".join(command) for command in payload["planned_commands"]))

        layer3_path = self.root / "layer3" / "repo-a--node-resize-stopped.qcow2"
        data = json.loads(layer3_path.read_text())
        self.assertEqual(data["virtual_size_bytes"], 2048 * 1024 * 1024)

    def test_build_services_uses_environment_config_path(self) -> None:
        original = os.environ.get("KVM_CONTROL_CONFIG")
        os.environ["KVM_CONTROL_CONFIG"] = str(self.config_path)
        services = None
        try:
            services = build_services()
            self.assertEqual(services.config.source_path, str(self.config_path))
            self.assertEqual(str(services.config.storage.state_dir), str(self.root / "state"))
        finally:
            if services is not None:
                services.monitor.stop()
            if original is None:
                os.environ.pop("KVM_CONTROL_CONFIG", None)
            else:
                os.environ["KVM_CONTROL_CONFIG"] = original

    def test_basic_auth_is_enforced_when_configured(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {"username": "test", "password": "secret"}
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))

        unauthenticated = self.control.get("/v1/vms")
        self.assertEqual(unauthenticated.status_code, 401)

        wrong_password = self.control.get("/v1/vms", auth=("test", "wrong"))
        self.assertEqual(wrong_password.status_code, 401)

        authenticated = self.control.get("/v1/vms", auth=("test", "secret"))
        self.assertEqual(authenticated.status_code, 200)

    def test_bearer_auth_onboards_repository_token_and_enforces_namespace_zone(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {"admin_token": "admin-secret"}
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))
        admin_headers = {"Authorization": "Bearer admin-secret"}

        created_token = self.control.post(
            "/v1/admin/auth/tokens",
            json={"username": "git.repo-a"},
            headers=admin_headers,
        )
        self.assertEqual(created_token.status_code, 201)
        repo_headers = {"Authorization": f"Bearer {created_token.json()['token']}"}

        whoami = self.control.get("/v1/auth/whoami", headers=repo_headers)
        self.assertEqual(whoami.status_code, 200)
        self.assertEqual(whoami.json()["namespace"], "git.repo-a")
        self.assertEqual(whoami.json()["allowed_zones"], ["dev"])

        lock = self.lock.post("/v1/locks/requests", json={"resource_id": "repo-lock"}, headers=repo_headers)
        self.assertEqual(lock.status_code, 201)
        self.assertEqual(lock.json()["namespace"], "git.repo-a")
        self.assertEqual(lock.json()["effective_namespace"], "git.repo-a")
        self.assertEqual(lock.json()["authenticated_as"], "git.repo-a")

        mismatch = self.lock.post(
            "/v1/locks/requests",
            json={"resource_id": "repo-lock", "namespace": "git.repo-b"},
            headers=repo_headers,
        )
        self.assertEqual(mismatch.status_code, 403)

        missing_agent_session = self.control.post(
            "/v1/vms",
            json={
                "template_id": "ubuntu-24.04",
                "vm_slot": "missing-session",
                "network_id": "dev",
                "autostart": False,
            },
            headers=repo_headers,
        )
        self.assertEqual(missing_agent_session.status_code, 422)
        self.assertIn("agent_session_id", missing_agent_session.json()["detail"])

        stage_vm = self.control.post(
            "/v1/vms",
            json={
                "template_id": "ubuntu-24.04",
                "vm_slot": "stage-denied",
                "network_id": "stage",
                "autostart": False,
                "agent_session_id": "pytest-auth-session",
            },
            headers=repo_headers,
        )
        self.assertEqual(stage_vm.status_code, 403)

        nested_denied = self.control.post(
            "/v1/vms",
            json={
                "template_id": "ubuntu-24.04",
                "vm_slot": "nested-denied",
                "network_id": "dev",
                "autostart": False,
                "agent_session_id": "pytest-auth-session",
                "nested_virtualization": True,
            },
            headers=repo_headers,
        )
        self.assertEqual(nested_denied.status_code, 403)
        self.assertEqual(nested_denied.json()["detail"], "nested virtualization denied")

        kvm_control_token = self.control.post(
            "/v1/admin/auth/tokens",
            json={"username": "git.kvm-control"},
            headers=admin_headers,
        )
        self.assertEqual(kvm_control_token.status_code, 201)
        kvm_control_headers = {"Authorization": f"Bearer {kvm_control_token.json()['token']}"}
        nested_allowed = self.control.post(
            "/v1/vms",
            json={
                "template_id": "ubuntu-24.04",
                "vm_slot": "nested-allowed",
                "network_id": "dev",
                "autostart": False,
                "agent_session_id": "pytest-auth-session",
                "nested_virtualization": True,
            },
            headers=kvm_control_headers,
        )
        self.assertEqual(nested_allowed.status_code, 202)
        self.assertTrue(nested_allowed.json()["nested_virtualization"])

        dev_vm = self.control.post(
            "/v1/vms",
            json={
                "template_id": "ubuntu-24.04",
                "vm_slot": "node1",
                "network_id": "dev",
                "autostart": False,
                "agent_session_id": "pytest-auth-session",
            },
            headers=repo_headers,
        )
        self.assertEqual(dev_vm.status_code, 202)
        self.assertEqual(dev_vm.json()["namespace"], "git.repo-a")

        self.services.registry.record_archived_vm(
            self.services.registry.get_vm(dev_vm.json()["vm_id"]),
            trashed_path=str(self.root / "trash" / "git.repo-a-node1.qcow2"),
            reason="test",
        )
        archived = self.control.get("/v1/archived-vms", headers=repo_headers)
        self.assertEqual(archived.status_code, 200)
        self.assertTrue(any(item["vm_id"] == dev_vm.json()["vm_id"] for item in archived.json()))

        other_token = self.control.post(
            "/v1/admin/auth/tokens",
            json={"username": "git.repo-b"},
            headers=admin_headers,
        )
        self.assertEqual(other_token.status_code, 201)
        other_headers = {"Authorization": f"Bearer {other_token.json()['token']}"}
        other_archived = self.control.get("/v1/archived-vms", headers=other_headers)
        self.assertEqual(other_archived.status_code, 200)
        self.assertFalse(any(item["vm_id"] == dev_vm.json()["vm_id"] for item in other_archived.json()))

        def catalog_image(image_id: str, namespace: str, keyword: str) -> dict:
            return {
                "image_id": image_id,
                "namespace": namespace,
                "source_vm_id": image_id,
                "source_template_id": "ubuntu-24.04",
                "workflow_name": "pytest",
                "workflow_version": "v1",
                "git_ref": None,
                "local_path": str(self.root / "layer2" / f"{image_id}.qcow2"),
                "remote_path": str(self.root / "layer2" / f"{image_id}.qcow2"),
                "remote_backend": "local",
                "cache_state": "present",
                "checksum_sha256": None,
                "size_bytes": 1,
                "metadata": {"keywords": [keyword], "description": f"{namespace} image"},
                "last_published_at": None,
                "last_fetched_at": None,
                "last_retired_at": None,
            }

        self.services.registry.upsert_image(catalog_image("default.sandbox.layer2", "default", "sandbox"))
        self.services.registry.upsert_image(catalog_image("git.repo-a.private.layer2", "git.repo-a", "private"))
        self.services.registry.upsert_image(catalog_image("git.repo-b.private.layer2", "git.repo-b", "private"))

        repo_images = self.control.get("/v1/images", headers=repo_headers)
        self.assertEqual(repo_images.status_code, 200)
        self.assertEqual(
            [image["image_id"] for image in repo_images.json()],
            ["default.sandbox.layer2", "git.repo-a.private.layer2"],
        )
        default_image = self.control.get("/v1/images/default.sandbox.layer2", headers=repo_headers)
        self.assertEqual(default_image.status_code, 200)
        other_private_image = self.control.get("/v1/images/git.repo-b.private.layer2", headers=repo_headers)
        self.assertEqual(other_private_image.status_code, 403)
        sandbox_images = self.control.get("/v1/images", params={"keyword": "sandbox"}, headers=repo_headers)
        self.assertEqual([image["image_id"] for image in sandbox_images.json()], ["default.sandbox.layer2"])

    def test_bearer_auth_honors_forwarded_for_from_trusted_mcp_proxy(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {
            "admin_token": "admin-secret",
            "trusted_proxy_cidrs": ["127.0.0.1/32"],
            "acl": [
                {"users": ["admin"], "source_cidrs": ["127.0.0.1/32"], "zones": ["dev", "stage", "misc", "live"]},
                {"users": ["git.*"], "source_cidrs": ["192.0.2.1/32"], "zones": ["dev"]},
            ],
        }
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))

        created_token = self.control.post(
            "/v1/admin/auth/tokens",
            json={"username": "git.repo-a"},
            headers={"Authorization": "Bearer admin-secret"},
        )
        self.assertEqual(created_token.status_code, 201)
        headers = {
            "Authorization": f"Bearer {created_token.json()['token']}",
            "X-Forwarded-For": "192.0.2.1",
        }

        whoami = self.control.get("/v1/auth/whoami", headers=headers)

        self.assertEqual(whoami.status_code, 200)
        self.assertEqual(whoami.json()["username"], "git.repo-a")
        self.assertEqual(whoami.json()["source_ip"], "192.0.2.1")
        self.assertEqual(whoami.json()["allowed_zones"], ["dev"])

    def test_repository_self_registration_key_mints_one_repo_token(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {"admin_token": "admin-secret"}
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))
        admin_headers = {"Authorization": "Bearer admin-secret"}

        created_key = self.control.post(
            "/v1/admin/auth/repository-self-registration-keys",
            json={"name": "codex-local-repositories"},
            headers=admin_headers,
        )
        self.assertEqual(created_key.status_code, 201)
        self.assertTrue(created_key.json()["key"].startswith("kvmreg_"))
        registration_headers = {"Authorization": f"Bearer {created_key.json()['key']}"}

        listed_keys = self.control.get("/v1/admin/auth/repository-self-registration-keys", headers=admin_headers)
        self.assertEqual(listed_keys.status_code, 200)
        self.assertEqual(listed_keys.json()[0]["name"], "codex-local-repositories")
        self.assertNotIn("key", listed_keys.json()[0])

        registered = self.control.post(
            "/v1/auth/repository-self-registration",
            json={"repository": "repo-a", "agent_session_id": "pytest-self-register"},
            headers=registration_headers,
        )
        self.assertEqual(registered.status_code, 201)
        self.assertEqual(registered.json()["username"], "git.repo-a")
        self.assertEqual(registered.json()["namespace"], "git.repo-a")
        self.assertEqual(registered.json()["token_file"], "repo.auth.token")
        self.assertTrue(registered.json()["token"].startswith("kvm_"))
        repo_headers = {"Authorization": f"Bearer {registered.json()['token']}"}

        whoami = self.control.get("/v1/auth/whoami", headers=repo_headers)
        self.assertEqual(whoami.status_code, 200)
        self.assertEqual(whoami.json()["username"], "git.repo-a")
        self.assertEqual(whoami.json()["namespace"], "git.repo-a")

        duplicate = self.control.post(
            "/v1/auth/repository-self-registration",
            json={"repository": "repo-a", "agent_session_id": "pytest-duplicate"},
            headers=registration_headers,
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(duplicate.json()["detail"], "repository is already registered")

        revoked = self.control.post(
            f"/v1/admin/auth/tokens/{registered.json()['token_id']}/revoke",
            headers=admin_headers,
        )
        self.assertEqual(revoked.status_code, 200)
        replacement = self.control.post(
            "/v1/auth/repository-self-registration",
            json={"repository": "repo-a", "agent_session_id": "pytest-replacement"},
            headers=registration_headers,
        )
        self.assertEqual(replacement.status_code, 201)
        self.assertNotEqual(replacement.json()["token_id"], registered.json()["token_id"])

    def test_repository_self_registration_rejects_bad_key_and_git_prefix(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {"admin_token": "admin-secret"}
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))

        missing = self.control.post("/v1/auth/repository-self-registration", json={"repository": "repo-a"})
        self.assertEqual(missing.status_code, 401)

        admin_headers = {"Authorization": "Bearer admin-secret"}
        created_key = self.control.post(
            "/v1/admin/auth/repository-self-registration-keys",
            json={"name": "codex-local-repositories"},
            headers=admin_headers,
        )
        self.assertEqual(created_key.status_code, 201)
        prefixed = self.control.post(
            "/v1/auth/repository-self-registration",
            json={"repository": "git.repo-a"},
            headers={"Authorization": f"Bearer {created_key.json()['key']}"},
        )
        self.assertEqual(prefixed.status_code, 422)

    def test_open_auth_mode_accepts_anonymous_clients_and_enforces_valid_token(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {"mode": "open", "admin_token": "admin-secret"}
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))

        anonymous = self.control.get("/v1/auth/whoami")
        self.assertEqual(anonymous.status_code, 200)
        self.assertEqual(anonymous.json()["username"], "anonymous")
        self.assertEqual(anonymous.json()["auth_mode"], "open")
        self.assertEqual(anonymous.json()["credential_status"], "missing")
        self.assertEqual(anonymous.json()["allowed_zones"], ["dev", "stage", "misc", "live"])

        created_token = self.control.post("/v1/admin/auth/tokens", json={"username": "git.repo-a"})
        self.assertEqual(created_token.status_code, 201)
        repo_headers = {"Authorization": f"Bearer {created_token.json()['token']}"}

        whoami = self.control.get("/v1/auth/whoami", headers=repo_headers)
        self.assertEqual(whoami.status_code, 200)
        self.assertEqual(whoami.json()["username"], "git.repo-a")
        self.assertEqual(whoami.json()["namespace"], "git.repo-a")
        self.assertEqual(whoami.json()["allowed_zones"], ["dev"])
        self.assertEqual(whoami.json()["auth_mode"], "open")
        self.assertEqual(whoami.json()["credential_status"], "valid")
        self.assertEqual(whoami.json()["credential_principal"]["username"], "git.repo-a")
        self.assertEqual(whoami.json()["credential_principal"]["allowed_zones"], ["dev"])

        lock = self.lock.post(
            "/v1/locks/requests",
            json={"resource_id": "repo-lock", "namespace": "git.repo-b"},
            headers=repo_headers,
        )
        self.assertEqual(lock.status_code, 403)

        allowed_lock = self.lock.post(
            "/v1/locks/requests",
            json={"resource_id": "repo-lock"},
            headers=repo_headers,
        )
        self.assertEqual(allowed_lock.status_code, 201)
        self.assertEqual(allowed_lock.json()["namespace"], "git.repo-a")
        self.assertEqual(allowed_lock.json()["authenticated_as"], "git.repo-a")

        stage_vm = self.control.post(
            "/v1/vms",
            json={
                "template_id": "ubuntu-24.04",
                "vm_slot": "stage-open",
                "network_id": "stage",
                "autostart": False,
                "agent_session_id": "pytest-open-session",
            },
            headers=repo_headers,
        )
        self.assertEqual(stage_vm.status_code, 403)

    def test_open_auth_mode_rejects_invalid_token(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {"mode": "open", "admin_token": "admin-secret"}
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))

        whoami = self.control.get("/v1/auth/whoami", headers={"Authorization": "Bearer not-a-real-token"})
        self.assertEqual(whoami.status_code, 401)

        listed = self.control.get("/v1/vms", headers={"Authorization": "Bearer not-a-real-token"})
        self.assertEqual(listed.status_code, 401)

    def test_open_auth_mode_rejects_acl_denied_token(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {
            "mode": "open",
            "admin_token": "admin-secret",
            "acl": [
                {"users": ["admin"], "zones": ["dev", "stage", "misc", "live"]},
                {"users": ["git.*"], "source_cidrs": ["192.0.2.0/24"], "zones": ["dev"]},
            ],
        }
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))

        created_token = self.control.post("/v1/admin/auth/tokens", json={"username": "git.repo-a"})
        self.assertEqual(created_token.status_code, 201)
        repo_headers = {"Authorization": f"Bearer {created_token.json()['token']}"}

        whoami = self.control.get("/v1/auth/whoami", headers=repo_headers)
        self.assertEqual(whoami.status_code, 403)

    def test_dev_token_uses_requested_dev_prefixed_namespace(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {"admin_token": "admin-secret"}
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))
        admin_headers = {"Authorization": "Bearer admin-secret"}

        created_token = self.control.post(
            "/v1/admin/auth/tokens",
            json={"username": "dev"},
            headers=admin_headers,
        )
        self.assertEqual(created_token.status_code, 201)
        dev_headers = {"Authorization": f"Bearer {created_token.json()['token']}"}

        whoami = self.control.get("/v1/auth/whoami", headers=dev_headers)
        self.assertEqual(whoami.status_code, 200)
        self.assertIsNone(whoami.json()["namespace"])
        self.assertEqual(whoami.json()["role"], "dev")
        self.assertEqual(whoami.json()["allowed_zones"], ["dev"])

        lock = self.lock.post(
            "/v1/locks/requests",
            json={"resource_id": "repo-lock", "namespace": "repo-a"},
            headers=dev_headers,
        )
        self.assertEqual(lock.status_code, 201)
        self.assertEqual(lock.json()["namespace"], "dev.repo-a")
        self.assertEqual(lock.json()["effective_namespace"], "dev.repo-a")

        explicit_dev = self.lock.post(
            "/v1/locks/requests",
            json={"resource_id": "repo-lock-2", "namespace": "dev.repo-b"},
            headers=dev_headers,
        )
        self.assertEqual(explicit_dev.status_code, 201)
        self.assertEqual(explicit_dev.json()["namespace"], "dev.repo-b")

        escaped = self.lock.post(
            "/v1/locks/requests",
            json={"resource_id": "repo-lock", "namespace": "git.repo-a"},
            headers=dev_headers,
        )
        self.assertEqual(escaped.status_code, 403)

    def test_control_api_exposes_lock_routes(self) -> None:
        created = self.control.post(
            "/v1/locks/requests",
            json={"resource_id": "namespace:repo-a", "namespace": "repo-a"},
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["status"], "granted")
        self.assertIsNotNone(created.json()["lease_expires_at"])

        listed = self.control.get("/v1/locks/resources")
        self.assertEqual(listed.status_code, 200)
        self.assertTrue(any(row["resource_id"] == "namespace:repo-a" for row in listed.json()))

        queued = self.control.get("/v1/locks/resources/namespace:repo-a/queue")
        self.assertEqual(queued.status_code, 200)
        self.assertEqual(len(queued.json()), 1)

        release = self.control.post(
            f"/v1/locks/requests/{created.json()['id']}/release",
            json={"released_by": "repo-a"},
        )
        self.assertEqual(release.status_code, 200)

    def test_namespace_lock_lease_refresh_and_expiry_shutdown_namespace_vms(self) -> None:
        lock = self.lock.post("/v1/locks/requests", json={"resource_id": "namespace:repo-lease", "namespace": "repo-lease"})
        self.assertEqual(lock.status_code, 201)
        request_id = lock.json()["id"]

        refresh = self.lock.post(f"/v1/locks/requests/{request_id}/lease/refresh")
        self.assertEqual(refresh.status_code, 200)
        self.assertEqual(refresh.json()["namespace"], "repo-lease")
        self.assertIsNotNone(refresh.json()["last_lease_refresh_at"])
        self.assertIsNotNone(refresh.json()["lease_expires_at"])

        create_a = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-lease",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node-a",
                "network_id": "dev",
                "lock_resource_id": "namespace:repo-lease",
            },
        )
        create_b = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-lease",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node-b",
                "network_id": "dev",
                "lock_resource_id": "namespace:repo-lease",
            },
        )
        self.assertEqual(create_a.status_code, 202)
        self.assertEqual(create_b.status_code, 202)
        vm_ids = {create_a.json()["vm_id"], create_b.json()["vm_id"]}

        with self.services.registry.tx() as conn:
            conn.execute(
                """
                UPDATE lock_requests
                SET lease_expires_at = datetime(CURRENT_TIMESTAMP, '-1 seconds'),
                    lease_expired_at = NULL
                WHERE id = ?
                """,
                (request_id,),
            )
        self.services.monitor.sample_all_runs()

        for vm_id in vm_ids:
            vm = self.control.get(f"/v1/vms/{vm_id}")
            self.assertEqual(vm.status_code, 200)
            self.assertEqual(vm.json()["power_state"], "stopped")
            self.assertEqual(vm.json()["layer3_presence"], "present")

        expired = self.services.registry.get_lock_request(request_id)
        self.assertIsNotNone(expired["lease_expired_at"])
        blocked = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-lease",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node-c",
                "network_id": "dev",
                "lock_resource_id": "namespace:repo-lease",
            },
        )
        self.assertEqual(blocked.status_code, 423)
        self.assertIn("refresh lease", blocked.json()["detail"]["reason"])
        events = self.services.registry.list_status_events(limit=100)
        self.assertTrue(any(event["kind"] == "lease" and event["status"] == "expired" and event["namespace"] == "repo-lease" for event in events))

    def test_lock_lease_can_request_bounded_long_ttl(self) -> None:
        lock = self.lock.post(
            "/v1/locks/requests",
            json={"resource_id": "namespace:repo-long", "namespace": "repo-long", "lease_ttl_seconds": 3 * 24 * 60 * 60},
        )
        self.assertEqual(lock.status_code, 201)
        self.assertEqual(lock.json()["lease_ttl_seconds"], 3 * 24 * 60 * 60)

        refresh = self.lock.post(
            f"/v1/locks/requests/{lock.json()['id']}/lease/refresh",
            json={"lease_ttl_seconds": 4 * 24 * 60 * 60},
        )
        self.assertEqual(refresh.status_code, 200)
        self.assertEqual(refresh.json()["lease_ttl_seconds"], 4 * 24 * 60 * 60)

        too_long = self.lock.post(
            f"/v1/locks/requests/{lock.json()['id']}/lease/refresh",
            json={"lease_ttl_seconds": 8 * 24 * 60 * 60},
        )
        self.assertEqual(too_long.status_code, 422)

    def test_reconcile_discards_stale_stopped_ephemeral_vms_only(self) -> None:
        layer2 = self.root / "layer2" / "repo-cleanup--ubuntu-24.04.qcow2"
        layer2.parent.mkdir(parents=True, exist_ok=True)
        layer2.write_text("layer2", encoding="utf-8")

        def seed(vm_slot: str, retention: str = "ephemeral") -> str:
            vm_id = f"repo-cleanup-{vm_slot}"
            layer3 = self.root / "layer3" / f"repo-cleanup--{vm_slot}.qcow2"
            layer3.parent.mkdir(parents=True, exist_ok=True)
            layer3.write_text(vm_id, encoding="utf-8")
            self.services.registry.upsert_vm(
                {
                    "vm_id": vm_id,
                    "namespace": "repo-cleanup",
                    "vm_slot": vm_slot,
                    "template_id": "ubuntu-24.04",
                    "network_id": "dev",
                    "vcpus": 1,
                    "memory_mb": 512,
                    "estimated_layer3_growth_mb": None,
                    "reserved_ip": "10.90.0.120",
                    "reserved_mac": f"52:54:00:00:10:{len(vm_slot):02x}",
                    "power_state": "stopped",
                    "readiness_state": "configuring",
                    "status": "stopped",
                    "layer2_path": str(layer2),
                    "layer2_presence": "present",
                    "layer3_path": str(layer3),
                    "layer3_presence": "present",
                    "pause_reason": None,
                    "lock_resource_id": "namespace:repo-cleanup",
                    "source_image_id": None,
                    "retention": retention,
                    "agent_session_id": "cleanup-test",
                }
            )
            return vm_id

        stale = seed("stale")
        recent = seed("recent")
        retained = seed("retained", retention="keep_stopped")
        with self.services.registry.tx() as conn:
            conn.execute(
                """
                UPDATE vm_instances
                SET updated_at = CURRENT_TIMESTAMP,
                    stopped_at = datetime(CURRENT_TIMESTAMP, '-25 hours')
                WHERE vm_id IN (?, ?)
                """,
                (stale, retained),
            )

        result = cleanup_stale_stopped_ephemeral_vms(self.services.config, self.services.registry, self.services.executor)
        self.assertEqual([item["vm_id"] for item in result["cleaned"]], [stale])
        self.assertIsNone(self.services.registry.get_vm(stale))
        self.assertIsNotNone(self.services.registry.get_vm(recent))
        self.assertIsNotNone(self.services.registry.get_vm(retained))
        self.assertFalse((self.root / "layer3" / "repo-cleanup--stale.qcow2").exists())
        self.assertTrue((self.root / "layer3" / "repo-cleanup--recent.qcow2").exists())
        self.assertTrue((self.root / "layer3" / "repo-cleanup--retained.qcow2").exists())

    def test_monitor_runs_stale_stopped_ephemeral_vm_cleanup(self) -> None:
        layer2 = self.root / "layer2" / "repo-monitor-cleanup--ubuntu-24.04.qcow2"
        layer3 = self.root / "layer3" / "repo-monitor-cleanup--stale.qcow2"
        layer2.parent.mkdir(parents=True, exist_ok=True)
        layer3.parent.mkdir(parents=True, exist_ok=True)
        layer2.write_text("layer2", encoding="utf-8")
        layer3.write_text("stale", encoding="utf-8")
        self.services.registry.upsert_vm(
            {
                "vm_id": "repo-monitor-cleanup-stale",
                "namespace": "repo-monitor-cleanup",
                "vm_slot": "stale",
                "template_id": "ubuntu-24.04",
                "network_id": "dev",
                "vcpus": 1,
                "memory_mb": 512,
                "estimated_layer3_growth_mb": None,
                "reserved_ip": "10.90.0.121",
                "reserved_mac": "52:54:00:00:20:01",
                "power_state": "stopped",
                "readiness_state": "configuring",
                "status": "stopped",
                "layer2_path": str(layer2),
                "layer2_presence": "present",
                "layer3_path": str(layer3),
                "layer3_presence": "present",
                "pause_reason": None,
                "lock_resource_id": "namespace:repo-monitor-cleanup",
                "source_image_id": None,
                "retention": "ephemeral",
                "agent_session_id": "cleanup-test",
            }
        )
        with self.services.registry.tx() as conn:
            conn.execute(
                """
                UPDATE vm_instances
                SET updated_at = CURRENT_TIMESTAMP,
                    stopped_at = datetime(CURRENT_TIMESTAMP, '-25 hours')
                WHERE vm_id = 'repo-monitor-cleanup-stale'
                """
            )

        self.services.monitor._last_stale_ephemeral_cleanup_at = 0.0
        self.services.monitor.sample_all_runs()
        self.assertIsNone(self.services.registry.get_vm("repo-monitor-cleanup-stale"))
        self.assertFalse(layer3.exists())

    def test_monitor_runs_stale_trash_cleanup(self) -> None:
        self.services.config.cleanup.trash_file_ttl_seconds = 86400
        self.services.config.cleanup.trash_file_cleanup_interval_seconds = 60
        self.services.monitor._last_stale_trash_cleanup_at = 0.0

        with patch("kvm_control.monitor.cleanup_stale_trash_files", return_value={"deleted": [], "failed": []}) as cleanup:
            self.services.monitor.sample_all_runs()

        cleanup.assert_called_once_with(self.services.config, self.services.registry, self.services.executor)

    def test_inspect_does_not_reset_stopped_ephemeral_cleanup_deadline(self) -> None:
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-inspect-cleanup",
                "template_id": "ubuntu-24.04",
                "vm_slot": "stale",
                "network_id": "dev",
                "autostart": False,
                "lock_resource_id": "namespace:repo-inspect-cleanup",
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]
        with self.services.registry.tx() as conn:
            conn.execute(
                """
                UPDATE vm_instances
                SET stopped_at = datetime(CURRENT_TIMESTAMP, '-25 hours'),
                    updated_at = CURRENT_TIMESTAMP
                WHERE vm_id = ?
                """,
                (vm_id,),
            )

        inspected = self.control.get(f"/v1/vms/{vm_id}")
        self.assertEqual(inspected.status_code, 200)
        after_inspect = self.services.registry.get_vm(vm_id)
        self.assertIsNotNone(after_inspect)
        self.assertLess(after_inspect["stopped_at"], after_inspect["updated_at"])

        result = cleanup_stale_stopped_ephemeral_vms(self.services.config, self.services.registry, self.services.executor)
        self.assertEqual([item["vm_id"] for item in result["cleaned"]], [vm_id])
        self.assertIsNone(self.services.registry.get_vm(vm_id))

    def test_startup_reconcile_sets_stopped_at_to_host_boot_for_crashed_active_vm(self) -> None:
        layer2 = self.root / "layer2" / "repo-boot-cleanup--ubuntu-24.04.qcow2"
        layer3 = self.root / "layer3" / "repo-boot-cleanup--node.qcow2"
        layer2.parent.mkdir(parents=True, exist_ok=True)
        layer3.parent.mkdir(parents=True, exist_ok=True)
        layer2.write_text("layer2", encoding="utf-8")
        layer3.write_text("layer3", encoding="utf-8")
        self.services.registry.upsert_vm(
            {
                "vm_id": "repo-boot-cleanup-node",
                "namespace": "repo-boot-cleanup",
                "vm_slot": "node",
                "template_id": "ubuntu-24.04",
                "network_id": "dev",
                "vcpus": 1,
                "memory_mb": 512,
                "estimated_layer3_growth_mb": None,
                "reserved_ip": "10.90.0.122",
                "reserved_mac": "52:54:00:00:30:01",
                "power_state": "running",
                "readiness_state": "ready",
                "status": "running",
                "layer2_path": str(layer2),
                "layer2_presence": "present",
                "layer3_path": str(layer3),
                "layer3_presence": "present",
                "pause_reason": None,
                "lock_resource_id": "namespace:repo-boot-cleanup",
                "source_image_id": None,
                "retention": "ephemeral",
                "agent_session_id": "cleanup-test",
            }
        )
        with self.services.registry.tx() as conn:
            conn.execute(
                """
                UPDATE vm_instances
                SET updated_at = '2026-08-01 08:00:00',
                    stopped_at = NULL
                WHERE vm_id = 'repo-boot-cleanup-node'
                """
            )

        test_case = self

        class FakeExecutor:
            def run(self, action: str, payload: dict) -> dict:
                test_case.assertEqual(action, "inspect-vm")
                return {
                    "result": "ok",
                    "vm_id": payload["vm_id"],
                    "domain_state": None,
                    "power_state": "stopped",
                    "current_ip": None,
                    "host_booted_at": "2026-08-02T06:30:00+00:00",
                    "inspected_at": "2026-08-02T12:00:00+00:00",
                }

        original_executor = self.services.executor
        self.services.executor = FakeExecutor()  # type: ignore[assignment]
        try:
            result = reconcile_registered_vm_runtime_states(self.services)
        finally:
            self.services.executor = original_executor

        self.assertEqual(result["failed"], [])
        vm = self.services.registry.get_vm("repo-boot-cleanup-node")
        self.assertIsNotNone(vm)
        self.assertEqual(vm["power_state"], "stopped")
        self.assertEqual(vm["stopped_at"], "2026-08-02 06:30:00")

    def test_guest_config_webroot_is_served_from_api_root(self) -> None:
        webroot = self.root / "webroot"
        webroot.mkdir(parents=True, exist_ok=True)
        (webroot / "repo-a@setup_2nd_stage.sh").write_text("#!/bin/sh\necho ok\n")

        response = self.control.get("/repo-a@setup_2nd_stage.sh")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "#!/bin/sh\necho ok\n")

    def test_webroot_artifact_api_uploads_lists_serves_and_deletes_files(self) -> None:
        content = b"#!/bin/sh\necho managed\n"

        uploaded = self.control.put("/v1/webroot-artifacts/repo-a/setup/autostart.sh", content=content)

        self.assertEqual(uploaded.status_code, 200)
        self.assertEqual(uploaded.json()["namespace"], "repo-a")
        self.assertEqual(uploaded.json()["path"], "setup/autostart.sh")
        self.assertEqual(uploaded.json()["public_path"], "/repo-a/setup/autostart.sh")
        self.assertEqual(uploaded.json()["size_bytes"], len(content))
        self.assertEqual(uploaded.json()["checksum_sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual((self.root / "webroot" / "repo-a" / "setup" / "autostart.sh").read_bytes(), content)

        served = self.control.get("/repo-a/setup/autostart.sh")
        self.assertEqual(served.status_code, 200)
        self.assertEqual(served.content, content)

        listed = self.control.get("/v1/webroot-artifacts/repo-a")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual([artifact["path"] for artifact in listed.json()], ["setup/autostart.sh"])

        deleted = self.control.delete("/v1/webroot-artifacts/repo-a/setup/autostart.sh")
        self.assertEqual(deleted.status_code, 200)
        self.assertTrue(deleted.json()["deleted"])
        self.assertFalse((self.root / "webroot" / "repo-a" / "setup" / "autostart.sh").exists())
        self.assertEqual(self.control.get("/repo-a/setup/autostart.sh").status_code, 404)

    def test_webroot_artifact_api_rejects_namespace_escape_paths(self) -> None:
        parent_escape = self.control.put("/v1/webroot-artifacts/repo-a/setup/%2E%2E/owned.sh", content=b"bad")
        self.assertEqual(parent_escape.status_code, 422)

        encoded_escape = self.control.put("/v1/webroot-artifacts/repo-a/%2E%2E/repo-b/owned.sh", content=b"bad")
        self.assertEqual(encoded_escape.status_code, 422)
        self.assertFalse((self.root / "webroot" / "repo-b" / "owned.sh").exists())

    def test_repository_token_can_only_manage_own_webroot_artifacts(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {"mode": "enforced", "admin_token": "admin-secret"}
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))

        admin_headers = {"Authorization": "Bearer admin-secret"}
        created_token = self.control.post(
            "/v1/admin/auth/tokens",
            json={"username": "git.repo-a"},
            headers=admin_headers,
        )
        self.assertEqual(created_token.status_code, 201)
        repo_headers = {"Authorization": f"Bearer {created_token.json()['token']}"}

        own = self.control.put("/v1/webroot-artifacts/git.repo-a/setup.sh", content=b"echo own\n", headers=repo_headers)
        self.assertEqual(own.status_code, 200)
        self.assertEqual(own.json()["public_path"], "/git.repo-a/setup.sh")

        other = self.control.put("/v1/webroot-artifacts/git.repo-b/setup.sh", content=b"echo other\n", headers=repo_headers)
        self.assertEqual(other.status_code, 403)

        admin_other = self.control.put("/v1/webroot-artifacts/git.repo-b/setup.sh", content=b"echo admin\n", headers=admin_headers)
        self.assertEqual(admin_other.status_code, 200)
        repo_list = self.control.get("/v1/webroot-artifacts/git.repo-a", headers=repo_headers)
        self.assertEqual([artifact["path"] for artifact in repo_list.json()], ["setup.sh"])

    def test_vm_create_requires_granted_lock(self) -> None:
        self.lock.post("/v1/locks/requests", json={"resource_id": "shared-db", "namespace": "repo-a"})
        self.lock.post("/v1/locks/requests", json={"resource_id": "shared-db", "namespace": "repo-b"})
        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-b",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node1",
                "lock_resource_id": "shared-db",
            },
        )
        self.assertEqual(create.status_code, 423)

    def test_dry_run_logs_expected_executor_commands(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root, dry_run=True)
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))

        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node1",
                "vcpus": 2,
                "memory_mb": 1024,
            },
        )
        self.assertEqual(create.status_code, 202)
        self.assertTrue(create.json()["dry_run"])
        self.assertTrue(any("qemu-img" in " ".join(command) for command in create.json()["planned_commands"]))
        vm_id = create.json()["vm_id"]
        stop = self.control.post(f"/v1/vms/{vm_id}/stop")
        self.assertEqual(stop.status_code, 202)
        self.assertTrue(stop.json()["dry_run"])
        self.assertTrue(any("virsh shutdown" in " ".join(command) for command in stop.json()["planned_commands"]))
        revert = self.control.post(f"/v1/vms/{vm_id}/revert")
        self.assertEqual(revert.status_code, 202)
        self.assertTrue(revert.json()["dry_run"])
        self.assertTrue(any(command[:2] == ["mv", str(self.root / "layer3" / "repo-a--node1.qcow2")] for command in revert.json()["planned_commands"]))
        delete = self.control.delete(f"/v1/vms/{vm_id}")
        self.assertEqual(delete.status_code, 202)
        self.assertTrue(delete.json()["dry_run"])
        self.assertEqual(delete.json()["action"], "delete")

        entries = [
            json.loads(line)
            for line in (self.root / "state" / "audit.log").read_text().splitlines()
            if line.strip()
        ]
        actions = [entry["action"] for entry in entries]
        self.assertIn("create-layer2", actions)

    def test_status_routes_are_public_when_api_auth_is_enabled(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        config = json.loads(self.config_path.read_text())
        config["auth"] = {"username": "test", "password": "secret"}
        self.config_path.write_text(json.dumps(config))
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))

        protected = self.control.get("/v1/vms")
        self.assertEqual(protected.status_code, 401)

        status_page = self.control.get("/status")
        self.assertEqual(status_page.status_code, 200)
        self.assertIn("kvm-control status", status_page.text)

        snapshot = self.control.get("/status/api/snapshot")
        self.assertEqual(snapshot.status_code, 200)
        self.assertIn("generated_at", snapshot.json())

    def test_status_snapshot_groups_vms_and_locks(self) -> None:
        create_a = self.control.post(
            "/v1/vms",
            json={"namespace": "repo-a", "template_id": "ubuntu-24.04", "vm_slot": "node1"},
        )
        self.assertEqual(create_a.status_code, 202)
        create_b = self.control.post(
            "/v1/vms",
            json={"namespace": "repo-b", "template_id": "ubuntu-24.04", "vm_slot": "node2", "autostart": False},
        )
        self.assertEqual(create_b.status_code, 202)
        self.lock.post("/v1/locks/requests", json={"resource_id": "lab-a", "namespace": "repo-a"})
        self.lock.post("/v1/locks/requests", json={"resource_id": "lab-a", "namespace": "repo-b"})

        snapshot = self.control.get("/status/api/snapshot")
        self.assertEqual(snapshot.status_code, 200)
        payload = snapshot.json()

        self.assertIn("repo-a", payload["vms"])
        self.assertIn("repo-b", payload["vms"])
        repo_a_vm = payload["vms"]["repo-a"][0]
        self.assertEqual(repo_a_vm["base_image"], "ubuntu-24.04-base.qcow2")
        self.assertEqual(repo_a_vm["layer2_presence"], "present")
        self.assertEqual(repo_a_vm["layer3_presence"], "present")

        namespaces = {item["namespace"]: item for item in payload["namespaces"]}
        self.assertEqual(namespaces["repo-a"]["granted_lock_count"], 1)
        self.assertEqual(namespaces["repo-b"]["queued_lock_count"], 1)
        self.assertTrue(any(lock["resource_id"] == "lab-a" and lock["queued_count"] == 1 for lock in payload["locks"]))

    def test_status_events_capture_vm_lock_run_and_failure_activity(self) -> None:
        self.lock.post("/v1/locks/requests", json={"resource_id": "shared-db", "namespace": "repo-a"})
        self.lock.post("/v1/locks/requests", json={"resource_id": "shared-db", "namespace": "repo-b"})
        release = self.lock.post("/v1/locks/requests/1/release", json={"released_by": "repo-a"})
        self.assertEqual(release.status_code, 200)

        create_vm = self.control.post(
            "/v1/vms",
            json={"namespace": "repo-a", "template_id": "ubuntu-24.04", "vm_slot": "node1"},
        )
        self.assertEqual(create_vm.status_code, 202)
        vm_id = create_vm.json()["vm_id"]

        create_run = self.control.post(
            "/v1/runs",
            json={
                "namespace": "repo-a",
                "workflow_name": "status-check",
                "workflow_version": "v1",
                "vm_ids": [vm_id],
                "declared_tests": ["boot"],
                "selected_tests": ["boot"],
            },
        )
        self.assertEqual(create_run.status_code, 201)
        run_id = create_run.json()["id"]
        self.control.post(f"/v1/runs/{run_id}/stages/boot/start", json={"name": "boot", "order_index": 1})
        self.control.post(f"/v1/runs/{run_id}/stages/boot/finish", json={"status": "completed"})
        self.control.post(f"/v1/runs/{run_id}/events", json={"event_type": "warning", "message": "boot warning"})

        failing_root = Path(self.tmp.name) / "missing-base-status"
        failing_root.mkdir(parents=True, exist_ok=True)
        failing_config = write_config(failing_root)
        (failing_root / "base" / "ubuntu-24.04-base.qcow2").unlink()
        failing_services = build_services(str(failing_config))
        failing_control = TestClient(create_control_app(failing_services))
        failed_create = failing_control.post(
            "/v1/vms",
            json={"namespace": "repo-x", "template_id": "ubuntu-24.04", "vm_slot": "broken"},
        )
        self.assertEqual(failed_create.status_code, 503)

        events = self.services.registry.list_status_events(limit=200)
        self.assertTrue(any(event["kind"] == "ip_reservation" and event["details"]["reserved_ip"] == create_vm.json()["reserved_ip"] for event in events))
        self.assertTrue(any(event["kind"] == "lock" and event["status"] == "released" for event in events))
        self.assertTrue(any(event["kind"] == "lock" and event["status"] == "granted" and event["namespace"] == "repo-b" for event in events))
        self.assertTrue(any(event["kind"] == "run_stage" and event["stage_id"] == "boot" and event["status"] == "completed" for event in events))
        self.assertTrue(any(event["kind"] == "run_event" and event["summary"] == "boot warning" for event in events))

        failing_events = failing_services.registry.list_status_events(limit=50)
        self.assertTrue(any(event["kind"] == "executor" and event["status"] == "failed" for event in failing_events))

    def test_status_websocket_replays_recent_events(self) -> None:
        self.lock.post("/v1/locks/requests", json={"resource_id": "lab-a", "namespace": "repo-a"})

        with self.control.websocket_connect("/status/ws") as websocket:
            replay = websocket.receive_json()
            self.assertIn(replay["kind"], {"lock", "api_request", "executor"})

    def test_status_websocket_receives_live_updates(self) -> None:
        with self.control.websocket_connect("/status/ws") as websocket:
            create_vm = self.control.post(
                "/v1/vms",
                json={"namespace": "repo-a", "template_id": "ubuntu-24.04", "vm_slot": "node-ws"},
            )
            self.assertEqual(create_vm.status_code, 202)
            received = []
            deadline = time.time() + 5.0
            while time.time() < deadline:
                try:
                    received.append(websocket.receive_json(timeout=max(0.1, deadline - time.time())))
                except queue.Empty:
                    break
                if any(event["kind"] in {"operation", "executor", "ip_reservation", "api_request"} for event in received):
                    break
            self.assertTrue(
                any(event["kind"] in {"operation", "executor", "ip_reservation", "api_request"} for event in received),
                received,
            )


class StatusBusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root)
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))

    def tearDown(self) -> None:
        self.services.monitor.stop()
        self.tmp.cleanup()

    def test_status_bus_drops_old_messages_for_slow_subscribers(self) -> None:
        bus = StatusEventBus(replay_limit=4, subscriber_queue_size=1)
        subscription = bus.subscribe()
        bus.publish({"id": 1, "created_at": "2026-05-02T00:00:00Z", "kind": "test", "summary": "first"})
        bus.publish({"id": 2, "created_at": "2026-05-02T00:00:01Z", "kind": "test", "summary": "second"})
        bus.publish({"id": 3, "created_at": "2026-05-02T00:00:02Z", "kind": "test", "summary": "third"})

        event = subscription.queue.get(timeout=1.0)
        self.assertEqual(event["id"], 3)

    def test_dry_run_promote_layer3_logs_convert_command(self) -> None:
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = write_config(self.root, dry_run=True)
        self.services = build_services(str(self.config_path))
        self.control = TestClient(create_control_app(self.services))
        self.lock = TestClient(create_lock_app(self.services))

        create = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "golden-seed",
            },
        )
        self.assertEqual(create.status_code, 202)
        vm_id = create.json()["vm_id"]
        stop = self.control.post(f"/v1/vms/{vm_id}/stop")
        self.assertEqual(stop.status_code, 202)
        promote = self.control.post(f"/v1/vms/{vm_id}/promote-layer2")
        self.assertEqual(promote.status_code, 202)
        self.assertTrue(promote.json()["dry_run"])
        self.assertTrue(any("qemu-img convert" in " ".join(command) for command in promote.json()["planned_commands"]))

        entries = [
            json.loads(line)
            for line in (self.root / "state" / "audit.log").read_text().splitlines()
            if line.strip()
        ]
        promote_entries = [entry for entry in entries if entry["action"] == "convert-layer3-to-layer2"]
        self.assertEqual(len(promote_entries), 1)
        flattened = [" ".join(command) for command in promote_entries[0]["commands"]]
        self.assertTrue(any(command.startswith("qemu-img convert") for command in flattened))

    def test_run_tracking_summary_and_learning_exclusion(self) -> None:
        create_vm = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node1",
                "vcpus": 2,
                "memory_mb": 1024,
            },
        )
        self.assertEqual(create_vm.status_code, 202)
        vm_id = create_vm.json()["vm_id"]

        create_run = self.control.post(
            "/v1/runs",
            json={
                "namespace": "repo-a",
                "workflow_name": "cluster-smoke",
                "workflow_version": "v1",
                "git_ref": "refs/heads/main",
                "vm_ids": [vm_id],
                "declared_tests": ["provision"],
                "selected_tests": ["provision"],
            },
        )
        self.assertEqual(create_run.status_code, 201)
        run_id = create_run.json()["id"]

        estimate = self.control.post(
            f"/v1/runs/{run_id}/estimate",
            json={
                "estimated_disk_mb": 512,
                "estimated_ram_mb": 1024,
                "estimated_duration_s": 180,
                "source": "history",
                "confidence": 0.7,
            },
        )
        self.assertEqual(estimate.status_code, 200)

        stage_start = self.control.post(
            f"/v1/runs/{run_id}/stages/provision/start",
            json={"name": "provision", "order_index": 10},
        )
        self.assertEqual(stage_start.status_code, 200)
        time.sleep(1.1)
        stage_finish = self.control.post(
            f"/v1/runs/{run_id}/stages/provision/finish",
            json={"status": "completed", "notes": "base install cache reused"},
        )
        self.assertEqual(stage_finish.status_code, 200)
        self.assertGreaterEqual(stage_finish.json()["duration_s"], 1.0)

        event = self.control.post(
            f"/v1/runs/{run_id}/events",
            json={
                "event_type": "disk_full",
                "message": "layer3 pool filled during exhaustive package install",
                "stage_id": "provision",
                "details": {"device": "layer3", "recovered": False},
            },
        )
        self.assertEqual(event.status_code, 201)

        usage = self.control.get(f"/v1/runs/{run_id}/usage")
        self.assertEqual(usage.status_code, 200)
        self.assertGreaterEqual(usage.json()["current_ram_mb"], 1024)
        self.assertGreaterEqual(usage.json()["sample_count"], 1)

        finish = self.control.post(
            f"/v1/runs/{run_id}/finish",
            json={"status": "failed", "notes": "captured disk pressure outlier"},
        )
        self.assertEqual(finish.status_code, 200)
        self.assertEqual(finish.json()["status"], "failed")

        ignore = self.control.post(
            f"/v1/runs/{run_id}/ignore-for-learning",
            json={"reason": "bug-triggered exhaustive package loop", "bug_reference": "BUG-123"},
        )
        self.assertEqual(ignore.status_code, 200)

        summary = self.control.get(f"/v1/runs/{run_id}/summary")
        self.assertEqual(summary.status_code, 200)
        payload = summary.json()
        self.assertEqual(payload["run"]["workflow_name"], "cluster-smoke")
        self.assertEqual(payload["estimate"]["estimated_duration_s"], 180)
        self.assertEqual(payload["events"][0]["event_type"], "disk_full")
        self.assertEqual(payload["learning_exclusion"]["bug_reference"], "BUG-123")
        self.assertEqual(payload["stages"][0]["stage_id"], "provision")
        self.assertEqual(payload["run"]["declared_tests"], ["provision"])
        self.assertEqual(payload["run"]["selected_tests"], ["provision"])

    def test_monitor_detects_host_side_disk_full_once_per_pressure_period(self) -> None:
        create_vm = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node1",
            },
        )
        self.assertEqual(create_vm.status_code, 202)
        vm_id = create_vm.json()["vm_id"]

        create_run = self.control.post(
            "/v1/runs",
            json={
                "namespace": "repo-a",
                "workflow_name": "cluster-smoke",
                "workflow_version": "v1",
                "vm_ids": [vm_id],
                "declared_tests": ["cluster-smoke"],
                "selected_tests": ["cluster-smoke"],
            },
        )
        self.assertEqual(create_run.status_code, 201)
        run_id = create_run.json()["id"]

        with patch("kvm_control.monitor.shutil.disk_usage") as disk_usage:
            disk_usage.return_value = shutil._ntuple_diskusage(total=1024, used=1000, free=24)
            self.services.monitor.sample_all_runs()
            self.services.monitor.sample_all_runs()

        vm = self.control.get(f"/v1/vms/{vm_id}")
        self.assertEqual(vm.status_code, 200)
        self.assertEqual(vm.json()["power_state"], "paused")
        self.assertEqual(vm.json()["pause_reason"], "disk_full")

        events = self.control.get(f"/v1/runs/{run_id}/events")
        self.assertEqual(events.status_code, 200)
        disk_full_events = [event for event in events.json() if event["event_type"] == "disk_full"]
        self.assertEqual(len(disk_full_events), 2)
        self.assertTrue(all(event["details"]["source"] == "host_monitor" for event in disk_full_events))
        pause_events = [event for event in events.json() if event["message"].startswith(f"vm {vm_id} paused")]
        self.assertEqual(len(pause_events), 1)

        with patch("kvm_control.monitor.shutil.disk_usage") as disk_usage:
            disk_usage.return_value = shutil._ntuple_diskusage(total=1024**3, used=1024, free=1024**3 - 1024)
            self.services.monitor.sample_all_runs()

        vm = self.control.get(f"/v1/vms/{vm_id}")
        self.assertEqual(vm.status_code, 200)
        self.assertEqual(vm.json()["power_state"], "running")
        self.assertIsNone(vm.json()["pause_reason"])

        with patch("kvm_control.monitor.shutil.disk_usage") as disk_usage:
            disk_usage.return_value = shutil._ntuple_diskusage(total=1024, used=1000, free=24)
            self.services.monitor.sample_all_runs()

        events = self.control.get(f"/v1/runs/{run_id}/events")
        disk_full_events = [event for event in events.json() if event["event_type"] == "disk_full"]
        self.assertEqual(len(disk_full_events), 4)
        resume_events = [event for event in events.json() if event["message"].startswith(f"vm {vm_id} resumed")]
        self.assertEqual(len(resume_events), 1)

    def test_disk_full_pause_time_is_subtracted_from_stage_and_run_duration(self) -> None:
        create_vm = self.control.post(
            "/v1/vms",
            json={
                "namespace": "repo-a",
                "template_id": "ubuntu-24.04",
                "vm_slot": "node1",
            },
        )
        self.assertEqual(create_vm.status_code, 202)
        vm_id = create_vm.json()["vm_id"]

        create_run = self.control.post(
            "/v1/runs",
            json={
                "namespace": "repo-a",
                "workflow_name": "timing-check",
                "workflow_version": "v1",
                "vm_ids": [vm_id],
                "declared_tests": ["provision"],
                "selected_tests": ["provision"],
            },
        )
        self.assertEqual(create_run.status_code, 201)
        run_id = create_run.json()["id"]

        stage_start = self.control.post(
            f"/v1/runs/{run_id}/stages/provision/start",
            json={"name": "provision", "order_index": 1},
        )
        self.assertEqual(stage_start.status_code, 200)
        time.sleep(0.6)
        self.services.registry.start_run_pause(run_id, "disk_full", "provision")
        time.sleep(1.1)
        self.services.registry.finish_run_pause(run_id, "disk_full")
        time.sleep(0.6)

        stage_finish = self.control.post(
            f"/v1/runs/{run_id}/stages/provision/finish",
            json={"status": "completed"},
        )
        self.assertEqual(stage_finish.status_code, 200)
        self.assertGreater(stage_finish.json()["duration_s"], stage_finish.json()["effective_duration_s"])
        self.assertGreaterEqual(stage_finish.json()["paused_duration_s"], 1.0)

        finish = self.control.post(f"/v1/runs/{run_id}/finish", json={"status": "completed"})
        self.assertEqual(finish.status_code, 200)
        self.assertGreater(finish.json()["duration_s"], finish.json()["effective_duration_s"])
        self.assertGreaterEqual(finish.json()["paused_duration_s"], 1.0)

    def test_declared_tests_prune_removed_stage_history(self) -> None:
        first_run = self.control.post(
            "/v1/runs",
            json={
                "namespace": "repo-a",
                "workflow_name": "catalog-check",
                "workflow_version": "v1",
                "declared_tests": ["keep", "drop"],
                "selected_tests": ["keep", "drop"],
            },
        )
        self.assertEqual(first_run.status_code, 201)
        first_id = first_run.json()["id"]
        self.control.post(f"/v1/runs/{first_id}/stages/keep/start", json={"name": "keep", "order_index": 1})
        self.control.post(f"/v1/runs/{first_id}/stages/keep/finish", json={"status": "completed"})
        self.control.post(f"/v1/runs/{first_id}/stages/drop/start", json={"name": "drop", "order_index": 2})
        self.control.post(f"/v1/runs/{first_id}/stages/drop/finish", json={"status": "completed"})
        self.control.post(f"/v1/runs/{first_id}/finish", json={"status": "completed"})

        second_run = self.control.post(
            "/v1/runs",
            json={
                "namespace": "repo-a",
                "workflow_name": "catalog-check",
                "workflow_version": "v1",
                "declared_tests": ["keep"],
                "selected_tests": ["keep"],
            },
        )
        self.assertEqual(second_run.status_code, 201)

        first_summary = self.control.get(f"/v1/runs/{first_id}/summary")
        self.assertEqual(first_summary.status_code, 200)
        stage_ids = [stage["stage_id"] for stage in first_summary.json()["stages"]]
        self.assertEqual(stage_ids, ["keep"])


if __name__ == "__main__":
    unittest.main()
