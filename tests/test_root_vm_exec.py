from __future__ import annotations

import json
from collections import namedtuple
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

from kvm_control.config import load_config
from kvm_control.root_vm_exec import (
    _append_guest_ssh_public_key,
    _ensure_virt_customize_scratch_space,
    _guest_bootstrap_file_contents,
    _layer2_bootstrap_script,
    _virt_customize_scratch_paths,
    _write_debootstrap_base_config,
    handle_request,
)


def write_config(root: Path) -> Path:
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
            "cidr": "10.90.0.0/20",
            "gateway": "10.90.0.1",
            "dhcp_cidr": "10.91.0.0/24",
            "mac_prefix": "52:54:00",
        },
        "guest_bootstrap": {
            "apt_http_proxy": "http://192.0.2.25:3142/",
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
        "executor_bin": "python3 -m kvm_control.root_vm_exec",
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
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


class RootVmExecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = load_config(write_config(self.root))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _payload(self) -> dict[str, object]:
        layer2 = self.root / "layer2" / "repo-a--ubuntu-24.04.qcow2"
        layer3 = self.root / "layer3" / "repo-a--node1.qcow2"
        layer2.parent.mkdir(parents=True, exist_ok=True)
        layer3.parent.mkdir(parents=True, exist_ok=True)
        layer2.write_text("{}", encoding="utf-8")
        layer3.write_text("{}", encoding="utf-8")
        return {
            "vm_id": "repo-a--node1",
            "namespace": "repo-a",
            "network_id": "dev",
            "network_bridge": "dev",
            "vcpus": 2,
            "memory_mb": 1024,
            "reserved_ip": "10.90.0.10",
            "reserved_mac": "52:54:00:00:00:10",
            "layer2_path": str(layer2),
            "layer3_path": str(layer3),
            "template_architecture": "x86_64",
            "template_boot_mode": "disk",
        }

    def test_start_vm_redefines_existing_stopped_domain(self) -> None:
        payload = self._payload()
        runtime_xml = self.config.storage.runtime_dir / "repo-a--node1.xml"
        runtime_json = self.config.storage.runtime_dir / "repo-a--node1.json"
        guest_bootstrap = self.config.storage.webroot_dir / "setup_2nd_stage.52:54:00:00:00:10.sh"

        with (
            patch("kvm_control.root_vm_exec._libvirt_available", return_value=True),
            patch("kvm_control.root_vm_exec._domain_exists", return_value=True),
            patch("kvm_control.root_vm_exec._domain_state", side_effect=["shut off", "shut off"]),
            patch("kvm_control.root_vm_exec._wait_for_domain_state", return_value="running"),
            patch("kvm_control.root_vm_exec._require_kvm_device"),
            patch("kvm_control.root_vm_exec._virsh") as virsh,
        ):
            result = handle_request(self.config, "start-vm", payload)

        self.assertEqual(result["result"], "ok")
        self.assertTrue(runtime_xml.exists())
        self.assertTrue(runtime_json.exists())
        self.assertTrue(guest_bootstrap.exists())
        virsh.assert_has_calls(
            [
                call(["undefine", "repo-a--node1"], check=False),
                call(["define", str(runtime_xml)]),
                call(["start", "repo-a--node1"]),
            ]
        )
        runtime_data = json.loads(runtime_json.read_text(encoding="utf-8"))
        self.assertEqual(runtime_data["power_state"], "running")
        self.assertEqual(runtime_data["guest_bootstrap_script"], str(guest_bootstrap))
        self.assertEqual(runtime_data["guest_bootstrap"]["mode"], "test-stub")

        guest_bootstrap_text = guest_bootstrap.read_text(encoding="utf-8")
        self.assertIn("KVM_CONTROL_IPV4_ADDRESS=10.90.0.10", guest_bootstrap_text)
        self.assertIn("KVM_CONTROL_IPV4_GATEWAY=10.90.0.1", guest_bootstrap_text)
        self.assertIn("KVM_CONTROL_IPV4_PREFIX=20", guest_bootstrap_text)
        self.assertIn("Acquire::http::Proxy", guest_bootstrap_text)
        self.assertIn("http://192.0.2.25:3142/", guest_bootstrap_text)
        self.assertIn("/etc/cron.d/kvm-control", guest_bootstrap_text)
        self.assertIn("@reboot root /usr/local/sbin/kvm-control-configure-network", guest_bootstrap_text)
        self.assertIn("@reboot root /usr/local/sbin/kvm-control-grow-rootfs", guest_bootstrap_text)
        self.assertIn("/etc/init.d/kvm-control", guest_bootstrap_text)
        self.assertIn("/etc/rcS.d", guest_bootstrap_text)
        self.assertIn("mkdir -p /etc/network/interfaces.d", guest_bootstrap_text)
        self.assertIn('[ "$root_fstype" = "ext4" ] || exit 0', guest_bootstrap_text)
        self.assertIn('resize2fs "$root_source"', guest_bootstrap_text)
        self.assertNotIn("xfs", guest_bootstrap_text.lower())

        layer3_files = result["guest_bootstrap"]
        self.assertEqual(layer3_files["mode"], "test-stub")

    def test_append_guest_ssh_public_key_writes_root_authorized_keys(self) -> None:
        guest_root = self.root / "guest"
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey pytest-agent"

        added = _append_guest_ssh_public_key(guest_root, key)
        added_again = _append_guest_ssh_public_key(guest_root, key)

        authorized_keys = guest_root / "root/.ssh/authorized_keys"
        self.assertTrue(added)
        self.assertTrue(added_again)
        self.assertEqual(authorized_keys.read_text(encoding="utf-8").splitlines(), [key])
        self.assertEqual(oct((guest_root / "root/.ssh").stat().st_mode & 0o777), "0o700")
        self.assertEqual(oct(authorized_keys.stat().st_mode & 0o777), "0o600")

    def test_guest_bootstrap_files_grow_direct_ext4_root(self) -> None:
        payload = {
            "vm_id": "repo-a--node1",
            "namespace": "repo-a",
            "network_id": "dev",
            "reserved_mac": "52:54:00:00:00:10",
            "reserved_ip": "10.90.0.10",
        }

        files = _guest_bootstrap_file_contents(self.config, payload)

        grow_script = files["/usr/local/sbin/kvm-control-grow-rootfs"]
        self.assertIn('resize2fs "$root_source"', grow_script)
        self.assertIn('if [ -z "$disk_name" ] && [ -z "$part_no" ]; then', grow_script)
        self.assertIn("/etc/init.d/kvm-control", files)
        self.assertIn("/etc/rcS.d/S02kvm-control", files)
        self.assertIn("/usr/local/sbin/kvm-control-configure-network", files["/etc/init.d/kvm-control"])
        self.assertIn("mkdir -p /etc/network/interfaces.d", files["/usr/local/sbin/kvm-control-configure-network"])

    def test_virt_customize_scratch_space_rejects_low_free_space(self) -> None:
        usage = namedtuple("usage", "total used free")
        scratch = self.root / "scratch"

        with (
            patch("kvm_control.root_vm_exec._virt_customize_scratch_paths", return_value=[scratch]),
            patch("kvm_control.root_vm_exec.shutil.disk_usage", return_value=usage(10 * 1024**3, 9 * 1024**3, 512 * 1024**2)),
        ):
            with self.assertRaisesRegex(RuntimeError, "not enough free space for virt-customize scratch"):
                _ensure_virt_customize_scratch_space()

    def test_virt_customize_scratch_paths_follow_libguestfs_environment(self) -> None:
        scratch = self.root / "libguestfs"

        with patch.dict(
            "os.environ",
            {
                "LIBGUESTFS_CACHEDIR": str(scratch),
                "LIBGUESTFS_TMPDIR": str(scratch),
                "TMPDIR": "/var/tmp",
            },
        ):
            self.assertEqual(_virt_customize_scratch_paths(), [scratch.resolve()])

    def test_restart_vm_refreshes_guest_bootstrap_script(self) -> None:
        payload = self._payload()
        runtime_json = self.config.storage.runtime_dir / "repo-a--node1.json"
        runtime_json.parent.mkdir(parents=True, exist_ok=True)
        runtime_json.write_text(json.dumps({"power_state": "running"}), encoding="utf-8")
        guest_bootstrap = self.config.storage.webroot_dir / "setup_2nd_stage.52:54:00:00:00:10.sh"

        with (
            patch("kvm_control.root_vm_exec._libvirt_available", return_value=True),
            patch("kvm_control.root_vm_exec._domain_exists", return_value=True),
            patch("kvm_control.root_vm_exec._wait_for_domain_state", return_value="running"),
            patch("kvm_control.root_vm_exec._virsh") as virsh,
        ):
            result = handle_request(self.config, "restart-vm", payload)

        self.assertEqual(result["result"], "ok")
        self.assertEqual(result["guest_bootstrap_script"], str(guest_bootstrap))
        self.assertTrue(guest_bootstrap.exists())
        virsh.assert_called_once_with(["reboot", "repo-a--node1"])
        runtime_data = json.loads(runtime_json.read_text(encoding="utf-8"))
        self.assertEqual(runtime_data["guest_bootstrap_script"], str(guest_bootstrap))

    def test_publish_fetch_retire_and_delete_image(self) -> None:
        source_layer2 = self.root / "layer2" / "repo-a--seed--promoted.qcow2"
        source_layer2.parent.mkdir(parents=True, exist_ok=True)
        source_layer2.write_text("seed-image", encoding="utf-8")
        payload = {
            "vm_id": "basic-vm-handling.v1.seed",
            "image_id": "basic-vm-handling.v1.seed",
            "layer2_path": str(source_layer2),
            "layer3_path": str(self.root / "layer3" / "unused.qcow2"),
            "local_path": str(source_layer2),
            "remote_path": str(self.root / "image-remote" / "basic-vm-handling.v1.seed.qcow2"),
            "source_layer2_path": str(source_layer2),
            "metadata": {"test_id": "basic-vm-handling.v1"},
        }

        publish = handle_request(self.config, "publish-image", payload)
        remote_path = Path(publish["remote_path"])
        self.assertTrue(remote_path.exists())
        self.assertTrue(remote_path.with_suffix(remote_path.suffix + ".meta").exists())

        retire = handle_request(self.config, "retire-image", payload)
        self.assertIn("trashed_path", retire)
        self.assertFalse(source_layer2.exists())

        fetch = handle_request(self.config, "fetch-image", payload)
        self.assertTrue(source_layer2.exists())
        self.assertEqual(fetch["checksum_sha256"], publish["checksum_sha256"])

        delete = handle_request(self.config, "delete-image", payload)
        self.assertTrue(delete["deleted_remote"])
        self.assertFalse(source_layer2.exists())
        self.assertFalse(remote_path.exists())

    def test_build_ubuntu_base_image_dry_run_writes_artifacts(self) -> None:
        self.config.dry_run = True
        recipe = next(recipe for recipe in self.config.image_factory.recipes if recipe.id == "ubuntu-24.04-noble-amd64")
        image_path = self.config.storage.base_dir / "ubuntu-24.04-noble-amd64.raw"
        kernel_dir = self.config.storage.base_dir.parent / "vm-kernels" / "noble"
        payload = {
            "operation_id": 1,
            "vm_id": recipe.id,
            "image_id": recipe.catalog_image_id,
            "recipe": recipe.model_dump(mode="json") if hasattr(recipe, "model_dump") else json.loads(recipe.json()),
            "image_path": str(image_path),
            "metadata_path": str(image_path.with_suffix(image_path.suffix + ".meta")),
            "kernel_dir": str(kernel_dir),
            "authorized_keys_path": str(self.root / "missing-authorized-keys"),
            "image_size_mb": 1024,
            "force": False,
            "publish": True,
        }

        result = handle_request(self.config, "build-base-image", payload)

        self.assertEqual(result["result"], "ok")
        self.assertTrue(result["dry_run"])
        self.assertTrue(image_path.exists())
        self.assertTrue(image_path.with_suffix(image_path.suffix + ".meta").exists())
        self.assertTrue((kernel_dir / "vmlinuz").exists())
        self.assertTrue((kernel_dir / "initrd.img").exists())
        self.assertEqual(result["image_path"], str(image_path))
        self.assertEqual(result["kernel_path"], str(kernel_dir / "vmlinuz"))
        self.assertTrue(any("debootstrap" in command for command in result["planned_commands"]))

    def test_debootstrap_base_config_does_not_inherit_guest_proxy_when_recipe_cache_disabled(self) -> None:
        recipe = next(recipe for recipe in self.config.image_factory.recipes if recipe.id == "ubuntu-24.04-noble-amd64")
        guest_root = self.root / "guest-root"
        payload = {"recipe": recipe.model_dump(mode="json") if hasattr(recipe, "model_dump") else json.loads(recipe.json())}

        _write_debootstrap_base_config(guest_root, self.config, payload)

        self.assertTrue((guest_root / "etc/apt/apt.conf.d/80-kvm-control-retries.conf").exists())
        self.assertFalse((guest_root / "etc/apt/apt.conf.d/80-proxy.conf").exists())

    def test_debootstrap_base_config_uses_recipe_apt_cache_proxy_when_enabled(self) -> None:
        recipe = next(recipe for recipe in self.config.image_factory.recipes if recipe.id == "ubuntu-24.04-noble-amd64")
        recipe_data = recipe.model_dump(mode="json") if hasattr(recipe, "model_dump") else json.loads(recipe.json())
        recipe_data["apt_cache"] = {"enabled": True, "proxy_url": "http://cache.example:3142/", "required": True}
        guest_root = self.root / "guest-root-with-cache"

        _write_debootstrap_base_config(guest_root, self.config, {"recipe": recipe_data})

        self.assertEqual(
            (guest_root / "etc/apt/apt.conf.d/80-proxy.conf").read_text(encoding="utf-8"),
            'Acquire::http::Proxy "http://cache.example:3142/";\n',
        )

    def test_build_devuan_excalibur_base_image_dry_run_writes_artifacts(self) -> None:
        self.config.dry_run = True
        recipe = next(recipe for recipe in self.config.image_factory.recipes if recipe.id == "devuan-6-excalibur-amd64")
        image_path = self.config.storage.base_dir / "devuan-6-excalibur-amd64.raw"
        kernel_dir = self.config.storage.base_dir.parent / "vm-kernels" / "excalibur"
        payload = {
            "operation_id": 1,
            "vm_id": recipe.id,
            "image_id": recipe.catalog_image_id,
            "recipe": recipe.model_dump(mode="json") if hasattr(recipe, "model_dump") else json.loads(recipe.json()),
            "image_path": str(image_path),
            "metadata_path": str(image_path.with_suffix(image_path.suffix + ".meta")),
            "kernel_dir": str(kernel_dir),
            "authorized_keys_path": str(self.root / "missing-authorized-keys"),
            "image_size_mb": 1024,
            "force": False,
            "publish": True,
        }

        result = handle_request(self.config, "build-base-image", payload)

        self.assertEqual(result["result"], "ok")
        self.assertTrue(result["dry_run"])
        self.assertTrue(image_path.exists())
        self.assertTrue((kernel_dir / "vmlinuz").exists())
        self.assertTrue(any("linux-image-amd64" in command for command in result["planned_commands"]))

    def test_build_layer2_image_dry_run_writes_artifacts(self) -> None:
        self.config.dry_run = True
        recipe = next(recipe for recipe in self.config.image_factory.layer2_recipes if recipe.id == "agent-sandbox-tools-devuan-6-excalibur-amd64")
        base_image = self.config.storage.base_dir / "devuan-6-excalibur-amd64.raw"
        base_image.write_text("base", encoding="utf-8")
        layer2_path = self.config.storage.layer2_dir / f"{recipe.catalog_image_id}.qcow2"
        payload = {
            "operation_id": 1,
            "vm_id": recipe.id,
            "image_id": recipe.catalog_image_id,
            "recipe": recipe.model_dump(mode="json") if hasattr(recipe, "model_dump") else json.loads(recipe.json()),
            "base_image_path": str(base_image),
            "base_image_format": "raw",
            "layer2_path": str(layer2_path),
            "force": False,
            "publish": True,
        }

        result = handle_request(self.config, "build-layer2-image", payload)

        self.assertEqual(result["result"], "ok")
        self.assertTrue(result["dry_run"])
        self.assertTrue(layer2_path.exists())
        self.assertTrue(layer2_path.with_suffix(layer2_path.suffix + ".meta").exists())
        self.assertEqual(result["layer2_path"], str(layer2_path))
        self.assertTrue(any("ripgrep" in " ".join(command) for command in result["planned_commands"]))
        self.assertTrue(any("python3-pytest" in " ".join(command) for command in result["planned_commands"]))

        second = handle_request(self.config, "build-layer2-image", payload)
        self.assertTrue(second["idempotent"])
        self.assertEqual(second["planned_commands"], [])

    def test_layer2_bootstrap_script_uses_configured_proxy_and_bridge_dns_fallback(self) -> None:
        recipe = next(recipe for recipe in self.config.image_factory.layer2_recipes if recipe.id == "agent-sandbox-tools-devuan-6-excalibur-amd64")
        recipe_data = recipe.model_dump(mode="json") if hasattr(recipe, "model_dump") else json.loads(recipe.json())

        script = _layer2_bootstrap_script(self.config, recipe_data)

        self.assertIn("grep -qs '^nameserver ' /etc/resolv.conf", script)
        self.assertIn("nameserver 10.90.0.1", script)
        self.assertNotIn("10.0.0.53", script)
        self.assertIn('Acquire::http::Proxy "http://192.0.2.25:3142/"', script)
        self.assertIn("/usr/local/sbin/kvm-control-grow-rootfs", script)
        self.assertIn("apt-get update || { rm -f /etc/apt/apt.conf.d/80-proxy.conf; apt-get update; }", script)

    def test_layer2_bootstrap_script_prefers_recipe_apt_cache_proxy(self) -> None:
        recipe = next(recipe for recipe in self.config.image_factory.layer2_recipes if recipe.id == "agent-sandbox-tools-devuan-6-excalibur-amd64")
        recipe_data = recipe.model_dump(mode="json") if hasattr(recipe, "model_dump") else json.loads(recipe.json())
        recipe_data["apt_cache"] = {"enabled": True, "proxy_url": "http://cache.example:3142/", "required": True}

        script = _layer2_bootstrap_script(self.config, recipe_data)

        self.assertIn('Acquire::http::Proxy "http://cache.example:3142/"', script)
        self.assertIn("apt-get update\n", script)
        self.assertNotIn("apt-get update ||", script)

    def test_publish_fetch_and_delete_image_over_rsync_remote(self) -> None:
        source_layer2 = self.root / "layer2" / "repo-a--seed--promoted.qcow2"
        source_layer2.parent.mkdir(parents=True, exist_ok=True)
        source_layer2.write_text("seed-image", encoding="utf-8")
        payload = {
            "vm_id": "basic-vm-handling.v1.seed",
            "image_id": "basic-vm-handling.v1.seed",
            "layer2_path": str(source_layer2),
            "layer3_path": str(self.root / "layer3" / "unused.qcow2"),
            "local_path": str(source_layer2),
            "remote_path": "rsync://192.0.2.41/data-storage/kvm-control-images/basic-vm-handling.v1.seed/image.qcow2",
            "remote_backend": "rsync",
            "remote_timeout_s": 30,
            "source_layer2_path": str(source_layer2),
            "metadata": {"test_id": "basic-vm-handling.v1"},
        }

        def fake_rsync(argv: list[str], timeout_s: int, check: bool = True):  # type: ignore[override]
            if argv[:2] == ["-aS", "--mkpath"] and argv[-1] == payload["remote_path"]:
                return None
            if argv[:2] == ["-aS", "--mkpath"] and argv[-1] == f"{payload['remote_path']}.meta":
                return None
            if argv[:2] == ["--list-only", payload["remote_path"]]:
                return type("R", (), {"returncode": 0})()
            if argv[:2] == ["--list-only", f"{payload['remote_path']}.meta"]:
                return type("R", (), {"returncode": 0})()
            if argv[:2] == ["-aS", payload["remote_path"]]:
                local_copy = Path(payload["local_path"])
                local_copy.write_text("seed-image", encoding="utf-8")
                return None
            if argv[:2] == ["-aS", f"{payload['remote_path']}.meta"]:
                meta_path = Path(f"{payload['local_path']}.meta")
                meta_path.write_text("test_id: basic-vm-handling.v1\n", encoding="utf-8")
                return None
            if argv[:2] == ["-a", "--delete"]:
                return None
            raise AssertionError(f"unexpected rsync argv: {argv}")

        with patch("kvm_control.root_vm_exec._rsync_run", side_effect=fake_rsync):
            publish = handle_request(self.config, "publish-image", payload)
            self.assertTrue(publish["remote_verified"])
            retire = handle_request(self.config, "retire-image", payload)
            self.assertIn("trashed_path", retire)
            fetch = handle_request(self.config, "fetch-image", payload)
            self.assertTrue(fetch["remote_verified"])
            self.assertTrue(source_layer2.exists())

        def fake_rsync_delete(argv: list[str], timeout_s: int, check: bool = True):  # type: ignore[override]
            if argv[:2] == ["-a", "--delete"]:
                return None
            if argv[:2] == ["--list-only", payload["remote_path"]]:
                return type("R", (), {"returncode": 1})()
            if argv[:2] == ["--list-only", f"{payload['remote_path']}.meta"]:
                return type("R", (), {"returncode": 1})()
            raise AssertionError(f"unexpected rsync argv during delete: {argv}")

        with patch("kvm_control.root_vm_exec._rsync_run", side_effect=fake_rsync_delete):
            delete = handle_request(self.config, "delete-image", payload)
            self.assertTrue(delete["deleted_remote"])
            self.assertTrue(delete["remote_verified"])

    def test_sync_firewall_egress_writes_state_when_ipset_unavailable(self) -> None:
        payload = {
            "vm_id": "firewall-egress",
            "image_id": "firewall-egress",
            "layer2_path": str(self.root / "layer2" / "unused.qcow2"),
            "layer3_path": str(self.root / "layer3" / "unused.qcow2"),
            "entries": ["0.0.0.0/1", "128.0.0.0/1", "198.51.100.42"],
            "ipset_name": "kvmEgressAnyV4",
        }

        with patch("kvm_control.root_vm_exec.shutil.which", return_value=None):
            result = handle_request(self.config, "sync-firewall-egress", payload)

        self.assertEqual(result["result"], "ok")
        state_file = self.config.storage.state_dir / "firewall-egress.json"
        self.assertTrue(state_file.exists())
        state = json.loads(state_file.read_text(encoding="utf-8"))
        self.assertEqual(state["entries"], ["0.0.0.0/1", "128.0.0.0/1", "198.51.100.42"])

    def test_sync_firewall_ingress_writes_state_when_ipset_unavailable(self) -> None:
        payload = {
            "vm_id": "firewall-ingress",
            "image_id": "firewall-ingress",
            "layer2_path": str(self.root / "layer2" / "unused.qcow2"),
            "layer3_path": str(self.root / "layer3" / "unused.qcow2"),
            "entries": ["0.0.0.0/1", "128.0.0.0/1", "198.51.100.42"],
            "ipset_name": "kvmIngressAnyV4",
        }

        with patch("kvm_control.root_vm_exec.shutil.which", return_value=None):
            result = handle_request(self.config, "sync-firewall-ingress", payload)

        self.assertEqual(result["result"], "ok")
        state_file = self.config.storage.state_dir / "firewall-ingress.json"
        self.assertTrue(state_file.exists())
        state = json.loads(state_file.read_text(encoding="utf-8"))
        self.assertEqual(state["entries"], ["0.0.0.0/1", "128.0.0.0/1", "198.51.100.42"])

    def test_sync_firewall_ipset_writes_named_state_when_ipset_unavailable(self) -> None:
        payload = {
            "vm_id": "firewall-dev",
            "image_id": "firewall-dev",
            "layer2_path": str(self.root / "layer2" / "unused.qcow2"),
            "layer3_path": str(self.root / "layer3" / "unused.qcow2"),
            "entries": ["198.51.100.42"],
            "ipset_name": "kvmIngressDevV4",
            "target_zone": "dev",
        }

        with patch("kvm_control.root_vm_exec.shutil.which", return_value=None):
            result = handle_request(self.config, "sync-firewall-ipset", payload)

        self.assertEqual(result["result"], "ok")
        state_file = self.config.storage.state_dir / "kvmIngressDevV4.json"
        self.assertTrue(state_file.exists())
        state = json.loads(state_file.read_text(encoding="utf-8"))
        self.assertEqual(state["entries"], ["198.51.100.42"])
