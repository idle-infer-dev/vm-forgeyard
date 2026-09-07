from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import AppConfig, load_config

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None


ALLOWED_ACTIONS = {
    "build-base-image",
    "build-layer2-image",
    "create-layer2",
    "create-layer3",
    "resize-layer3",
    "convert-layer3-to-layer2",
    "start-vm",
    "poweroff-vm",
    "pause-vm",
    "resume-vm",
    "stop-vm",
    "restart-vm",
    "inspect-vm",
    "revert-vm",
    "delete-layer3",
    "delete-layer2",
    "publish-image",
    "fetch-image",
    "retire-image",
    "delete-image",
    "sync-firewall-ipset",
    "sync-firewall-ingress",
    "sync-firewall-egress",
    "delete-runtime",
    "reconcile-runtime",
    "cleanup-after-boot",
    "cleanup-trash",
    "get-host-capacity",
    "wait-ssh",
}


DEFAULT_LAYER3_VIRTUAL_SIZE_BYTES = 1024 * 1024 * 1024
MIN_VIRT_CUSTOMIZE_SCRATCH_FREE_BYTES = 1024 * 1024 * 1024


def _resolve(path: str) -> Path:
    return Path(path).resolve()


def _ensure_under(root: Path, path: Path) -> None:
    if root not in path.parents and root != path:
        raise ValueError(f"path {path} escapes root {root}")


def _ensure_min_free_space(path: Path, required_bytes: int, context: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(path)
    if usage.free < required_bytes:
        raise RuntimeError(
            f"not enough free space for {context}: {path} has {usage.free} bytes free, "
            f"requires at least {required_bytes} bytes"
        )


def _virt_customize_scratch_paths() -> list[Path]:
    tmpdir = os.environ.get("TMPDIR") or "/var/tmp"
    candidates = [
        os.environ.get("LIBGUESTFS_CACHEDIR") or tmpdir,
        os.environ.get("LIBGUESTFS_TMPDIR") or tmpdir,
    ]
    paths: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).resolve()
        if path in seen:
            continue
        seen.add(path)
        paths.append(path)
    return paths


def _ensure_virt_customize_scratch_space() -> None:
    for path in _virt_customize_scratch_paths():
        _ensure_min_free_space(path, MIN_VIRT_CUSTOMIZE_SCRATCH_FREE_BYTES, "virt-customize scratch")


def _touch_qcow(
    path: Path,
    backing_file: str | None = None,
    backing_format: str = "qcow2",
    virtual_size_bytes: int | None = None,
    dry_run: bool = False,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    stored_virtual_size_bytes = virtual_size_bytes or DEFAULT_LAYER3_VIRTUAL_SIZE_BYTES
    if dry_run:
        payload = {
            "format": "qcow2",
            "backing_file": backing_file,
            "virtual_size_bytes": stored_virtual_size_bytes,
            "created_at": datetime.now(UTC).isoformat(),
            "dry_run": True,
        }
        path.write_text(json.dumps(payload, indent=2))
        return
    qemu_img = shutil.which("qemu-img")
    if qemu_img and backing_file:
        command = [qemu_img, "create", "-f", "qcow2", "-F", backing_format, "-b", backing_file, str(path)]
        if virtual_size_bytes is not None:
            command.insert(-1, "-u")
            command.append(str(virtual_size_bytes))
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
        return
    if qemu_img:
        subprocess.run(
            [qemu_img, "create", "-f", "qcow2", str(path), str(stored_virtual_size_bytes)],
            check=True,
            capture_output=True,
            text=True,
        )
        return
    payload = {"format": "qcow2", "backing_file": backing_file, "created_at": datetime.now(UTC).isoformat()}
    payload["virtual_size_bytes"] = stored_virtual_size_bytes
    path.write_text(json.dumps(payload, indent=2))


def _qcow_virtual_size_bytes(path: Path) -> int:
    if not path.exists():
        raise FileNotFoundError(f"missing qcow2 image {path}")
    qemu_img = shutil.which("qemu-img")
    if qemu_img:
        try:
            result = subprocess.run(
                [qemu_img, "info", "--output=json", str(path)],
                check=True,
                capture_output=True,
                text=True,
            )
            data = json.loads(result.stdout)
            return int(data["virtual-size"])
        except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError, ValueError, TypeError):
            pass
    try:
        data = json.loads(path.read_text())
        if "virtual_size_bytes" in data:
            return int(data["virtual_size_bytes"])
    except (json.JSONDecodeError, OSError, ValueError, TypeError):
        pass
    return path.stat().st_size


def _resize_qcow(path: Path, new_virtual_size_bytes: int, dry_run: bool = False) -> None:
    if not path.exists():
        raise FileNotFoundError(f"missing qcow2 image {path}")
    if dry_run:
        try:
            payload = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            payload = {"format": "qcow2"}
        payload["virtual_size_bytes"] = new_virtual_size_bytes
        payload["resized_at"] = datetime.now(UTC).isoformat()
        payload["dry_run"] = True
        path.write_text(json.dumps(payload, indent=2))
        return
    qemu_img = shutil.which("qemu-img")
    if qemu_img:
        subprocess.run(
            [qemu_img, "resize", str(path), str(new_virtual_size_bytes)],
            check=True,
            capture_output=True,
            text=True,
        )
        return
    try:
        payload = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        payload = {"format": "qcow2"}
    payload["virtual_size_bytes"] = new_virtual_size_bytes
    payload["resized_at"] = datetime.now(UTC).isoformat()
    path.write_text(json.dumps(payload, indent=2))


def _convert_qcow(
    path: Path,
    source_path: Path,
    backing_file: str,
    source_format: str = "qcow2",
    backing_format: str = "qcow2",
    dry_run: bool = False,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if dry_run:
        payload = {
            "format": "qcow2",
            "source_path": str(source_path),
            "backing_file": backing_file,
            "created_at": datetime.now(UTC).isoformat(),
            "dry_run": True,
        }
        path.write_text(json.dumps(payload, indent=2))
        return
    qemu_img = shutil.which("qemu-img")
    if qemu_img:
        subprocess.run(
            [
                qemu_img,
                "convert",
                "-f",
                source_format,
                "-O",
                "qcow2",
                "-B",
                backing_file,
                "-F",
                backing_format,
                str(source_path),
                str(path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return
    payload = {
        "format": "qcow2",
        "source_path": str(source_path),
        "backing_file": backing_file,
        "created_at": datetime.now(UTC).isoformat(),
    }
    path.write_text(json.dumps(payload, indent=2))


def _meta_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".meta")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_or_stub(source: Path, target: Path, dry_run: bool) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if dry_run:
        payload = {
            "copied_from": str(source),
            "created_at": datetime.now(UTC).isoformat(),
            "dry_run": True,
        }
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return
    shutil.copy2(str(source), str(target))


def _write_metadata(path: Path, metadata: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if yaml is None:
        path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        return
    path.write_text(yaml.safe_dump(metadata, sort_keys=True), encoding="utf-8")


def _is_rsync_uri(path: str) -> bool:
    return path.startswith("rsync://")


def _parse_rsync_uri(uri: str) -> tuple[str, str, str]:
    parsed = urlparse(uri)
    if parsed.scheme != "rsync" or not parsed.netloc:
        raise ValueError(f"invalid rsync uri: {uri}")
    path = parsed.path.lstrip("/")
    module, _, remainder = path.partition("/")
    if not module or not remainder:
        raise ValueError(f"invalid rsync uri path: {uri}")
    return parsed.netloc, module, remainder


def _rsync_meta_uri(uri: str) -> str:
    return f"{uri}.meta"


def _rsync_parent_uri(uri: str) -> str:
    host, module, remainder = _parse_rsync_uri(uri)
    parent = remainder.rsplit("/", 1)[0]
    return f"rsync://{host}/{module}/{parent}/"


def _rsync_run(args: list[str], timeout_s: int, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["rsync", "--timeout", str(timeout_s), *args],
        check=check,
        capture_output=True,
        text=True,
    )


def _rsync_exists(uri: str, timeout_s: int) -> bool:
    result = _rsync_run(["--list-only", uri], timeout_s, check=False)
    return result.returncode == 0


def _rsync_put_file(source: Path, destination_uri: str, timeout_s: int) -> None:
    _rsync_run(["-aS", "--mkpath", str(source), destination_uri], timeout_s)


def _rsync_get_file(source_uri: str, destination: Path, timeout_s: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    _rsync_run(["-aS", source_uri, str(destination)], timeout_s)


def _rsync_delete_image_dir(image_uri: str, timeout_s: int) -> None:
    image_dir_uri = _rsync_parent_uri(image_uri)
    with tempfile.TemporaryDirectory() as tmpdir:
        _rsync_run(["-a", "--delete", f"{tmpdir}/", image_dir_uri], timeout_s)


def _runtime_json(config: AppConfig, vm_id: str) -> Path:
    return config.storage.runtime_dir / f"{vm_id}.json"


def _runtime_xml(config: AppConfig, vm_id: str) -> Path:
    return config.storage.runtime_dir / f"{vm_id}.xml"


def _command_log(config: AppConfig, action: str, vm_id: str | None, commands: list[list[str]]) -> None:
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "executor_command",
        "action": action,
        "vm_id": vm_id,
        "dry_run": config.dry_run,
        "commands": commands,
    }
    config.storage.audit_log.parent.mkdir(parents=True, exist_ok=True)
    with config.storage.audit_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def _progress_log(config: AppConfig, action: str, subject_id: str | None, step: str, status: str, details: dict[str, Any] | None = None) -> None:
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "executor_progress",
        "action": action,
        "subject_id": subject_id,
        "step": step,
        "status": status,
        "details": details or {},
    }
    config.storage.audit_log.parent.mkdir(parents=True, exist_ok=True)
    with config.storage.audit_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
    print(json.dumps(entry), file=sys.stderr, flush=True)


def _required_tool(name: str) -> str:
    tool = shutil.which(name)
    if tool is None:
        raise RuntimeError(f"{name} is required")
    return tool


def _run_command(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if check and completed.returncode != 0:
        output = "\n".join(part for part in (completed.stdout.strip(), completed.stderr.strip()) if part)
        command_text = " ".join(shlex.quote(part) for part in command)
        raise RuntimeError(output or f"{command_text} failed with exit status {completed.returncode}")
    return completed


def _run_progress_command(config: AppConfig, action: str, subject_id: str | None, step: str, command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    started = time.monotonic()
    command_text = " ".join(shlex.quote(part) for part in command)
    _progress_log(config, action, subject_id, step, "running", {"command": command_text})
    try:
        completed = _run_command(command, check=check)
    except Exception as exc:
        _progress_log(
            config,
            action,
            subject_id,
            step,
            "failed",
            {"command": command_text, "duration_s": round(time.monotonic() - started, 3), "error": str(exc)},
        )
        raise
    _progress_log(
        config,
        action,
        subject_id,
        step,
        "completed",
        {"command": command_text, "duration_s": round(time.monotonic() - started, 3), "returncode": completed.returncode},
    )
    return completed


def _run_chroot(root: Path, command: list[str]) -> None:
    _run_command(["chroot", str(root), *command])


def _base_image_metadata(payload: dict[str, Any], image_path: Path, kernel_dir: Path, result: dict[str, Any]) -> dict[str, Any]:
    recipe = dict(payload["recipe"])
    return {
        "image_id": payload["image_id"],
        "recipe": recipe,
        "image_path": str(image_path),
        "image_format": recipe["output_format"],
        "kernel_dir": str(kernel_dir),
        "kernel_path": result.get("kernel_path"),
        "initrd_path": result.get("initrd_path"),
        "checksum_sha256": result.get("checksum_sha256"),
        "size_bytes": result.get("size_bytes"),
        "built_at": result.get("built_at"),
        "builder": "kvm-control",
    }


def _planned_base_image_commands(config: AppConfig, payload: dict[str, Any]) -> list[list[str]]:
    recipe = payload["recipe"]
    image_path = payload["image_path"]
    mount_label = "BUILD_MOUNT"
    packages = _base_image_packages(recipe)
    debootstrap_command = [
        "env",
        "DEBOOTSTRAP_DIR=/usr/share/debootstrap",
        "debootstrap",
        "--arch=amd64",
        "--variant=minbase",
        f"--keyring={_debootstrap_keyring(recipe)}",
        recipe["suite"],
        mount_label,
        recipe["repository_urls"][0],
        _debootstrap_script(recipe),
    ]
    apt_http_proxy = _base_image_apt_http_proxy(config, recipe)
    if apt_http_proxy:
        debootstrap_command[1:1] = [f"http_proxy={apt_http_proxy}", f"https_proxy={apt_http_proxy}"]
    commands = [
        ["truncate", "-s", f"{payload['image_size_mb']}M", image_path],
        ["mkfs.ext4", "-F", "-L", recipe["catalog_image_id"][:16], image_path],
        ["mount", "-o", "loop", image_path, mount_label],
        debootstrap_command,
        ["chroot", mount_label, "apt-get", "install", "-y", *packages],
        ["umount", mount_label],
        ["e2fsck", "-fy", image_path],
        ["resize2fs", "-M", image_path],
        ["write-image-meta", image_path],
    ]
    if config.guest_bootstrap.apt_http_proxy:
        commands.insert(4, ["write-apt-proxy", config.guest_bootstrap.apt_http_proxy])
    return commands


def _layer2_python_tool_command(tools: list[str]) -> str:
    quoted_tools = " ".join(shlex.quote(tool) for tool in tools)
    return (
        "python3 -m venv /opt/kvm-control-agent-tools && "
        "/opt/kvm-control-agent-tools/bin/python -m pip install --upgrade pip setuptools wheel && "
        f"/opt/kvm-control-agent-tools/bin/python -m pip install {quoted_tools} && "
        "find /opt/kvm-control-agent-tools/bin -maxdepth 1 -type f -perm /111 "
        "-exec ln -sf {} /usr/local/bin/ \\;"
    )


def _layer2_account_commands(recipe: dict[str, Any]) -> list[str]:
    commands: list[str] = []
    for account in recipe.get("user_accounts") or []:
        username = account["username"]
        shell = "/bin/bash" if account.get("login", True) else "/usr/sbin/nologin"
        commands.append(f"id -u {shlex.quote(username)} >/dev/null 2>&1 || useradd -m -s {shlex.quote(shell)} {shlex.quote(username)}")
        for group in account.get("groups") or []:
            commands.append(f"getent group {shlex.quote(group)} >/dev/null 2>&1 && usermod -aG {shlex.quote(group)} {shlex.quote(username)} || true")
        if account.get("sudo"):
            commands.append(f"usermod -aG sudo {shlex.quote(username)}")
    return commands


def _layer2_service_disable_commands(recipe: dict[str, Any]) -> list[str]:
    names: set[str] = set()
    for service in recipe.get("services") or []:
        if service.get("enabled_by_default"):
            continue
        names.add(service["name"])
        names.update(service.get("package_names") or [])
    return [f"if command -v systemctl >/dev/null 2>&1; then systemctl disable --now {shlex.quote(name)} 2>/dev/null || true; else service {shlex.quote(name)} stop 2>/dev/null || true; fi" for name in sorted(names)]


def _planned_layer2_image_commands(config: AppConfig, payload: dict[str, Any]) -> list[list[str]]:
    recipe = payload["recipe"]
    commands = [_layer2_create_command(payload, payload["base_image_path"], payload["layer2_path"], recipe)]
    if recipe.get("layer2_size_mb"):
        commands.append(["grow-layer2-ext4", payload["layer2_path"]])
    commands.append(_layer2_customize_command(payload))
    commands.append(["write-image-meta", payload["layer2_path"]])
    return commands


def _layer2_customize_command(payload: dict[str, Any]) -> list[str]:
    recipe = payload["recipe"]
    virt_customize = ["virt-customize", "--network", "-a", payload["layer2_path"]]
    if recipe.get("system_packages"):
        virt_customize.extend(["--install", ",".join(recipe["system_packages"])])
    for command in _layer2_account_commands(recipe):
        virt_customize.extend(["--run-command", command])
    if recipe.get("python_venv_tools"):
        virt_customize.extend(["--run-command", _layer2_python_tool_command(recipe["python_venv_tools"])])
    for command in _layer2_service_disable_commands(recipe):
        virt_customize.extend(["--run-command", command])
    virt_customize.extend(["--write", f"/etc/kvm-control-layer2-recipe:{recipe['id']}\n"])
    return virt_customize


def _layer2_booted_builder_enabled(recipe: dict[str, Any]) -> bool:
    return recipe["id"] == "agent-sandbox-tools-ubuntu-24.04-noble-amd64"


def _layer2_create_command(payload: dict[str, Any], base_image_path: str, layer2_path: str, recipe: dict[str, Any]) -> list[str]:
    command = [
        "qemu-img",
        "create",
        "-f",
        "qcow2",
        "-F",
        payload.get("base_image_format", "raw"),
        "-b",
        base_image_path,
        layer2_path,
    ]
    if recipe.get("layer2_size_mb"):
        command.append(str(int(recipe["layer2_size_mb"]) * 1024 * 1024))
    return command


def _grow_layer2_ext4(config: AppConfig, layer2_path: Path) -> None:
    if config.dry_run:
        return
    qemu_nbd = shutil.which("qemu-nbd")
    if qemu_nbd is None:
        raise RuntimeError("qemu-nbd is required to grow layer2 ext4 filesystems")
    _run_command(["modprobe", "nbd", "max_part=16"], check=False)
    nbd_device = _find_free_nbd()
    if nbd_device is None:
        raise RuntimeError("no free nbd device available to grow layer2 filesystem")
    connected = False
    try:
        _run_command([qemu_nbd, "--connect", nbd_device, str(layer2_path)])
        connected = True
        root_device = _mountable_root_device(nbd_device)
        _run_command(["e2fsck", "-fy", root_device])
        _run_command(["resize2fs", root_device])
    finally:
        if connected:
            _run_command([qemu_nbd, "--disconnect", nbd_device], check=False)


def _safe_id(value: str, max_len: int = 56) -> str:
    text = "".join(char if char.isalnum() else "-" for char in value.lower()).strip("-")
    while "--" in text:
        text = text.replace("--", "-")
    return text[:max_len].strip("-") or "build"


def _build_vm_mac(config: AppConfig, recipe_id: str) -> str:
    prefix_parts = config.network.mac_prefix.split(":")
    digest = hashlib.sha256(recipe_id.encode("utf-8")).digest()
    suffix = [f"{byte:02x}" for byte in digest[: max(0, 6 - len(prefix_parts))]]
    return ":".join([*prefix_parts, *suffix][:6])


def _build_vm_network(config: AppConfig) -> tuple[str, str, str]:
    segment = next((candidate for candidate in config.network.segments if candidate.id == "dev"), config.network.segments[0])
    if segment.address:
        network = ipaddress.ip_interface(segment.address).network
    else:
        network = ipaddress.ip_network(config.network.cidr, strict=False)
    hosts = list(network.hosts())
    reserved_ip = str(hosts[-10] if len(hosts) >= 10 else hosts[-1])
    return segment.id, segment.bridge, reserved_ip


def _build_vm_dns_server(config: AppConfig) -> str | None:
    segment = next((candidate for candidate in config.network.segments if candidate.id == "dev"), config.network.segments[0])
    if segment.address:
        return str(ipaddress.ip_interface(segment.address).ip)
    if config.network.gateway:
        return str(ipaddress.ip_address(config.network.gateway))
    return None


def _read_first_authorized_key(path: Path) -> str | None:
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        candidate = line.strip()
        if candidate.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")):
            return candidate
    return None


def _ssh_base_command(ip_address: str, identity_file: Path | None = None) -> list[str]:
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=10",
    ]
    if identity_file is not None:
        command.extend(["-i", str(identity_file)])
    command.append(f"root@{ip_address}")
    return command


def _run_ssh(ip_address: str, command: str, *, identity_file: Path | None = None, timeout_s: int = 300, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*_ssh_base_command(ip_address, identity_file), command],
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


def _run_ssh_script(ip_address: str, script: str, *, identity_file: Path | None = None, timeout_s: int = 1800) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*_ssh_base_command(ip_address, identity_file), "bash", "-s"],
        input=script,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


def _wait_for_ssh(config: AppConfig, action: str, subject_id: str | None, ip_address: str, *, identity_file: Path | None = None, timeout_s: int = 300) -> None:
    deadline = time.monotonic() + timeout_s
    last_error = ""
    while time.monotonic() < deadline:
        result = _run_ssh(ip_address, "true", identity_file=identity_file, timeout_s=15, check=False)
        if result.returncode == 0:
            return
        last_error = (result.stderr or result.stdout).strip()
        time.sleep(5)
    _progress_log(config, action, subject_id, "wait for ssh", "failed", {"ip_address": ip_address, "error": last_error})
    raise TimeoutError(f"timed out waiting for ssh on {ip_address}: {last_error}")


def _wait_for_build_ssh(
    config: AppConfig,
    action: str,
    subject_id: str | None,
    reserved_ip: str,
    mac_address: str,
    *,
    identity_file: Path,
    timeout_s: int = 360,
) -> str:
    deadline = time.monotonic() + timeout_s
    last_error = ""
    tried: set[str] = set()
    while time.monotonic() < deadline:
        candidates = [reserved_ip]
        lease_ip = _read_leases_for_mac(mac_address)
        if lease_ip and lease_ip not in candidates:
            candidates.append(lease_ip)
        for ip_address in candidates:
            tried.add(ip_address)
            result = _run_ssh(ip_address, "true", identity_file=identity_file, timeout_s=15, check=False)
            if result.returncode == 0:
                return ip_address
            last_error = (result.stderr or result.stdout).strip()
        time.sleep(5)
    _progress_log(
        config,
        action,
        subject_id,
        "wait for ssh",
        "failed",
        {"ip_address": reserved_ip, "mac_address": mac_address, "tried": sorted(tried), "error": last_error},
    )
    raise TimeoutError(f"timed out waiting for ssh for {mac_address} via {sorted(tried)}: {last_error}")


def _write_ephemeral_ssh_key(key_path: Path) -> str:
    _required_tool("ssh-keygen")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    for candidate in (key_path, key_path.with_suffix(key_path.suffix + ".pub")):
        if candidate.exists():
            candidate.unlink()
    _run_command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "kvm-control-layer2-build", "-f", str(key_path)])
    return key_path.with_suffix(key_path.suffix + ".pub").read_text(encoding="utf-8").strip()


def _layer2_bootstrap_script(config: AppConfig, recipe: dict[str, Any]) -> str:
    packages = " ".join(shlex.quote(package) for package in recipe.get("system_packages") or [])
    accounts = "\n".join(_layer2_account_commands(recipe))
    python_tools = _layer2_python_tool_command(recipe.get("python_venv_tools") or []) if recipe.get("python_venv_tools") else "true"
    services = "\n".join(_layer2_service_disable_commands(recipe))
    apt_cache = recipe.get("apt_cache") or {}
    apt_proxy = apt_cache.get("proxy_url") if apt_cache.get("enabled") else config.guest_bootstrap.apt_http_proxy
    apt_cache_required = bool(apt_cache.get("required")) if apt_cache.get("enabled") else False
    dns_server = _build_vm_dns_server(config)
    dns_block = (
        f"grep -qs '^nameserver ' /etc/resolv.conf || printf 'nameserver {dns_server}\\n' >/etc/resolv.conf"
        if dns_server
        else "true"
    )
    proxy_block = (
        f"printf 'Acquire::http::Proxy \"{apt_proxy}\";\\n' >/etc/apt/apt.conf.d/80-proxy.conf"
        if apt_proxy
        else "rm -f /etc/apt/apt.conf.d/80-proxy.conf"
    )
    apt_update = (
        "apt-get update"
        if apt_cache_required
        else "apt-get update || { rm -f /etc/apt/apt.conf.d/80-proxy.conf; apt-get update; }"
    )
    return f"""set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
{dns_block}
{proxy_block}
if [ -x /usr/local/sbin/kvm-control-grow-rootfs ]; then
    /usr/local/sbin/kvm-control-grow-rootfs || true
fi
cat >/usr/sbin/policy-rc.d <<'EOF'
#!/bin/sh
exit 101
EOF
chmod 0755 /usr/sbin/policy-rc.d
held_packages="$(dpkg-query -W -f='${{binary:Package}}\\n' systemd systemd-sysv systemd-timesyncd udev libsystemd0 libudev1 libpam-systemd 2>/dev/null || true)"
if [ -n "$held_packages" ]; then
    apt-mark hold $held_packages
fi
cleanup_layer2_build() {{
    rm -f /usr/sbin/policy-rc.d
    if [ -n "$held_packages" ]; then
        apt-mark unhold $held_packages || true
    fi
}}
trap cleanup_layer2_build EXIT
{apt_update}
apt-get install -y --no-upgrade {packages}
{accounts}
{python_tools}
{services}
printf '%s\\n' {shlex.quote(recipe['id'])} >/etc/kvm-control-layer2-recipe
command -v rg
	python3 --version
	"""


def _layer2_cleanup_script(ephemeral_public_key: str) -> str:
    return f"""set -euxo pipefail
if [ -f /root/.ssh/authorized_keys ]; then
    grep -vxF {shlex.quote(ephemeral_public_key)} /root/.ssh/authorized_keys >/root/.ssh/authorized_keys.new || true
    mv /root/.ssh/authorized_keys.new /root/.ssh/authorized_keys
    chmod 0600 /root/.ssh/authorized_keys
fi
rm -f /etc/kvm-control/vm.env /etc/cron.d/kvm-control /etc/network/interfaces.d/kvm-control
rm -f /usr/local/sbin/kvm-control-configure-network /usr/local/sbin/kvm-control-grow-rootfs
rm -f /etc/apt/apt.conf.d/80-proxy.conf
rm -rf /var/log/kvm-control
"""


def _planned_booted_layer2_image_commands(config: AppConfig, payload: dict[str, Any]) -> list[list[str]]:
    recipe = payload["recipe"]
    network_id, network_bridge, reserved_ip = _build_vm_network(config)
    build_vm_id = f"kvm-control-build-{_safe_id(recipe['id'], 42)}"
    build_layer2 = str(config.storage.layer2_dir / f"{build_vm_id}.seed.qcow2")
    build_layer3 = str(config.storage.layer3_dir / f"{build_vm_id}.work.qcow2")
    return [
        ["qemu-img", "create", "-f", "qcow2", "-F", payload.get("base_image_format", "raw"), "-b", payload["base_image_path"], build_layer2],
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", build_layer2, build_layer3, str(12 * 1024 * 1024 * 1024)],
        ["prepare-layer3-bootstrap", build_layer3, payload.get("authorized_keys_path", "")],
        ["virsh", "define", str(_runtime_xml(config, build_vm_id))],
        ["virsh", "start", build_vm_id],
        ["wait-for-ssh", f"root@{reserved_ip}", "or dhcp lease", network_id, network_bridge],
        ["ssh", f"root@{reserved_ip}", "or dhcp lease", "install layer2 recipe packages/users/tools"],
        ["ssh", f"root@{reserved_ip}", "or dhcp lease", "cleanup build-only access and shutdown"],
        ["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", "-B", payload["base_image_path"], "-F", payload.get("base_image_format", "raw"), build_layer3, payload["layer2_path"]],
        ["cleanup", build_vm_id, build_layer2, build_layer3],
    ]


def _copy_authorized_keys(source_path: Path, root: Path) -> bool:
    if not source_path.exists():
        return False
    target_dir = root / "root/.ssh"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "authorized_keys"
    shutil.copy2(source_path, target)
    os.chmod(target_dir, 0o700)
    os.chmod(target, 0o600)
    return True


def _read_public_key_line(path: Path) -> str | None:
    if not path.exists():
        return None
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if line.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")):
            return line
    return None


def _public_key_for_private_identity(path: Path) -> str | None:
    public_key = _read_public_key_line(Path(f"{path}.pub"))
    if public_key:
        return public_key
    if not path.exists():
        return None
    ssh_keygen = shutil.which("ssh-keygen")
    if ssh_keygen is None:
        return None
    completed = subprocess.run(
        [ssh_keygen, "-y", "-f", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return _read_public_key_line_from_text(completed.stdout)


def _read_public_key_line_from_text(text: str) -> str | None:
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")):
            return line
    return None


def _append_host_ssh_identity_public_keys(root: Path, identity_dir: Path = Path("/root/.ssh")) -> int:
    added = 0
    for name in ("id_ed25519", "id_ecdsa", "id_rsa"):
        public_key = _public_key_for_private_identity(identity_dir / name)
        if public_key and _append_guest_ssh_public_key(root, public_key):
            added += 1
    return added


def _base_image_packages(recipe: dict[str, Any]) -> list[str]:
    common = [
        "ca-certificates",
        "cron",
        "curl",
        "initramfs-tools",
        "iproute2",
        "iputils-ping",
        "kmod",
        "netbase",
        "openssh-server",
        "procps",
        "wget",
    ]
    if recipe["id"] == "ubuntu-24.04-noble-amd64":
        return [*common, "linux-image-virtual", "netplan.io", "systemd-sysv"]
    if recipe["id"] == "devuan-6-excalibur-amd64":
        return ["busybox", "ethtool", "ifupdown", "isc-dhcp-client", *common, "linux-image-amd64"]
    raise NotImplementedError(f"package list is not implemented for recipe {recipe['id']}")


def _debootstrap_keyring(recipe: dict[str, Any]) -> str:
    if recipe["id"] == "ubuntu-24.04-noble-amd64":
        return "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
    if recipe["id"] == "devuan-6-excalibur-amd64":
        return "/usr/share/keyrings/devuan-archive-keyring.gpg"
    raise NotImplementedError(f"keyring is not implemented for recipe {recipe['id']}")


def _debootstrap_script(recipe: dict[str, Any]) -> str:
    # Devuan's debootstrap package can ship suite symlinks whose targets are not
    # copied correctly into the debootstrap runtime. Pass the concrete script.
    if recipe["id"] == "ubuntu-24.04-noble-amd64":
        return "/usr/share/debootstrap/scripts/gutsy"
    if recipe["id"] == "devuan-6-excalibur-amd64":
        return "/usr/share/debootstrap/scripts/ceres"
    raise NotImplementedError(f"debootstrap script is not implemented for recipe {recipe['id']}")


def _base_image_hostname(recipe: dict[str, Any]) -> str:
    if recipe["id"] == "ubuntu-24.04-noble-amd64":
        return "ubuntu-24-04-template"
    if recipe["id"] == "devuan-6-excalibur-amd64":
        return "devuan-excalibur-template"
    return f"{recipe['id']}-template"


def _sources_list(recipe: dict[str, Any]) -> str:
    suite = recipe["suite"]
    mirror = recipe["repository_urls"][0].rstrip("/")
    if recipe["id"] == "ubuntu-24.04-noble-amd64":
        return "\n".join(
            [
                f"deb {mirror} {suite} main universe",
                f"deb {mirror} {suite}-updates main universe",
                f"deb http://security.ubuntu.com/ubuntu {suite}-security main universe",
                "",
            ]
        )
    if recipe["id"] == "devuan-6-excalibur-amd64":
        return "\n".join(
            [
                f"deb {mirror} {suite} main",
                f"deb {mirror} {suite}-updates main",
                f"deb {mirror} {suite}-security main",
                "",
            ]
        )
    raise NotImplementedError(f"sources.list is not implemented for recipe {recipe['id']}")


def _recipe_apt_http_proxy(recipe: dict[str, Any]) -> str | None:
    apt_cache = recipe.get("apt_cache") or {}
    if not apt_cache.get("enabled"):
        return None
    proxy_url = apt_cache.get("proxy_url")
    if apt_cache.get("required") and not proxy_url:
        raise ValueError(f"recipe {recipe['id']} requires apt cache but has no proxy_url")
    return proxy_url


def _base_image_apt_http_proxy(config: AppConfig, recipe: dict[str, Any]) -> str | None:
    return _recipe_apt_http_proxy(recipe) or config.guest_bootstrap.apt_http_proxy


def _write_debootstrap_base_config(root: Path, config: AppConfig, payload: dict[str, Any]) -> None:
    recipe = payload["recipe"]
    hostname = _base_image_hostname(recipe)
    (root / "etc/apt").mkdir(parents=True, exist_ok=True)
    (root / "etc/apt/sources.list").write_text(_sources_list(recipe), encoding="utf-8")
    apt_conf_dir = root / "etc/apt/apt.conf.d"
    apt_conf_dir.mkdir(parents=True, exist_ok=True)
    (apt_conf_dir / "80-kvm-control-retries.conf").write_text('Acquire::Retries "3";\n', encoding="utf-8")
    apt_http_proxy = _base_image_apt_http_proxy(config, recipe)
    if apt_http_proxy:
        (apt_conf_dir / "80-proxy.conf").write_text(
            f'Acquire::http::Proxy "{apt_http_proxy}";\n',
            encoding="utf-8",
        )
    (root / "etc/hostname").write_text(f"{hostname}\n", encoding="utf-8")
    (root / "etc/hosts").write_text(
        f"127.0.0.1 localhost\n127.0.1.1 {hostname}\n",
        encoding="utf-8",
    )
    if recipe["id"] == "ubuntu-24.04-noble-amd64":
        netplan_dir = root / "etc/netplan"
        netplan_dir.mkdir(parents=True, exist_ok=True)
        (netplan_dir / "01-kvm-control.yaml").write_text(
            "\n".join(
                [
                    "network:",
                    "  version: 2",
                    "  renderer: networkd",
                    "  ethernets:",
                    "    all-ethernet:",
                    "      match:",
                    "        name: e*",
                    "      dhcp4: true",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    else:
        network_dir = root / "etc/network"
        network_dir.mkdir(parents=True, exist_ok=True)
        (network_dir / "interfaces").write_text(
            "\n".join(
                [
                    "source /etc/network/interfaces.d/*",
                    "",
                    "auto lo",
                    "iface lo inet loopback",
                    "",
                    "allow-hotplug eth0",
                    "iface eth0 inet dhcp",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    ssh_dir = root / "etc/ssh/sshd_config.d"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    (ssh_dir / "root-key.conf").write_text(
        "PermitRootLogin prohibit-password\nPasswordAuthentication no\nPubkeyAuthentication yes\n",
        encoding="utf-8",
    )


def _cleanup_mounts(root: Path) -> None:
    for suffix in ("dev/pts", "dev", "proc", "sys", ""):
        target = root / suffix if suffix else root
        _run_command(["umount", "-lf", str(target)], check=False)


def _copy_latest_kernel(root: Path, kernel_dir: Path) -> tuple[Path | None, Path | None]:
    kernel_dir.mkdir(parents=True, exist_ok=True)
    kernels = sorted((root / "boot").glob("vmlinuz-*"))
    initrds = sorted((root / "boot").glob("initrd.img-*"))
    if not kernels or not initrds:
        return None, None
    kernel = kernels[-1]
    initrd = initrds[-1]
    kernel_target = kernel_dir / "vmlinuz"
    initrd_target = kernel_dir / "initrd.img"
    shutil.copy2(kernel, kernel_target)
    shutil.copy2(initrd, initrd_target)
    return kernel_target, initrd_target


def _shrink_ext4_image(image_path: Path) -> None:
    _run_command(["e2fsck", "-fy", str(image_path)])
    _run_command(["resize2fs", "-M", str(image_path)])
    dump = _run_command(["dumpe2fs", "-h", str(image_path)])
    block_count: int | None = None
    block_size: int | None = None
    for line in dump.stdout.splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "Block count":
            block_count = int(value.strip())
        elif key.strip() == "Block size":
            block_size = int(value.strip())
    if block_count and block_size:
        with image_path.open("r+b") as handle:
            handle.truncate(block_count * block_size)
    _run_command(["fallocate", "-d", str(image_path)], check=False)


def _build_debootstrap_image(config: AppConfig, payload: dict[str, Any], planned_commands: list[list[str]]) -> dict[str, Any]:
    recipe = payload["recipe"]
    implemented_recipe_ids = {"ubuntu-24.04-noble-amd64", "devuan-6-excalibur-amd64"}
    if recipe["id"] not in implemented_recipe_ids:
        raise NotImplementedError(f"builder is not implemented for recipe {recipe['id']}")
    if recipe["method"] != "debootstrap" or recipe["architecture"] != "amd64":
        raise ValueError("debootstrap builder only supports amd64 debootstrap recipes")
    if recipe["disk_layout"] != "filesystem" or recipe["output_format"] != "raw":
        raise ValueError("debootstrap builder currently requires filesystem raw output")
    if not recipe.get("repository_urls"):
        raise ValueError("debootstrap builder requires repository_urls")

    image_path = _resolve(payload["image_path"])
    kernel_dir = _resolve(payload["kernel_dir"])
    _ensure_under(_resolve(str(config.storage.base_dir)), image_path)
    _ensure_under(_resolve(str(config.storage.base_dir.parent)), kernel_dir)
    if image_path.exists() and not payload.get("force"):
        raise FileExistsError(f"base image already exists: {image_path}")
    if config.dry_run:
        image_path.parent.mkdir(parents=True, exist_ok=True)
        kernel_dir.mkdir(parents=True, exist_ok=True)
        image_path.write_text(
            json.dumps({"format": "raw", "recipe_id": recipe["id"], "dry_run": True}, indent=2),
            encoding="utf-8",
        )
        kernel_path = kernel_dir / "vmlinuz"
        initrd_path = kernel_dir / "initrd.img"
        kernel_path.write_text("dry-run kernel\n", encoding="utf-8")
        initrd_path.write_text("dry-run initrd\n", encoding="utf-8")
        checksum = _sha256(image_path)
        result = {
            "result": "ok",
            "image_id": payload["image_id"],
            "image_path": str(image_path),
            "metadata_path": str(_meta_path(image_path)),
            "kernel_dir": str(kernel_dir),
            "kernel_path": str(kernel_path),
            "initrd_path": str(initrd_path),
            "checksum_sha256": checksum,
            "size_bytes": image_path.stat().st_size,
            "built_at": datetime.now(UTC).isoformat(),
            "planned_commands": planned_commands,
            "dry_run": True,
        }
        _write_metadata(_meta_path(image_path), _base_image_metadata(payload, image_path, kernel_dir, result))
        return result

    for tool in ("truncate", "mkfs.ext4", "mount", "debootstrap", "chroot", "e2fsck", "resize2fs", "dumpe2fs"):
        _required_tool(tool)
    tmp_image = image_path.with_name(f"{image_path.name}.tmp-{int(time.time())}")
    mount_dir = Path(tempfile.mkdtemp(prefix="kvm-control-base-image-"))
    mounted = False
    action = "build-base-image"
    subject_id = payload.get("image_id")
    try:
        _progress_log(config, action, subject_id, "build", "running", {"recipe_id": recipe["id"], "image_path": str(image_path)})
        tmp_image.parent.mkdir(parents=True, exist_ok=True)
        _run_progress_command(config, action, subject_id, "create sparse raw image", ["truncate", "-s", f"{int(payload['image_size_mb'])}M", str(tmp_image)])
        _run_progress_command(config, action, subject_id, "format ext4 filesystem", ["mkfs.ext4", "-F", "-L", recipe["catalog_image_id"][:16], str(tmp_image)])
        _run_progress_command(config, action, subject_id, "mount build filesystem", ["mount", "-o", "loop", str(tmp_image), str(mount_dir)])
        mounted = True
        debootstrap_command = [
            "env",
            "DEBOOTSTRAP_DIR=/usr/share/debootstrap",
            "debootstrap",
            "--arch=amd64",
            "--variant=minbase",
            f"--keyring={_debootstrap_keyring(recipe)}",
            recipe["suite"],
            str(mount_dir),
            recipe["repository_urls"][0],
            _debootstrap_script(recipe),
        ]
        apt_http_proxy = _base_image_apt_http_proxy(config, recipe)
        if apt_http_proxy:
            debootstrap_command[1:1] = [f"http_proxy={apt_http_proxy}", f"https_proxy={apt_http_proxy}"]
        _run_progress_command(
            config,
            action,
            subject_id,
            "debootstrap base system",
            debootstrap_command
        )
        shutil.copy2("/etc/resolv.conf", mount_dir / "etc/resolv.conf")
        _write_debootstrap_base_config(mount_dir, config, payload)
        _copy_authorized_keys(_resolve(payload["authorized_keys_path"]), mount_dir)
        for relative, fstype in (("dev", None), ("dev/pts", None), ("proc", "proc"), ("sys", "sysfs")):
            target = mount_dir / relative
            target.mkdir(parents=True, exist_ok=True)
            if fstype is None:
                _run_command(["mount", "--bind", f"/{relative}", str(target)])
            else:
                _run_command(["mount", "-t", fstype, fstype, str(target)])
        _run_progress_command(config, action, subject_id, "apt update", ["chroot", str(mount_dir), "/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update"])
        _run_progress_command(
            config,
            action,
            subject_id,
            "install image packages",
            [
                "chroot",
                str(mount_dir),
                "/usr/bin/env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "-y",
                *_base_image_packages(recipe),
            ],
        )
        _run_progress_command(config, action, subject_id, "generate initramfs", ["chroot", str(mount_dir), "update-initramfs", "-c", "-k", "all"])
        _progress_log(config, action, subject_id, "copy kernel artifacts", "running", {"kernel_dir": str(kernel_dir)})
        kernel_path, initrd_path = _copy_latest_kernel(mount_dir, kernel_dir)
        if kernel_path is None or initrd_path is None:
            raise RuntimeError("debootstrap build did not produce kernel artifacts")
        _progress_log(config, action, subject_id, "copy kernel artifacts", "completed", {"kernel_path": str(kernel_path), "initrd_path": str(initrd_path)})
        shutil.rmtree(mount_dir / "var/cache/apt/archives", ignore_errors=True)
        shutil.rmtree(mount_dir / "var/lib/apt/lists", ignore_errors=True)
        _progress_log(config, action, subject_id, "unmount build filesystem", "running", {"mount_dir": str(mount_dir)})
        _cleanup_mounts(mount_dir)
        _progress_log(config, action, subject_id, "unmount build filesystem", "completed", {"mount_dir": str(mount_dir)})
        mounted = False
        _progress_log(config, action, subject_id, "shrink ext4 image", "running", {"image_path": str(tmp_image)})
        _shrink_ext4_image(tmp_image)
        _progress_log(config, action, subject_id, "shrink ext4 image", "completed", {"image_path": str(tmp_image), "size_bytes": tmp_image.stat().st_size})
        os.chmod(tmp_image, 0o444)
        if image_path.exists():
            image_path.unlink()
        shutil.move(str(tmp_image), str(image_path))
        checksum = _sha256(image_path)
        result = {
            "result": "ok",
            "image_id": payload["image_id"],
            "image_path": str(image_path),
            "metadata_path": str(_meta_path(image_path)),
            "kernel_dir": str(kernel_dir),
            "kernel_path": str(kernel_path),
            "initrd_path": str(initrd_path),
            "checksum_sha256": checksum,
            "size_bytes": image_path.stat().st_size,
            "built_at": datetime.now(UTC).isoformat(),
            "planned_commands": planned_commands,
            "dry_run": False,
        }
        _write_metadata(_meta_path(image_path), _base_image_metadata(payload, image_path, kernel_dir, result))
        _progress_log(config, action, subject_id, "build", "completed", {"image_path": str(image_path), "size_bytes": result["size_bytes"]})
        return result
    except Exception as exc:
        _progress_log(config, action, subject_id, "build", "failed", {"recipe_id": recipe["id"], "error": str(exc)})
        raise
    finally:
        if mounted:
            _progress_log(config, action, subject_id, "cleanup mounted filesystems", "running", {"mount_dir": str(mount_dir)})
            _cleanup_mounts(mount_dir)
            _progress_log(config, action, subject_id, "cleanup mounted filesystems", "completed", {"mount_dir": str(mount_dir)})
        if tmp_image.exists():
            tmp_image.unlink()
        try:
            mount_dir.rmdir()
        except OSError:
            pass

def _layer2_image_metadata(payload: dict[str, Any], layer2_path: Path, result: dict[str, Any]) -> dict[str, Any]:
    recipe = dict(payload["recipe"])
    return {
        "image_id": payload["image_id"],
        "recipe": recipe,
        "base_image_path": str(_resolve(payload["base_image_path"])),
        "layer2_path": str(layer2_path),
        "image_format": "qcow2",
        "checksum_sha256": result.get("checksum_sha256"),
        "size_bytes": result.get("size_bytes"),
        "built_at": result.get("built_at"),
        "idempotent": result.get("idempotent", False),
        "builder": "kvm-control",
    }


def _build_layer2_image_booted(config: AppConfig, payload: dict[str, Any], planned_commands: list[list[str]]) -> dict[str, Any]:
    recipe = payload["recipe"]
    base_image_path = _resolve(payload["base_image_path"])
    layer2_path = _resolve(payload["layer2_path"])
    action = "build-layer2-image"
    subject_id = payload.get("image_id")
    build_vm_id = f"kvm-control-build-{_safe_id(recipe['id'], 42)}"
    build_layer2 = _resolve(str(config.storage.layer2_dir / f"{build_vm_id}.seed.qcow2"))
    build_layer3 = _resolve(str(config.storage.layer3_dir / f"{build_vm_id}.work.qcow2"))
    network_id, network_bridge, reserved_ip = _build_vm_network(config)
    reserved_mac = _build_vm_mac(config, recipe["id"])
    runtime_xml = _runtime_xml(config, build_vm_id)
    runtime_json = _runtime_json(config, build_vm_id)
    ssh_key_path = _resolve(str(config.storage.runtime_dir / f"{build_vm_id}.ssh_key"))
    booted = False

    def cleanup_runtime() -> None:
        if not config.dry_run and _libvirt_available() and _domain_exists(build_vm_id):
            state = _domain_state(build_vm_id)
            if state not in _STOPPED_DOMAIN_STATES:
                _virsh(["destroy", build_vm_id], check=False)
            _virsh(["undefine", build_vm_id], check=False)
        for candidate in (runtime_xml, runtime_json, build_layer2, build_layer3, ssh_key_path, ssh_key_path.with_suffix(ssh_key_path.suffix + ".pub")):
            if candidate.exists():
                candidate.unlink()

    if layer2_path.exists() and not payload.get("force"):
        checksum = _sha256(layer2_path)
        result = {
            "result": "ok",
            "image_id": payload["image_id"],
            "layer2_path": str(layer2_path),
            "base_image_path": str(base_image_path),
            "checksum_sha256": checksum,
            "size_bytes": layer2_path.stat().st_size,
            "built_at": datetime.now(UTC).isoformat(),
            "planned_commands": [],
            "idempotent": True,
            "dry_run": config.dry_run,
            "builder_mode": "booted-vm",
        }
        _write_metadata(_meta_path(layer2_path), _layer2_image_metadata(payload, layer2_path, result))
        return result

    if config.dry_run:
        layer2_path.parent.mkdir(parents=True, exist_ok=True)
        layer2_path.write_text(
            json.dumps({"format": "qcow2", "backing_file": str(base_image_path), "recipe_id": recipe["id"], "builder_mode": "booted-vm", "dry_run": True}, indent=2),
            encoding="utf-8",
        )
        checksum = _sha256(layer2_path)
        result = {
            "result": "ok",
            "image_id": payload["image_id"],
            "layer2_path": str(layer2_path),
            "base_image_path": str(base_image_path),
            "checksum_sha256": checksum,
            "size_bytes": layer2_path.stat().st_size,
            "built_at": datetime.now(UTC).isoformat(),
            "planned_commands": planned_commands,
            "idempotent": False,
            "dry_run": True,
            "builder_mode": "booted-vm",
        }
        _write_metadata(_meta_path(layer2_path), _layer2_image_metadata(payload, layer2_path, result))
        return result

    for tool in ("qemu-img", "qemu-nbd", "ssh"):
        _required_tool(tool)
    if not base_image_path.exists():
        raise FileNotFoundError(f"missing base image {base_image_path}")
    _require_kvm_device()

    _progress_log(config, action, subject_id, "build", "running", {"recipe_id": recipe["id"], "layer2_path": str(layer2_path), "builder_mode": "booted-vm"})
    try:
        cleanup_runtime()
        layer2_path.parent.mkdir(parents=True, exist_ok=True)
        build_layer3.parent.mkdir(parents=True, exist_ok=True)
        _run_progress_command(
            config,
            action,
            subject_id,
            "create build layer2",
            _layer2_create_command(payload, str(base_image_path), str(build_layer2), recipe),
        )
        _run_progress_command(
            config,
            action,
            subject_id,
            "create build layer3",
            ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(build_layer2), str(build_layer3), str(12 * 1024 * 1024 * 1024)],
        )
        ssh_public_key = _write_ephemeral_ssh_key(ssh_key_path)
        vm_payload = {
            "vm_id": build_vm_id,
            "namespace": "default",
            "network_id": network_id,
            "network_bridge": network_bridge,
            "vcpus": 2,
            "memory_mb": 2048,
            "reserved_ip": reserved_ip,
            "reserved_mac": reserved_mac,
            "layer2_path": str(build_layer2),
            "layer3_path": str(build_layer3),
            "ssh_public_key": ssh_public_key,
            "template_architecture": payload.get("template_architecture", "x86_64"),
            "template_boot_mode": payload.get("template_boot_mode", "disk"),
            "template_kernel_path": payload.get("template_kernel_path"),
            "template_initrd_path": payload.get("template_initrd_path"),
            "template_kernel_append": payload.get("template_kernel_append"),
        }
        _progress_log(config, action, subject_id, "prepare guest bootstrap", "running", {"vm_id": build_vm_id, "reserved_ip": reserved_ip})
        _prepare_layer3_guest_bootstrap(config, vm_payload)
        _progress_log(config, action, subject_id, "prepare guest bootstrap", "completed", {"vm_id": build_vm_id, "reserved_ip": reserved_ip})
        _write_runtime_xml(config, vm_payload)
        _run_progress_command(config, action, subject_id, "define build vm", ["virsh", "define", str(runtime_xml)])
        _run_progress_command(config, action, subject_id, "start build vm", ["virsh", "start", build_vm_id])
        booted = True
        _progress_log(config, action, subject_id, "wait for ssh", "running", {"ip_address": reserved_ip, "mac_address": reserved_mac})
        ssh_ip = _wait_for_build_ssh(config, action, subject_id, reserved_ip, reserved_mac, identity_file=ssh_key_path, timeout_s=360)
        _progress_log(config, action, subject_id, "wait for ssh", "completed", {"ip_address": ssh_ip, "reserved_ip": reserved_ip, "mac_address": reserved_mac})
        _progress_log(config, action, subject_id, "install layer2 recipe in guest", "running", {"ip_address": ssh_ip})
        try:
            _run_ssh_script(ssh_ip, _layer2_bootstrap_script(config, recipe), identity_file=ssh_key_path, timeout_s=3600)
            _run_ssh_script(ssh_ip, _layer2_cleanup_script(ssh_public_key), identity_file=ssh_key_path, timeout_s=300)
        except subprocess.CalledProcessError as exc:
            _progress_log(
                config,
                action,
                subject_id,
                "install layer2 recipe in guest",
                "failed",
                {
                    "ip_address": ssh_ip,
                    "returncode": exc.returncode,
                    "stdout": (exc.stdout or "")[-4000:],
                    "stderr": (exc.stderr or "")[-4000:],
                },
            )
            raise
        _progress_log(config, action, subject_id, "install layer2 recipe in guest", "completed", {"ip_address": ssh_ip})
        _progress_log(config, action, subject_id, "shutdown build vm", "running", {"vm_id": build_vm_id})
        _run_progress_command(config, action, subject_id, "shutdown build vm", ["virsh", "shutdown", build_vm_id], check=False)
        state = _wait_for_domain_state(build_vm_id, {"shut off", "shutdown", "no state"}, 180.0)
        if state not in {"shut off", "shutdown", "no state"}:
            raise RuntimeError(f"build vm {build_vm_id} failed to shut down, current state={state}")
        _progress_log(config, action, subject_id, "shutdown build vm", "completed", {"vm_id": build_vm_id})
        booted = False
        temp_target = layer2_path.with_name(f"{layer2_path.stem}.tmp-{datetime.now(UTC).timestamp():.0f}{layer2_path.suffix}")
        _run_progress_command(
            config,
            action,
            subject_id,
            "promote build layer3",
            [
                "qemu-img",
                "convert",
                "-f",
                "qcow2",
                "-O",
                "qcow2",
                "-B",
                str(base_image_path),
                "-F",
                payload.get("base_image_format", "raw"),
                str(build_layer3),
                str(temp_target),
            ],
        )
        if layer2_path.exists():
            layer2_path.unlink()
        shutil.move(str(temp_target), str(layer2_path))
        checksum = _sha256(layer2_path)
        result = {
            "result": "ok",
            "image_id": payload["image_id"],
            "layer2_path": str(layer2_path),
            "base_image_path": str(base_image_path),
            "checksum_sha256": checksum,
            "size_bytes": layer2_path.stat().st_size,
            "built_at": datetime.now(UTC).isoformat(),
            "planned_commands": planned_commands,
            "idempotent": False,
            "dry_run": False,
            "builder_mode": "booted-vm",
        }
        _write_metadata(_meta_path(layer2_path), _layer2_image_metadata(payload, layer2_path, result))
        _progress_log(config, action, subject_id, "build", "completed", {"layer2_path": str(layer2_path), "size_bytes": result["size_bytes"], "builder_mode": "booted-vm"})
        return result
    except Exception as exc:
        _progress_log(config, action, subject_id, "build", "failed", {"recipe_id": recipe["id"], "error": str(exc), "builder_mode": "booted-vm"})
        raise
    finally:
        if booted and not config.dry_run and _libvirt_available() and _domain_exists(build_vm_id):
            _virsh(["destroy", build_vm_id], check=False)
        cleanup_runtime()


def _build_layer2_image(config: AppConfig, payload: dict[str, Any], planned_commands: list[list[str]]) -> dict[str, Any]:
    recipe = payload["recipe"]
    if not recipe.get("builder_implemented"):
        raise NotImplementedError(f"builder is not implemented for layer2 recipe {recipe['id']}")
    if recipe["architecture"] != "amd64":
        raise ValueError("layer2 image builder currently supports amd64 recipes")
    if _layer2_booted_builder_enabled(recipe):
        return _build_layer2_image_booted(config, payload, planned_commands)

    base_image_path = _resolve(payload["base_image_path"])
    layer2_path = _resolve(payload["layer2_path"])
    _ensure_under(_resolve(str(config.storage.base_dir)), base_image_path)
    _ensure_under(_resolve(str(config.storage.layer2_dir)), layer2_path)
    if not base_image_path.exists():
        raise FileNotFoundError(f"missing base image {base_image_path}")

    if layer2_path.exists() and not payload.get("force"):
        checksum = _sha256(layer2_path)
        result = {
            "result": "ok",
            "image_id": payload["image_id"],
            "layer2_path": str(layer2_path),
            "base_image_path": str(base_image_path),
            "checksum_sha256": checksum,
            "size_bytes": layer2_path.stat().st_size,
            "built_at": datetime.now(UTC).isoformat(),
            "planned_commands": [],
            "idempotent": True,
            "dry_run": config.dry_run,
        }
        _write_metadata(_meta_path(layer2_path), _layer2_image_metadata(payload, layer2_path, result))
        return result

    if config.dry_run:
        layer2_path.parent.mkdir(parents=True, exist_ok=True)
        layer2_path.write_text(
            json.dumps({"format": "qcow2", "backing_file": str(base_image_path), "recipe_id": recipe["id"], "dry_run": True}, indent=2),
            encoding="utf-8",
        )
        checksum = _sha256(layer2_path)
        result = {
            "result": "ok",
            "image_id": payload["image_id"],
            "layer2_path": str(layer2_path),
            "base_image_path": str(base_image_path),
            "checksum_sha256": checksum,
            "size_bytes": layer2_path.stat().st_size,
            "built_at": datetime.now(UTC).isoformat(),
            "planned_commands": planned_commands,
            "idempotent": False,
            "dry_run": True,
        }
        _write_metadata(_meta_path(layer2_path), _layer2_image_metadata(payload, layer2_path, result))
        return result

    for tool in ("qemu-img", "virt-customize"):
        _required_tool(tool)
    tmp_layer2 = layer2_path.with_name(f"{layer2_path.name}.tmp-{int(time.time())}")
    action = "build-layer2-image"
    subject_id = payload.get("image_id")
    if tmp_layer2.exists():
        tmp_layer2.unlink()
    try:
        _progress_log(config, action, subject_id, "build", "running", {"recipe_id": recipe["id"], "layer2_path": str(layer2_path)})
        _run_progress_command(
            config,
            action,
            subject_id,
            "create layer2 qcow2",
            _layer2_create_command(payload, str(base_image_path), str(tmp_layer2), recipe),
        )
        customize_payload = {**payload, "layer2_path": str(tmp_layer2), "base_image_path": str(base_image_path)}
        if recipe.get("layer2_size_mb"):
            _progress_log(config, action, subject_id, "grow layer2 ext4 filesystem", "running", {"layer2_path": str(tmp_layer2), "layer2_size_mb": recipe.get("layer2_size_mb")})
            _grow_layer2_ext4(config, tmp_layer2)
            _progress_log(config, action, subject_id, "grow layer2 ext4 filesystem", "completed", {"layer2_path": str(tmp_layer2), "layer2_size_mb": recipe.get("layer2_size_mb")})
        _ensure_virt_customize_scratch_space()
        _run_progress_command(config, action, subject_id, "customize layer2 image", _layer2_customize_command(customize_payload))
        if layer2_path.exists():
            layer2_path.unlink()
        shutil.move(str(tmp_layer2), str(layer2_path))
        checksum = _sha256(layer2_path)
        result = {
            "result": "ok",
            "image_id": payload["image_id"],
            "layer2_path": str(layer2_path),
            "base_image_path": str(base_image_path),
            "checksum_sha256": checksum,
            "size_bytes": layer2_path.stat().st_size,
            "built_at": datetime.now(UTC).isoformat(),
            "planned_commands": planned_commands,
            "idempotent": False,
            "dry_run": False,
        }
        _write_metadata(_meta_path(layer2_path), _layer2_image_metadata(payload, layer2_path, result))
        _progress_log(config, action, subject_id, "build", "completed", {"layer2_path": str(layer2_path), "size_bytes": result["size_bytes"]})
        return result
    except Exception as exc:
        _progress_log(config, action, subject_id, "build", "failed", {"recipe_id": recipe["id"], "error": str(exc)})
        if tmp_layer2.exists():
            tmp_layer2.unlink()
        raise


def _virsh(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run_command(["virsh", *command], check=check)


def _libvirt_available() -> bool:
    if shutil.which("virsh") is None:
        return False
    result = _virsh(["list", "--all"], check=False)
    return result.returncode == 0


def _domain_exists(vm_id: str) -> bool:
    result = _virsh(["dominfo", vm_id], check=False)
    return result.returncode == 0


def _domain_state(vm_id: str) -> str | None:
    result = _virsh(["domstate", vm_id], check=False)
    if result.returncode != 0:
        return None
    output = result.stdout.strip().splitlines()
    if not output:
        return None
    return output[-1].strip().lower()


def _map_domain_state(domain_state: str | None) -> str:
    if domain_state in {"running", "idle", "in shutdown"}:
        return "running"
    if domain_state == "paused":
        return "paused"
    if domain_state in {"shut off", "shutdown", "no state"} or domain_state is None:
        return "stopped"
    if domain_state == "crashed":
        return "failed"
    if domain_state == "pmsuspended":
        return "paused"
    return "failed"


def _host_booted_at() -> str | None:
    try:
        for line in Path("/proc/stat").read_text(encoding="utf-8").splitlines():
            if line.startswith("btime "):
                return datetime.fromtimestamp(int(line.split()[1]), UTC).isoformat()
    except (OSError, ValueError, IndexError):
        return None
    return None


def _wait_for_domain_state(vm_id: str, expected: set[str], timeout_s: float) -> str | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = _domain_state(vm_id)
        if state in expected:
            return state
        time.sleep(1.0)
    return _domain_state(vm_id)


_STOPPED_DOMAIN_STATES = {"shut off", "shutdown", "no state", None}
_RUNNING_DOMAIN_STATES = {"running", "idle"}


def _require_kvm_device() -> None:
    kvm_device = Path("/dev/kvm")
    if not kvm_device.exists():
        raise RuntimeError("/dev/kvm is not available; KVM acceleration is required to start VMs")
    if not os.access(kvm_device, os.R_OK | os.W_OK):
        raise RuntimeError("/dev/kvm is not accessible to the root executor")


def _read_leases_for_mac(mac_address: str) -> str | None:
    lease_files = [
        Path("/var/lib/misc/dnsmasq.leases"),
        Path("/var/lib/libvirt/dnsmasq/default.leases"),
    ]
    matches: list[tuple[int, str]] = []
    for lease_file in lease_files:
        if not lease_file.exists():
            continue
        for line in lease_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            if parts[1].lower() == mac_address.lower():
                try:
                    expires = int(parts[0])
                except ValueError:
                    expires = 0
                matches.append((expires, parts[2]))
    if not matches:
        return None
    return max(matches)[1]


def _write_runtime_xml(config: AppConfig, payload: dict[str, Any]) -> Path:
    vm_id = payload["vm_id"]
    runtime_xml = _runtime_xml(config, vm_id)
    architecture = payload.get("template_architecture", "x86_64")
    machine_type = payload.get("template_machine_type", "pc-i440fx-10.0")
    boot_mode = payload.get("template_boot_mode", "disk")
    kernel_path = payload.get("template_kernel_path")
    initrd_path = payload.get("template_initrd_path")
    kernel_append = payload.get("template_kernel_append")
    layer3_format = payload.get("layer3_format", "qcow2")
    network_bridge = payload["network_bridge"]
    nested_virtualization = bool(payload.get("nested_virtualization"))
    cpu_lines = ["  <cpu mode='host-passthrough' check='none' migratable='on'/>"]
    if not nested_virtualization:
        cpu_lines = [
            "  <cpu mode='host-passthrough' check='none' migratable='on'>",
            "    <feature policy='disable' name='vmx'/>",
            "    <feature policy='disable' name='svm'/>",
            "  </cpu>",
        ]
    domain_lines = [
        "<domain type='kvm'>",
        f"  <name>{vm_id}</name>",
        f"  <memory unit='MiB'>{payload['memory_mb']}</memory>",
        f"  <vcpu placement='static'>{payload['vcpus']}</vcpu>",
        "  <os>",
        f"    <type arch='{architecture}' machine='{machine_type}'>hvm</type>",
    ]
    if boot_mode == "direct_kernel":
        if not kernel_path or not initrd_path:
            raise RuntimeError(f"template for {vm_id} requires kernel_path and initrd_path")
        domain_lines.extend(
            [
                f"    <kernel>{kernel_path}</kernel>",
                f"    <initrd>{initrd_path}</initrd>",
            ]
        )
        if kernel_append:
            domain_lines.append(f"    <cmdline>{kernel_append}</cmdline>")
    domain_lines.extend(
        [
            "    <boot dev='hd'/>",
            "  </os>",
            "  <features><acpi/><apic/></features>",
            *cpu_lines,
            "  <devices>",
            "    <emulator>/usr/bin/qemu-system-x86_64</emulator>",
            (
                "    <disk type='file' device='disk'>"
                f"<driver name='qemu' type='{layer3_format}'/>"
                f"<source file='{payload['layer3_path']}'/>"
                "<target dev='vda' bus='virtio'/>"
                "</disk>"
            ),
            (
                "    <interface type='bridge'>"
                f"<mac address='{payload['reserved_mac']}'/>"
                f"<source bridge='{network_bridge}'/>"
                "<model type='virtio'/>"
                "</interface>"
            ),
            "    <serial type='pty'><target port='0'/></serial>",
            "    <console type='pty'><target type='serial' port='0'/></console>",
            "  </devices>",
            "  <on_poweroff>destroy</on_poweroff>",
            "  <on_reboot>restart</on_reboot>",
            "  <on_crash>destroy</on_crash>",
            "</domain>",
            "",
        ]
    )
    runtime_xml.write_text("\n".join(domain_lines), encoding="utf-8")
    return runtime_xml


def _shell_value(value: object) -> str:
    return shlex.quote("" if value is None else str(value))


def _network_settings(config: AppConfig, network_id: str) -> tuple[str, int]:
    for segment in config.network.segments:
        if segment.id == network_id and segment.address:
            interface = ipaddress.ip_interface(segment.address)
            return str(interface.ip), int(interface.network.prefixlen)
    network = ipaddress.ip_network(config.network.cidr, strict=False)
    return config.network.gateway, int(network.prefixlen)


def _guest_netplan_config(mac: str, ip_address: str, prefix: int, gateway: str) -> str:
    return "\n".join(
        [
            "network:",
            "  version: 2",
            "  renderer: networkd",
            "  ethernets:",
            "    kvm-control:",
            "      match:",
            f"        macaddress: \"{mac}\"",
            "      dhcp4: false",
            f"      addresses: [{ip_address}/{prefix}]",
            "      routes:",
            "        - to: default",
            f"          via: {gateway}",
            "      nameservers:",
            f"        addresses: [{gateway}]",
            "",
        ]
    )


def _guest_systemd_bootstrap_unit() -> str:
    return """[Unit]
Description=kvm-control guest bootstrap
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target network.target ssh.service sshd.service
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/kvm-control-configure-network
ExecStart=/usr/local/sbin/kvm-control-grow-rootfs
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""


def _write_guest_bootstrap_script(config: AppConfig, payload: dict[str, Any]) -> Path:
    gateway, prefix = _network_settings(config, payload["network_id"])
    apt_http_proxy = config.guest_bootstrap.apt_http_proxy
    mac = str(payload["reserved_mac"]).lower()
    script_path = config.storage.webroot_dir / f"setup_2nd_stage.{mac}.sh"
    script_path.parent.mkdir(parents=True, exist_ok=True)
    env_text = "\n".join(
        [
            f"KVM_CONTROL_VM_ID={_shell_value(payload['vm_id'])}",
            f"KVM_CONTROL_NAMESPACE={_shell_value(payload['namespace'])}",
            f"KVM_CONTROL_NETWORK_ID={_shell_value(payload['network_id'])}",
            f"KVM_CONTROL_INTERFACE_MAC={_shell_value(mac)}",
            f"KVM_CONTROL_IPV4_ADDRESS={_shell_value(payload['reserved_ip'])}",
            f"KVM_CONTROL_IPV4_PREFIX={_shell_value(prefix)}",
            f"KVM_CONTROL_IPV4_GATEWAY={_shell_value(gateway)}",
            f"KVM_CONTROL_APT_HTTP_PROXY={_shell_value(apt_http_proxy or '')}",
        ]
    )
    netplan_text = _guest_netplan_config(mac, str(payload["reserved_ip"]), prefix, gateway)
    systemd_unit = _guest_systemd_bootstrap_unit()
    proxy_literal = shlex.quote(apt_http_proxy or "")
    script = f"""#!/bin/sh
set -eu

mkdir -p /etc/kvm-control /etc/cron.d /etc/apt/apt.conf.d /etc/netplan /etc/systemd/system/multi-user.target.wants /usr/local/sbin /var/log/kvm-control

cat >/etc/kvm-control/vm.env <<'EOF_KVM_CONTROL_ENV'
{env_text}
EOF_KVM_CONTROL_ENV
chmod 0644 /etc/kvm-control/vm.env

cat >/etc/netplan/01-kvm-control.yaml <<'EOF_KVM_CONTROL_NETPLAN'
{netplan_text}
EOF_KVM_CONTROL_NETPLAN
chmod 0644 /etc/netplan/01-kvm-control.yaml

if [ -n {proxy_literal} ]; then
    printf 'Acquire::http::Proxy "%s";\\n' {proxy_literal} >/etc/apt/apt.conf.d/80-proxy.conf
fi

cat >/usr/local/sbin/kvm-control-configure-network <<'EOF_KVM_CONTROL_NETWORK'
#!/bin/sh
set -eu

[ -r /etc/kvm-control/vm.env ] || exit 0
. /etc/kvm-control/vm.env

mac="$(printf '%s' "$KVM_CONTROL_INTERFACE_MAC" | tr 'A-F' 'a-f')"
iface=""
for path in /sys/class/net/*/address; do
    [ -r "$path" ] || continue
    found="$(cat "$path" | tr 'A-F' 'a-f')"
    if [ "$found" = "$mac" ]; then
        iface="${{path%/address}}"
        iface="${{iface##*/}}"
        break
    fi
done

[ -n "$iface" ] || exit 0

mkdir -p /etc/network/interfaces.d

cat >/etc/network/interfaces <<'EOF_INTERFACES'
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback
EOF_INTERFACES

cat >/etc/network/interfaces.d/kvm-control <<EOF_STATIC
allow-hotplug $iface
auto $iface
iface $iface inet static
    address $KVM_CONTROL_IPV4_ADDRESS/$KVM_CONTROL_IPV4_PREFIX
    gateway $KVM_CONTROL_IPV4_GATEWAY
EOF_STATIC

printf 'nameserver %s\\n' "$KVM_CONTROL_IPV4_GATEWAY" >/etc/resolv.conf

ip addr flush dev "$iface" || true
ip link set "$iface" up
ip addr add "$KVM_CONTROL_IPV4_ADDRESS/$KVM_CONTROL_IPV4_PREFIX" dev "$iface" 2>/dev/null || true
ip route replace default via "$KVM_CONTROL_IPV4_GATEWAY" dev "$iface" || true
if command -v netplan >/dev/null 2>&1; then
    netplan apply || true
fi
EOF_KVM_CONTROL_NETWORK
chmod 0755 /usr/local/sbin/kvm-control-configure-network

cat >/usr/local/sbin/kvm-control-grow-rootfs <<'EOF_KVM_CONTROL_GROW'
#!/bin/sh
set -eu

root_source="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
root_fstype="$(findmnt -n -o FSTYPE / 2>/dev/null || true)"

[ "$root_fstype" = "ext4" ] || exit 0
case "$root_source" in
    /dev/*) ;;
    *) exit 0 ;;
esac

disk_name="$(lsblk -no PKNAME "$root_source" 2>/dev/null | head -n1 | tr -d ' ')"
part_no="$(lsblk -no PARTN "$root_source" 2>/dev/null | head -n1 | tr -d ' ')"

if [ -z "$disk_name" ] && [ -z "$part_no" ]; then
    resize2fs "$root_source" || true
    exit 0
fi

[ -n "$disk_name" ] || exit 0
[ -n "$part_no" ] || exit 0
disk="/dev/$disk_name"

if command -v growpart >/dev/null 2>&1; then
    growpart "$disk" "$part_no" || true
elif command -v parted >/dev/null 2>&1; then
    parted -s "$disk" resizepart "$part_no" 100% || true
else
    exit 0
fi

partprobe "$disk" >/dev/null 2>&1 || blockdev --rereadpt "$disk" >/dev/null 2>&1 || true
resize2fs "$root_source" || true
EOF_KVM_CONTROL_GROW
chmod 0755 /usr/local/sbin/kvm-control-grow-rootfs

cat >/etc/cron.d/kvm-control <<'EOF_KVM_CONTROL_CRON'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

@reboot root /usr/local/sbin/kvm-control-configure-network >>/var/log/kvm-control/network.log 2>&1
@reboot root /usr/local/sbin/kvm-control-grow-rootfs >>/var/log/kvm-control/grow-rootfs.log 2>&1
EOF_KVM_CONTROL_CRON
chmod 0644 /etc/cron.d/kvm-control

cat >/etc/init.d/kvm-control <<'EOF_KVM_CONTROL_INIT'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          kvm-control
# Required-Start:    $remote_fs
# Default-Start:     S 2 3 4 5
# Short-Description: kvm-control guest bootstrap
### END INIT INFO

case "${{1:-start}}" in
    start|restart|force-reload)
        /usr/local/sbin/kvm-control-configure-network >>/var/log/kvm-control/network.log 2>&1 || true
        /usr/local/sbin/kvm-control-grow-rootfs >>/var/log/kvm-control/grow-rootfs.log 2>&1 || true
        ;;
    stop)
        ;;
esac
exit 0
EOF_KVM_CONTROL_INIT
chmod 0755 /etc/init.d/kvm-control
for runlevel_dir in /etc/rcS.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d; do
    mkdir -p "$runlevel_dir"
    ln -sf ../init.d/kvm-control "$runlevel_dir/S02kvm-control"
done
cat >/etc/systemd/system/kvm-control-bootstrap.service <<'EOF_KVM_CONTROL_SYSTEMD'
{systemd_unit}
EOF_KVM_CONTROL_SYSTEMD
chmod 0644 /etc/systemd/system/kvm-control-bootstrap.service
ln -sf ../kvm-control-bootstrap.service /etc/systemd/system/multi-user.target.wants/kvm-control-bootstrap.service

/usr/local/sbin/kvm-control-configure-network >>/var/log/kvm-control/network.log 2>&1 || true
/usr/local/sbin/kvm-control-grow-rootfs >>/var/log/kvm-control/grow-rootfs.log 2>&1 || true
"""
    script_path.write_text(script, encoding="utf-8")
    script_path.chmod(0o644)
    return script_path


def _guest_bootstrap_file_contents(config: AppConfig, payload: dict[str, Any]) -> dict[str, str]:
    gateway, prefix = _network_settings(config, payload["network_id"])
    apt_http_proxy = config.guest_bootstrap.apt_http_proxy or ""
    mac = str(payload["reserved_mac"]).lower()
    netplan_text = _guest_netplan_config(mac, str(payload["reserved_ip"]), prefix, gateway)
    env_text = "\n".join(
        [
            f"KVM_CONTROL_VM_ID={_shell_value(payload['vm_id'])}",
            f"KVM_CONTROL_NAMESPACE={_shell_value(payload['namespace'])}",
            f"KVM_CONTROL_NETWORK_ID={_shell_value(payload['network_id'])}",
            f"KVM_CONTROL_INTERFACE_MAC={_shell_value(mac)}",
            f"KVM_CONTROL_IPV4_ADDRESS={_shell_value(payload['reserved_ip'])}",
            f"KVM_CONTROL_IPV4_PREFIX={_shell_value(prefix)}",
            f"KVM_CONTROL_IPV4_GATEWAY={_shell_value(gateway)}",
            f"KVM_CONTROL_APT_HTTP_PROXY={_shell_value(apt_http_proxy)}",
        ]
    )
    network_script = """#!/bin/sh
set -eu

[ -r /etc/kvm-control/vm.env ] || exit 0
. /etc/kvm-control/vm.env

mac="$(printf '%s' "$KVM_CONTROL_INTERFACE_MAC" | tr 'A-F' 'a-f')"
iface=""
for path in /sys/class/net/*/address; do
    [ -r "$path" ] || continue
    found="$(cat "$path" | tr 'A-F' 'a-f')"
    if [ "$found" = "$mac" ]; then
        iface="${path%/address}"
        iface="${iface##*/}"
        break
    fi
done

[ -n "$iface" ] || exit 0

mkdir -p /etc/network/interfaces.d

cat >/etc/network/interfaces <<'EOF_INTERFACES'
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback
EOF_INTERFACES

cat >/etc/network/interfaces.d/kvm-control <<EOF_STATIC
allow-hotplug $iface
auto $iface
iface $iface inet static
    address $KVM_CONTROL_IPV4_ADDRESS/$KVM_CONTROL_IPV4_PREFIX
    gateway $KVM_CONTROL_IPV4_GATEWAY
EOF_STATIC

printf 'nameserver %s\\n' "$KVM_CONTROL_IPV4_GATEWAY" >/etc/resolv.conf

ip addr flush dev "$iface" || true
ip link set "$iface" up
ip addr add "$KVM_CONTROL_IPV4_ADDRESS/$KVM_CONTROL_IPV4_PREFIX" dev "$iface" 2>/dev/null || true
ip route replace default via "$KVM_CONTROL_IPV4_GATEWAY" dev "$iface" || true
if command -v netplan >/dev/null 2>&1; then
    netplan apply || true
fi
"""
    grow_script = """#!/bin/sh
set -eu

root_source="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
root_fstype="$(findmnt -n -o FSTYPE / 2>/dev/null || true)"

[ "$root_fstype" = "ext4" ] || exit 0
case "$root_source" in
    /dev/*) ;;
    *) exit 0 ;;
esac

disk_name="$(lsblk -no PKNAME "$root_source" 2>/dev/null | head -n1 | tr -d ' ')"
part_no="$(lsblk -no PARTN "$root_source" 2>/dev/null | head -n1 | tr -d ' ')"

if [ -z "$disk_name" ] && [ -z "$part_no" ]; then
    resize2fs "$root_source" || true
    exit 0
fi

[ -n "$disk_name" ] || exit 0
[ -n "$part_no" ] || exit 0
disk="/dev/$disk_name"

if command -v growpart >/dev/null 2>&1; then
    growpart "$disk" "$part_no" || true
elif command -v parted >/dev/null 2>&1; then
    parted -s "$disk" resizepart "$part_no" 100% || true
else
    exit 0
fi

partprobe "$disk" >/dev/null 2>&1 || blockdev --rereadpt "$disk" >/dev/null 2>&1 || true
resize2fs "$root_source" || true
"""
    cron = """SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

@reboot root /usr/local/sbin/kvm-control-configure-network >>/var/log/kvm-control/network.log 2>&1
@reboot root /usr/local/sbin/kvm-control-grow-rootfs >>/var/log/kvm-control/grow-rootfs.log 2>&1
"""
    init_script = """#!/bin/sh
### BEGIN INIT INFO
# Provides:          kvm-control
# Required-Start:    $remote_fs
# Default-Start:     S 2 3 4 5
# Short-Description: kvm-control guest bootstrap
### END INIT INFO

case "${1:-start}" in
    start|restart|force-reload)
        /usr/local/sbin/kvm-control-configure-network >>/var/log/kvm-control/network.log 2>&1 || true
        /usr/local/sbin/kvm-control-grow-rootfs >>/var/log/kvm-control/grow-rootfs.log 2>&1 || true
        ;;
    stop)
        ;;
esac
exit 0
"""
    apt_proxy = f'Acquire::http::Proxy "{apt_http_proxy}";\n' if apt_http_proxy else ""
    return {
        "/etc/kvm-control/vm.env": env_text + "\n",
        "/etc/apt/apt.conf.d/80-proxy.conf": apt_proxy,
        "/etc/netplan/01-kvm-control.yaml": netplan_text,
        "/usr/local/sbin/kvm-control-configure-network": network_script,
        "/usr/local/sbin/kvm-control-grow-rootfs": grow_script,
        "/etc/systemd/system/kvm-control-bootstrap.service": _guest_systemd_bootstrap_unit(),
        "/etc/cron.d/kvm-control": cron,
        "/etc/init.d/kvm-control": init_script,
        "/etc/rcS.d/S02kvm-control": init_script,
        "/etc/rc2.d/S02kvm-control": init_script,
        "/etc/rc3.d/S02kvm-control": init_script,
        "/etc/rc4.d/S02kvm-control": init_script,
        "/etc/rc5.d/S02kvm-control": init_script,
    }


def _write_guest_bootstrap_files(root: Path, config: AppConfig, payload: dict[str, Any]) -> None:
    for relative, content in _guest_bootstrap_file_contents(config, payload).items():
        target = root / relative.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        if relative.startswith("/usr/local/sbin/") or relative.startswith("/etc/init.d/") or relative.startswith("/etc/rc"):
            target.chmod(0o755)
        else:
            target.chmod(0o644)
    systemd_wants = root / "etc/systemd/system/multi-user.target.wants"
    systemd_wants.mkdir(parents=True, exist_ok=True)
    systemd_link = systemd_wants / "kvm-control-bootstrap.service"
    if systemd_link.exists() or systemd_link.is_symlink():
        systemd_link.unlink()
    os.symlink("../kvm-control-bootstrap.service", systemd_link)
    (root / "var/log/kvm-control").mkdir(parents=True, exist_ok=True)


def _append_guest_ssh_public_key(root: Path, ssh_public_key: str | None) -> bool:
    if not ssh_public_key:
        return False
    key = ssh_public_key.strip()
    if "\n" in key or "\r" in key:
        raise ValueError("ssh_public_key must be a single public key line")
    ssh_dir = root / "root/.ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    authorized_keys = ssh_dir / "authorized_keys"
    existing = authorized_keys.read_text(encoding="utf-8") if authorized_keys.exists() else ""
    if key not in existing.splitlines():
        with authorized_keys.open("a", encoding="utf-8") as handle:
            if existing and not existing.endswith("\n"):
                handle.write("\n")
            handle.write(f"{key}\n")
    os.chmod(ssh_dir, 0o700)
    os.chmod(authorized_keys, 0o600)
    return True


def _find_free_nbd() -> str | None:
    for index in range(16):
        name = f"nbd{index}"
        if not Path(f"/sys/block/{name}").exists():
            continue
        if not Path(f"/sys/block/{name}/pid").exists():
            return f"/dev/{name}"
    return None


def _blkid_type(device: str) -> str | None:
    result = _run_command(["blkid", "-o", "value", "-s", "TYPE", device], check=False)
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _mountable_root_device(nbd_device: str) -> str:
    _run_command(["partprobe", nbd_device], check=False)
    time.sleep(0.5)
    candidates = [f"{nbd_device}p1", nbd_device]
    for candidate in candidates:
        if Path(candidate).exists() and _blkid_type(candidate) == "ext4":
            return candidate
    raise RuntimeError(f"no ext4 root filesystem found on {nbd_device}")


def _prepare_layer3_guest_bootstrap(config: AppConfig, payload: dict[str, Any]) -> dict[str, Any]:
    layer3_path = Path(payload["layer3_path"])
    if config.dry_run:
        return {"prepared": True, "dry_run": True, "mode": "layer3"}
    if not layer3_path.exists():
        raise FileNotFoundError(f"missing layer3 {layer3_path}")
    try:
        with layer3_path.open("r", encoding="utf-8", errors="ignore") as handle:
            if handle.read(1) == "{":
                return {"prepared": False, "mode": "test-stub", "layer3_path": str(layer3_path)}
    except OSError:
        pass
    qemu_nbd = shutil.which("qemu-nbd")
    if qemu_nbd is None:
        raise RuntimeError("qemu-nbd is required to prepare guest bootstrap in layer3")
    _run_command(["modprobe", "nbd", "max_part=16"], check=False)
    nbd_device = _find_free_nbd()
    if nbd_device is None:
        raise RuntimeError("no free nbd device available for layer3 guest bootstrap")
    mount_dir = Path(tempfile.mkdtemp(prefix="kvm-control-layer3-"))
    mounted = False
    connected = False
    try:
        _run_command([qemu_nbd, "--connect", nbd_device, str(layer3_path)])
        connected = True
        root_device = _mountable_root_device(nbd_device)
        _run_command(["mount", "-o", "rw", root_device, str(mount_dir)])
        mounted = True
        _write_guest_bootstrap_files(mount_dir, config, payload)
        authorized_keys_path = _resolve(str(payload.get("authorized_keys_path") or config.image_factory.authorized_keys_path))
        host_authorized_keys_copied = _copy_authorized_keys(authorized_keys_path, mount_dir)
        host_identity_keys_available = _append_host_ssh_identity_public_keys(mount_dir)
        ssh_key_added = _append_guest_ssh_public_key(mount_dir, payload.get("ssh_public_key"))
        return {
            "prepared": True,
            "mode": "layer3",
            "layer3_path": str(layer3_path),
            "root_device": root_device,
            "host_authorized_keys_copied": host_authorized_keys_copied,
            "host_identity_keys_available": host_identity_keys_available,
            "ssh_public_key_added": ssh_key_added,
        }
    finally:
        if mounted:
            _run_command(["umount", str(mount_dir)], check=False)
        if connected:
            _run_command([qemu_nbd, "--disconnect", nbd_device], check=False)
        try:
            mount_dir.rmdir()
        except OSError:
            pass


def _planned_commands(config: AppConfig, action: str, payload: dict[str, Any]) -> list[list[str]]:
    commands: list[list[str]] = []
    if action == "wait-ssh":
        commands.append(
            [
                "ssh",
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "ControlMaster=no",
                "-o",
                "ControlPath=none",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=10",
                f"root@{payload['reserved_ip']}",
                "printf kvm-control-ssh-ready",
            ]
        )
        return commands
    if action == "build-base-image":
        return _planned_base_image_commands(config, payload)
    if action == "build-layer2-image":
        if _layer2_booted_builder_enabled(payload["recipe"]):
            return _planned_booted_layer2_image_commands(config, payload)
        return _planned_layer2_image_commands(config, payload)
    if action in {"cleanup-after-boot", "cleanup-trash"}:
        ttl_seconds = int(payload.get("ttl_seconds", config.cleanup.trash_file_ttl_seconds))
        commands.append(
            [
                "find",
                str(config.storage.trash_dir),
                "-maxdepth",
                "1",
                "-type",
                "f",
                "-mmin",
                f"+{max(0, ttl_seconds) // 60}",
                "-delete",
            ]
        )
        return commands
    if action == "reconcile-runtime":
        commands.append(["reconcile-runtime-state"])
        return commands
    vm_id = payload["vm_id"]
    layer2_path = payload["layer2_path"]
    layer3_path = payload["layer3_path"]
    if action == "create-layer2":
        commands.append(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                payload.get("base_image_format", "qcow2"),
                "-b",
                payload["base_image"],
                layer2_path,
            ]
        )
    elif action == "create-layer3":
        command = [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            layer2_path,
            layer3_path,
        ]
        if "layer3_size_mb" in payload:
            command.append(str(int(payload["layer3_size_mb"]) * 1024 * 1024))
        commands.append(command)
    elif action == "resize-layer3":
        commands.append(
            [
                "qemu-img",
                "resize",
                layer3_path,
                str(int(payload["new_virtual_size_mb"]) * 1024 * 1024),
            ]
        )
    elif action == "convert-layer3-to-layer2":
        commands.append(
            [
                "qemu-img",
                "convert",
                "-f",
                "qcow2",
                "-O",
                "qcow2",
                "-B",
                payload["base_image"],
                "-F",
                payload.get("base_image_format", "qcow2"),
                layer3_path,
                payload["target_layer2_path"],
            ]
        )
    elif action == "start-vm":
        runtime_xml = str(_runtime_xml(config, vm_id))
        commands.extend([["virsh", "define", runtime_xml], ["virsh", "start", vm_id]])
    elif action == "poweroff-vm":
        commands.append(["virsh", "destroy", vm_id])
    elif action == "stop-vm":
        commands.append(["virsh", "shutdown", vm_id])
    elif action == "pause-vm":
        commands.append(["virsh", "suspend", vm_id])
    elif action == "resume-vm":
        commands.append(["virsh", "resume", vm_id])
    elif action == "restart-vm":
        commands.extend([["virsh", "reboot", vm_id]])
    elif action == "inspect-vm":
        commands.append(["virsh", "domstate", vm_id])
    elif action in {"delete-layer3", "revert-vm"}:
        trashed = str(config.storage.trash_dir / f"{vm_id}-TIMESTAMP.qcow2")
        commands.append(["mv", layer3_path, trashed])
        if action == "revert-vm":
            commands.append(
                [
                    "qemu-img",
                    "create",
                    "-f",
                    "qcow2",
                    "-F",
                    "qcow2",
                    "-b",
                    layer2_path,
                    layer3_path,
                ]
            )
    elif action == "delete-layer2":
        trashed = str(config.storage.trash_dir / f"{vm_id}-layer2-TIMESTAMP.qcow2")
        commands.append(["mv", layer2_path, trashed])
    elif action == "publish-image":
        if payload.get("remote_backend") == "rsync":
            commands.append(["rsync", "-aS", "--mkpath", payload["source_layer2_path"], payload["remote_path"]])
            commands.append(["rsync", "-aS", "--mkpath", "LOCAL_META_FILE", f"{payload['remote_path']}.meta"])
            commands.append(["rsync", "--list-only", payload["remote_path"]])
        else:
            commands.append(["cp", payload["source_layer2_path"], payload["remote_path"]])
            commands.append(["write-image-meta", payload["remote_path"]])
    elif action == "fetch-image":
        if payload.get("remote_backend") == "rsync":
            commands.append(["rsync", "--list-only", payload["remote_path"]])
            commands.append(["rsync", "-aS", payload["remote_path"], payload["local_path"]])
            commands.append(["rsync", "-aS", f"{payload['remote_path']}.meta", f"{payload['local_path']}.meta"])
            commands.append(["write-image-meta", payload["local_path"]])
        else:
            commands.append(["cp", payload["remote_path"], payload["local_path"]])
            commands.append(["write-image-meta", payload["local_path"]])
    elif action == "retire-image":
        trashed = str(config.storage.trash_dir / f"{payload['image_id']}-TIMESTAMP.qcow2")
        commands.append(["mv", payload["local_path"], trashed])
        commands.append(["rm", "-f", str(_meta_path(Path(payload["local_path"])))])
    elif action == "delete-image":
        trashed = str(config.storage.trash_dir / f"{payload['image_id']}-delete-TIMESTAMP.qcow2")
        commands.append(["mv", payload["local_path"], trashed])
        if payload.get("remote_backend") == "rsync":
            commands.append(["rsync", "-a", "--delete", "EMPTY_DIR/", _rsync_parent_uri(payload["remote_path"])])
            commands.append(["rsync", "--list-only", payload["remote_path"]])
        else:
            commands.append(["rm", "-f", payload["remote_path"]])
            commands.append(["rm", "-f", str(_meta_path(Path(payload["local_path"]))), str(_meta_path(Path(payload["remote_path"])))])
    elif action == "sync-firewall-ipset":
        commands.append(["ipset", "create", payload["ipset_name"], "hash:net", "family", "inet", "-exist"])
        commands.append(["ipset", "flush", payload["ipset_name"]])
        for entry in payload.get("entries", []):
            commands.append(["ipset", "add", payload["ipset_name"], entry, "-exist"])
    elif action == "sync-firewall-egress":
        commands.append(["ipset", "create", payload.get("ipset_name", "kvmEgressAnyV4"), "hash:net", "family", "inet", "-exist"])
        commands.append(["ipset", "flush", payload.get("ipset_name", "kvmEgressAnyV4")])
        for entry in payload.get("entries", []):
            commands.append(["ipset", "add", payload.get("ipset_name", "kvmEgressAnyV4"), entry, "-exist"])
    elif action == "sync-firewall-ingress":
        commands.append(["ipset", "create", payload.get("ipset_name", "kvmIngressAnyV4"), "hash:net", "family", "inet", "-exist"])
        commands.append(["ipset", "flush", payload.get("ipset_name", "kvmIngressAnyV4")])
        for entry in payload.get("entries", []):
            commands.append(["ipset", "add", payload.get("ipset_name", "kvmIngressAnyV4"), entry, "-exist"])
    elif action == "delete-runtime":
        commands.append(["rm", "-f", str(_runtime_json(config, vm_id)), str(_runtime_xml(config, vm_id))])
    return commands


def handle_request(config: AppConfig, action: str, payload: dict[str, Any]) -> dict[str, Any]:
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"unsupported action {action}")

    storage = config.storage
    for path in (storage.base_dir, storage.layer2_dir, storage.layer3_dir, storage.image_remote_dir, storage.trash_dir, storage.runtime_dir):
        path.mkdir(parents=True, exist_ok=True)

    if action == "get-host-capacity":
        return {
            "vm_cpu_set": config.host.vm_cpu_set,
            "max_vms": config.host.max_vms,
            "max_total_vcpus": config.host.max_total_vcpus,
            "max_total_memory_mb": config.host.max_total_memory_mb,
        }

    if action == "wait-ssh":
        planned_commands = _planned_commands(config, action, payload)
        _command_log(config, action, payload.get("vm_id"), planned_commands)
        reserved_ip = str(payload["reserved_ip"])
        timeout_s = int(payload.get("timeout_s", 15))
        if config.dry_run:
            return {
                "result": "ok",
                "reserved_ip": reserved_ip,
                "readiness_probe": "root_ssh_command",
                "ssh_login_verified": True,
                "scp_verified": False,
                "planned_commands": planned_commands,
                "dry_run": True,
            }
        completed = _run_ssh(reserved_ip, "printf kvm-control-ssh-ready", timeout_s=timeout_s, check=False)
        output = (completed.stdout or "").strip()
        verified = completed.returncode == 0 and output == "kvm-control-ssh-ready"
        response = {
            "result": "ok" if verified else "not-ready",
            "reserved_ip": reserved_ip,
            "readiness_probe": "root_ssh_command",
            "ssh_login_verified": verified,
            "scp_verified": False,
            "planned_commands": planned_commands,
            "dry_run": False,
        }
        if not verified:
            response["error"] = (completed.stderr or completed.stdout or f"ssh exited {completed.returncode}").strip()
            response["returncode"] = completed.returncode
        return response

    if action in {"cleanup-after-boot", "cleanup-trash"}:
        planned_commands = _planned_commands(config, action, payload)
        _command_log(config, action, "host", planned_commands)
        ttl_seconds = int(payload.get("ttl_seconds", config.cleanup.trash_file_ttl_seconds))
        if ttl_seconds <= 0:
            return {
                "result": "ok",
                "deleted_files": [],
                "failed_files": [],
                "skipped": "disabled",
                "ttl_seconds": ttl_seconds,
                "planned_commands": planned_commands,
                "dry_run": config.dry_run,
            }
        cutoff = time.time() - ttl_seconds
        deleted_files: list[str] = []
        failed_files: list[dict[str, str]] = []
        for candidate in storage.trash_dir.iterdir():
            try:
                if not candidate.is_file():
                    continue
                if candidate.stat().st_mtime > cutoff:
                    continue
                if not config.dry_run:
                    candidate.unlink()
                deleted_files.append(str(candidate))
            except OSError as exc:
                failed_files.append({"path": str(candidate), "error": str(exc)})
        return {
            "result": "ok",
            "deleted_files": deleted_files,
            "failed_files": failed_files,
            "ttl_seconds": ttl_seconds,
            "planned_commands": planned_commands,
            "dry_run": config.dry_run,
        }

    if action == "reconcile-runtime":
        planned_commands = _planned_commands(config, action, payload)
        _command_log(config, action, "host", planned_commands)
        tracked = set(payload.get("tracked_vm_ids", []))
        deleted = 0
        for runtime in storage.runtime_dir.glob("*.json"):
            if runtime.stem not in tracked:
                runtime.unlink()
                deleted += 1
        for runtime_xml in storage.runtime_dir.glob("*.xml"):
            if runtime_xml.stem not in tracked:
                runtime_xml.unlink()
        return {"result": "ok", "deleted_runtime_files": deleted, "planned_commands": planned_commands, "dry_run": config.dry_run}

    if action == "build-base-image":
        planned_commands = _planned_commands(config, action, payload)
        _command_log(config, action, payload.get("image_id"), planned_commands)
        return _build_debootstrap_image(config, payload, planned_commands)

    if action == "build-layer2-image":
        planned_commands = _planned_commands(config, action, payload)
        _command_log(config, action, payload.get("image_id"), planned_commands)
        return _build_layer2_image(config, payload, planned_commands)

    if action in {"publish-image", "fetch-image", "retire-image", "delete-image"}:
        image_id = payload["image_id"]
        local_path = _resolve(payload["local_path"])
        remote_path_value = payload["remote_path"]
        remote_backend = payload.get("remote_backend") or "local"
        remote_timeout_s = int(payload.get("remote_timeout_s", 30))
        planned_commands = _planned_commands(config, action, payload)
        _command_log(config, action, image_id, planned_commands)
        _ensure_under(_resolve(str(storage.layer2_dir)), local_path)
        if remote_backend == "local":
            remote_path = _resolve(remote_path_value)
            try:
                _ensure_under(_resolve(str(storage.image_remote_dir)), remote_path)
            except ValueError:
                _ensure_under(_resolve(str(storage.layer2_dir)), remote_path)
        elif remote_backend == "rsync":
            remote_path = remote_path_value
            _parse_rsync_uri(remote_path)
        else:
            raise ValueError(f"unsupported remote backend {remote_backend}")
        metadata = dict(payload.get("metadata", {}))
        metadata.update(
            {
                "image_id": image_id,
                "local_path": str(local_path),
                "remote_path": str(remote_path),
                "remote_backend": remote_backend,
            }
        )

        if action == "publish-image":
            source_layer2 = _resolve(payload["source_layer2_path"])
            _ensure_under(_resolve(str(storage.layer2_dir)), source_layer2)
            if not source_layer2.exists():
                raise FileNotFoundError(f"missing promoted layer2 {source_layer2}")
            checksum = _sha256(source_layer2)
            size_bytes = source_layer2.stat().st_size
            metadata.update({"checksum_sha256": checksum, "size_bytes": size_bytes})
            _write_metadata(_meta_path(source_layer2), metadata)
            if remote_backend == "local":
                _copy_or_stub(source_layer2, remote_path, config.dry_run)
                _write_metadata(_meta_path(remote_path), metadata)
                remote_verified = remote_path.exists()
            else:
                with tempfile.TemporaryDirectory() as tmpdir:
                    meta_file = Path(tmpdir) / f"{image_id}.meta"
                    _write_metadata(meta_file, metadata)
                    _rsync_put_file(source_layer2, remote_path, remote_timeout_s)
                    _rsync_put_file(meta_file, _rsync_meta_uri(remote_path), remote_timeout_s)
                remote_verified = _rsync_exists(remote_path, remote_timeout_s) and _rsync_exists(_rsync_meta_uri(remote_path), remote_timeout_s)
            return {
                "result": "ok",
                "local_path": str(source_layer2),
                "remote_path": str(remote_path),
                "remote_backend": remote_backend,
                "remote_verified": remote_verified,
                "checksum_sha256": checksum,
                "size_bytes": size_bytes,
                "published_at": datetime.now(UTC).isoformat(),
                "planned_commands": planned_commands,
                "dry_run": config.dry_run,
            }

        if action == "fetch-image":
            if remote_backend == "local":
                if not remote_path.exists():
                    raise FileNotFoundError(f"missing remote image {remote_path}")
                _copy_or_stub(remote_path, local_path, config.dry_run)
                remote_verified = remote_path.exists()
            else:
                if not _rsync_exists(remote_path, remote_timeout_s):
                    raise FileNotFoundError(f"missing remote image {remote_path}")
                _rsync_get_file(remote_path, local_path, remote_timeout_s)
                remote_meta_uri = _rsync_meta_uri(remote_path)
                if _rsync_exists(remote_meta_uri, remote_timeout_s):
                    _rsync_get_file(remote_meta_uri, _meta_path(local_path), remote_timeout_s)
                remote_verified = True
            size_bytes = local_path.stat().st_size
            checksum = _sha256(local_path)
            metadata.update({"checksum_sha256": checksum, "size_bytes": size_bytes})
            _write_metadata(_meta_path(local_path), metadata)
            return {
                "result": "ok",
                "local_path": str(local_path),
                "remote_path": str(remote_path),
                "remote_backend": remote_backend,
                "remote_verified": remote_verified,
                "checksum_sha256": checksum,
                "size_bytes": size_bytes,
                "fetched_at": datetime.now(UTC).isoformat(),
                "planned_commands": planned_commands,
                "dry_run": config.dry_run,
            }

        if action == "retire-image":
            if local_path.exists():
                trashed = _resolve(str(storage.trash_dir / f"{image_id}-{datetime.now(UTC).timestamp():.0f}.qcow2"))
                shutil.move(str(local_path), str(trashed))
                meta_path = _meta_path(local_path)
                if meta_path.exists():
                    meta_path.unlink()
                return {
                    "result": "ok",
                    "trashed_path": str(trashed),
                    "remote_backend": remote_backend,
                    "retired_at": datetime.now(UTC).isoformat(),
                    "planned_commands": planned_commands,
                    "dry_run": config.dry_run,
                }
            return {
                "result": "ok",
                "missing": True,
                "remote_backend": remote_backend,
                "retired_at": datetime.now(UTC).isoformat(),
                "planned_commands": planned_commands,
                "dry_run": config.dry_run,
            }

        deleted_local = False
        deleted_remote = False
        if local_path.exists():
            trashed = _resolve(str(storage.trash_dir / f"{image_id}-delete-{datetime.now(UTC).timestamp():.0f}.qcow2"))
            shutil.move(str(local_path), str(trashed))
            deleted_local = True
        else:
            trashed = None
        local_meta = _meta_path(local_path)
        if local_meta.exists():
            local_meta.unlink()
        if remote_backend == "local":
            if remote_path == local_path:
                deleted_remote = deleted_local or not remote_path.exists()
            elif remote_path.exists():
                remote_path.unlink()
                deleted_remote = True
            remote_meta = _meta_path(remote_path)
            if remote_meta.exists():
                remote_meta.unlink()
            remote_verified = not remote_path.exists()
        else:
            _rsync_delete_image_dir(remote_path, remote_timeout_s)
            deleted_remote = not _rsync_exists(remote_path, remote_timeout_s) and not _rsync_exists(_rsync_meta_uri(remote_path), remote_timeout_s)
            remote_verified = deleted_remote
        return {
            "result": "ok",
            "deleted_local": deleted_local,
            "deleted_remote": deleted_remote,
            "remote_backend": remote_backend,
            "remote_verified": remote_verified,
            "trashed_path": str(trashed) if trashed else None,
            "deleted_at": datetime.now(UTC).isoformat(),
            "planned_commands": planned_commands,
            "dry_run": config.dry_run,
        }

    if action in {"sync-firewall-ipset", "sync-firewall-egress", "sync-firewall-ingress"}:
        planned_commands = _planned_commands(config, action, payload)
        _command_log(config, action, payload.get("vm_id"), planned_commands)
        if action == "sync-firewall-egress":
            default_ipset_name = "kvmEgressAnyV4"
            state_file_name = "firewall-egress.json"
        elif action == "sync-firewall-ingress":
            default_ipset_name = "kvmIngressAnyV4"
            state_file_name = "firewall-ingress.json"
        else:
            default_ipset_name = payload["ipset_name"]
            state_file_name = f"{default_ipset_name}.json"
        ipset_name = payload.get("ipset_name", default_ipset_name)
        entries = [str(entry) for entry in payload.get("entries", [])]
        state_file = config.storage.state_dir / state_file_name
        if config.dry_run or shutil.which("ipset") is None:
            state_file.write_text(json.dumps({"ipset_name": ipset_name, "entries": entries, "dry_run": config.dry_run}, indent=2), encoding="utf-8")
            return {"result": "ok", "ipset_name": ipset_name, "entries": entries, "state_file": str(state_file), "planned_commands": planned_commands, "dry_run": config.dry_run}
        current_type: str | None = None
        info = subprocess.run(["ipset", "list", ipset_name], check=False, capture_output=True, text=True)
        if info.returncode == 0:
            for line in info.stdout.splitlines():
                if line.startswith("Type: "):
                    current_type = line.split(":", 1)[1].strip()
                    break
        elif info.returncode != 1:
            raise RuntimeError(info.stderr.strip() or info.stdout.strip() or f"ipset list {ipset_name} failed")
        if current_type is not None and current_type not in {"hash:net", "hash:ip"}:
            raise RuntimeError(f"ipset {ipset_name} has type {current_type}, expected hash:net or hash:ip")
        if current_type == "hash:ip":
            invalid = [entry for entry in entries if "/" in entry and not entry.endswith("/32")]
            if invalid:
                raise RuntimeError(f"ipset {ipset_name} uses hash:ip and cannot accept network entries {invalid}; migrate it to hash:net")
        if current_type is None:
            subprocess.run(["ipset", "create", ipset_name, "hash:net", "family", "inet", "-exist"], check=True, capture_output=True, text=True)
        subprocess.run(["ipset", "flush", ipset_name], check=True, capture_output=True, text=True)
        for entry in entries:
            subprocess.run(["ipset", "add", ipset_name, entry, "-exist"], check=True, capture_output=True, text=True)
        state_file.write_text(json.dumps({"ipset_name": ipset_name, "entries": entries}, indent=2), encoding="utf-8")
        return {"result": "ok", "ipset_name": ipset_name, "entries": entries, "state_file": str(state_file), "planned_commands": planned_commands, "dry_run": config.dry_run}

    vm_id = payload["vm_id"]
    layer2_path = _resolve(payload["layer2_path"])
    layer3_path = _resolve(payload["layer3_path"])
    planned_commands = _planned_commands(config, action, payload)
    _command_log(config, action, vm_id, planned_commands)
    for root, path in (
        (_resolve(str(storage.layer2_dir)), layer2_path),
        (_resolve(str(storage.layer3_dir)), layer3_path),
    ):
        _ensure_under(root, path)

    if action == "create-layer2":
        if not layer2_path.exists():
            base_image = _resolve(payload["base_image"])
            _ensure_under(_resolve(str(storage.base_dir)), base_image)
            if not base_image.exists():
                raise FileNotFoundError(f"missing base image {base_image}")
            _touch_qcow(
                layer2_path,
                backing_file=str(base_image),
                backing_format=payload.get("base_image_format", "qcow2"),
                dry_run=config.dry_run,
            )
        return {"result": "ok", "layer2_path": str(layer2_path), "planned_commands": planned_commands, "dry_run": config.dry_run}

    if action == "create-layer3":
        layer3_path.parent.mkdir(parents=True, exist_ok=True)
        if not layer2_path.exists():
            raise FileNotFoundError(f"missing layer2 {layer2_path}")
        if layer3_path.exists():
            return {"result": "ok", "layer3_path": str(layer3_path), "already_present": True, "planned_commands": planned_commands, "dry_run": config.dry_run}
        layer3_size_mb = payload.get("layer3_size_mb")
        virtual_size_bytes = int(layer3_size_mb) * 1024 * 1024 if layer3_size_mb is not None else _qcow_virtual_size_bytes(layer2_path)
        _touch_qcow(layer3_path, backing_file=str(layer2_path), virtual_size_bytes=virtual_size_bytes, dry_run=config.dry_run)
        return {"result": "ok", "layer3_path": str(layer3_path), "planned_commands": planned_commands, "dry_run": config.dry_run}

    if action == "resize-layer3":
        if not layer3_path.exists():
            raise FileNotFoundError(f"missing layer3 {layer3_path}")
        new_virtual_size_mb = int(payload["new_virtual_size_mb"])
        new_virtual_size_bytes = new_virtual_size_mb * 1024 * 1024
        current_virtual_size_bytes = _qcow_virtual_size_bytes(layer3_path)
        if new_virtual_size_bytes <= current_virtual_size_bytes:
            raise ValueError(
                f"requested layer3 size {new_virtual_size_mb} MiB must be larger than current size "
                f"{current_virtual_size_bytes // (1024 * 1024)} MiB"
            )
        if not config.dry_run and _libvirt_available() and _domain_exists(vm_id):
            state = _domain_state(vm_id)
            if state not in {"shut off", "shutdown", "no state"}:
                raise ValueError(f"vm must be stopped before resizing layer3, current state={state}")
        _resize_qcow(layer3_path, new_virtual_size_bytes, dry_run=config.dry_run)
        return {
            "result": "ok",
            "layer3_path": str(layer3_path),
            "previous_virtual_size_bytes": current_virtual_size_bytes,
            "new_virtual_size_bytes": new_virtual_size_bytes,
            "planned_commands": planned_commands,
            "dry_run": config.dry_run,
        }

    if action == "convert-layer3-to-layer2":
        source_layer3 = layer3_path
        target_layer2 = _resolve(payload["target_layer2_path"])
        _ensure_under(_resolve(str(storage.layer2_dir)), target_layer2)
        if not source_layer3.exists():
            raise FileNotFoundError(f"missing layer3 {source_layer3}")
        base_image = _resolve(payload["base_image"])
        _ensure_under(_resolve(str(storage.base_dir)), base_image)
        if not base_image.exists():
            raise FileNotFoundError(f"missing base image {base_image}")
        removed_temp_paths: list[str] = []
        for stale_temp in target_layer2.parent.glob(f"{target_layer2.stem}.tmp-*{target_layer2.suffix}"):
            if stale_temp == target_layer2:
                continue
            stale_temp.unlink()
            removed_temp_paths.append(str(stale_temp))
        if target_layer2.exists():
            return {
                "result": "ok",
                "source_layer3_path": str(source_layer3),
                "target_layer2_path": str(target_layer2),
                "replaced_existing_target": False,
                "trashed_path": None,
                "removed_temp_paths": removed_temp_paths,
                "idempotent": True,
                "planned_commands": [],
                "dry_run": config.dry_run,
            }
        temp_target = target_layer2.with_name(f"{target_layer2.stem}.tmp-{datetime.now(UTC).timestamp():.0f}{target_layer2.suffix}")
        _convert_qcow(
            temp_target,
            source_layer3,
            str(base_image),
            source_format="qcow2",
            backing_format=payload.get("base_image_format", "qcow2"),
            dry_run=config.dry_run,
        )
        if target_layer2.exists():
            trashed = _resolve(str(storage.trash_dir / f"{target_layer2.stem}-{datetime.now(UTC).timestamp():.0f}{target_layer2.suffix}"))
            shutil.move(str(target_layer2), str(trashed))
        else:
            trashed = None
        shutil.move(str(temp_target), str(target_layer2))
        return {
            "result": "ok",
            "source_layer3_path": str(source_layer3),
            "target_layer2_path": str(target_layer2),
            "replaced_existing_target": trashed is not None,
            "trashed_path": str(trashed) if trashed else None,
            "removed_temp_paths": removed_temp_paths,
            "idempotent": False,
            "planned_commands": planned_commands,
            "dry_run": config.dry_run,
        }

    if action == "start-vm":
        guest_bootstrap_script = _write_guest_bootstrap_script(config, payload)
        guest_bootstrap_result = _prepare_layer3_guest_bootstrap(config, payload)
        runtime_xml = _write_runtime_xml(config, payload)
        runtime = _runtime_json(config, vm_id)
        if not config.dry_run:
            if not _libvirt_available():
                raise RuntimeError("libvirt/virsh is not available; cannot start VM outside dry-run mode")
            _require_kvm_device()
            domain_exists = _domain_exists(vm_id)
            state_before = _domain_state(vm_id) if domain_exists else None
            if not domain_exists:
                _virsh(["define", str(runtime_xml)])
            elif state_before in _STOPPED_DOMAIN_STATES:
                _virsh(["undefine", vm_id], check=False)
                _virsh(["define", str(runtime_xml)])
            if _domain_state(vm_id) not in _RUNNING_DOMAIN_STATES:
                _virsh(["start", vm_id])
            state = _wait_for_domain_state(vm_id, _RUNNING_DOMAIN_STATES, 15.0)
            if state not in _RUNNING_DOMAIN_STATES:
                raise RuntimeError(f"vm {vm_id} failed to reach running state, current state={state}")
        runtime.write_text(
            json.dumps(
                {
                    "vm_id": vm_id,
                    "namespace": payload["namespace"],
                    "network_id": payload["network_id"],
                    "network_bridge": payload["network_bridge"],
                    "vcpus": payload["vcpus"],
                    "memory_mb": payload["memory_mb"],
                    "reserved_ip": payload["reserved_ip"],
                    "reserved_mac": payload["reserved_mac"],
                    "nested_virtualization": bool(payload.get("nested_virtualization")),
                    "guest_bootstrap_script": str(guest_bootstrap_script),
                    "guest_bootstrap": guest_bootstrap_result,
                    "runtime_xml": str(runtime_xml),
                    "cpuset": config.host.vm_cpu_set,
                    "started_at": datetime.now(UTC).isoformat(),
                    "power_state": "running",
                },
                indent=2,
            )
        )
        return {
            "result": "ok",
            "runtime_path": str(runtime),
            "runtime_xml_path": str(runtime_xml),
            "guest_bootstrap_script": str(guest_bootstrap_script),
            "guest_bootstrap": guest_bootstrap_result,
            "planned_commands": planned_commands,
            "dry_run": config.dry_run,
        }

    if action == "poweroff-vm":
        runtime = _runtime_json(config, vm_id)
        if not config.dry_run and _libvirt_available() and _domain_exists(vm_id):
            _virsh(["destroy", vm_id])
            state = _wait_for_domain_state(vm_id, {"shut off", "shutdown", "no state"}, 10.0)
            if state not in {"shut off", "shutdown", "no state"}:
                raise RuntimeError(f"vm {vm_id} failed to power off, current state={state}")
        if runtime.exists():
            data = json.loads(runtime.read_text())
            data["power_state"] = "stopped"
            data["stopped_at"] = datetime.now(UTC).isoformat()
            runtime.write_text(json.dumps(data, indent=2))
        return {"result": "ok", "planned_commands": planned_commands, "dry_run": config.dry_run}

    if action == "stop-vm":
        runtime = _runtime_json(config, vm_id)
        if not config.dry_run and _libvirt_available() and _domain_exists(vm_id):
            state_before = _domain_state(vm_id)
            if state_before == "paused":
                _virsh(["destroy", vm_id])
                state = _wait_for_domain_state(vm_id, {"shut off", "shutdown", "no state"}, 10.0)
                if state not in {"shut off", "shutdown", "no state"}:
                    raise RuntimeError(f"vm {vm_id} failed to power off from paused state, current state={state}")
            elif state_before not in {"shut off", "shutdown", "no state"}:
                _virsh(["shutdown", vm_id])
                state = _wait_for_domain_state(vm_id, {"shut off", "shutdown", "no state"}, 90.0)
                if state not in {"shut off", "shutdown", "no state"}:
                    raise RuntimeError(f"vm {vm_id} failed to shut down, current state={state}")
        if runtime.exists():
            data = json.loads(runtime.read_text())
            data["power_state"] = "stopped"
            data["stopped_at"] = datetime.now(UTC).isoformat()
            runtime.write_text(json.dumps(data, indent=2))
        return {"result": "ok", "planned_commands": planned_commands, "dry_run": config.dry_run}

    if action == "pause-vm":
        runtime = _runtime_json(config, vm_id)
        if not config.dry_run and _libvirt_available():
            if not _domain_exists(vm_id):
                return {"result": "ok", "missing": True, "planned_commands": planned_commands, "dry_run": config.dry_run}
            _virsh(["suspend", vm_id])
        if not runtime.exists():
            return {"result": "ok", "missing": True, "planned_commands": planned_commands, "dry_run": config.dry_run}
        data = json.loads(runtime.read_text())
        data["power_state"] = "paused"
        data["paused_at"] = datetime.now(UTC).isoformat()
        runtime.write_text(json.dumps(data, indent=2))
        return {"result": "ok", "runtime_path": str(runtime), "planned_commands": planned_commands, "dry_run": config.dry_run}

    if action == "resume-vm":
        runtime = _runtime_json(config, vm_id)
        if not config.dry_run and _libvirt_available():
            if not _domain_exists(vm_id):
                return {"result": "ok", "missing": True, "planned_commands": planned_commands, "dry_run": config.dry_run}
            _virsh(["resume", vm_id])
        if not runtime.exists():
            return {"result": "ok", "missing": True, "planned_commands": planned_commands, "dry_run": config.dry_run}
        data = json.loads(runtime.read_text())
        data["power_state"] = "running"
        data["resumed_at"] = datetime.now(UTC).isoformat()
        runtime.write_text(json.dumps(data, indent=2))
        return {"result": "ok", "runtime_path": str(runtime), "planned_commands": planned_commands, "dry_run": config.dry_run}

    if action == "restart-vm":
        guest_bootstrap_script = _write_guest_bootstrap_script(config, payload)
        if not config.dry_run and _libvirt_available() and _domain_exists(vm_id):
            _virsh(["reboot", vm_id])
            state = _wait_for_domain_state(vm_id, {"running", "idle"}, 30.0)
            if state not in {"running", "idle"}:
                raise RuntimeError(f"vm {vm_id} failed to reboot cleanly, current state={state}")
        runtime = _runtime_json(config, vm_id)
        if runtime.exists():
            data = json.loads(runtime.read_text())
            data["power_state"] = "running"
            data["guest_bootstrap_script"] = str(guest_bootstrap_script)
            data["restarted_at"] = datetime.now(UTC).isoformat()
            runtime.write_text(json.dumps(data, indent=2))
        return {
            "result": "ok",
            "guest_bootstrap_script": str(guest_bootstrap_script),
            "planned_commands": planned_commands,
            "dry_run": config.dry_run,
        }

    if action == "inspect-vm":
        domain_state = None
        if not config.dry_run and _libvirt_available():
            domain_state = _domain_state(vm_id)
        else:
            runtime = _runtime_json(config, vm_id)
            if runtime.exists():
                try:
                    runtime_data = json.loads(runtime.read_text())
                    domain_state = {
                        "paused": "paused",
                        "stopped": "shut off",
                        "failed": "crashed",
                    }.get(runtime_data.get("power_state"), "running")
                except json.JSONDecodeError:
                    domain_state = "running"
        current_ip = _read_leases_for_mac(payload["reserved_mac"])
        return {
            "result": "ok",
            "vm_id": vm_id,
            "domain_state": domain_state,
            "power_state": _map_domain_state(domain_state),
            "current_ip": current_ip,
            "host_booted_at": _host_booted_at(),
            "inspected_at": datetime.now(UTC).isoformat(),
            "planned_commands": planned_commands,
            "dry_run": config.dry_run,
        }

    if action in {"delete-layer3", "revert-vm"}:
        if layer3_path.exists():
            trashed = _resolve(str(storage.trash_dir / f"{vm_id}-{datetime.now(UTC).timestamp():.0f}.qcow2"))
            shutil.move(str(layer3_path), str(trashed))
            if action == "revert-vm":
                _touch_qcow(layer3_path, backing_file=str(layer2_path), dry_run=config.dry_run)
            return {
                "result": "ok",
                "disposition": "recreated" if action == "revert-vm" else "trashed",
                "trashed_path": str(trashed),
                "trash_path_exists_after": trashed.exists(),
                "layer3_path": str(layer3_path),
                "layer3_path_exists_after": layer3_path.exists(),
                "planned_commands": planned_commands,
                "dry_run": config.dry_run,
            }
        if action == "revert-vm":
            _touch_qcow(layer3_path, backing_file=str(layer2_path), dry_run=config.dry_run)
            return {
                "result": "ok",
                "disposition": "recreated",
                "layer3_path": str(layer3_path),
                "layer3_path_exists_after": layer3_path.exists(),
                "trash_path_exists_after": False,
                "recreated": True,
                "planned_commands": planned_commands,
                "dry_run": config.dry_run,
            }
        return {
            "result": "ok",
            "disposition": "missing",
            "layer3_path": str(layer3_path),
            "layer3_path_exists_after": False,
            "trash_path_exists_after": False,
            "missing": True,
            "planned_commands": planned_commands,
            "dry_run": config.dry_run,
        }

    if action == "delete-layer2":
        if layer2_path.exists():
            trashed = _resolve(str(storage.trash_dir / f"{vm_id}-layer2-{datetime.now(UTC).timestamp():.0f}.qcow2"))
            shutil.move(str(layer2_path), str(trashed))
            return {"result": "ok", "trashed_path": str(trashed), "planned_commands": planned_commands, "dry_run": config.dry_run}
        return {"result": "ok", "missing": True, "planned_commands": planned_commands, "dry_run": config.dry_run}

    if action == "delete-runtime":
        runtime = _runtime_json(config, vm_id)
        runtime_xml = _runtime_xml(config, vm_id)
        if not config.dry_run and _libvirt_available() and _domain_exists(vm_id):
            state = _domain_state(vm_id)
            if state not in {"shut off", "shutdown", "no state"}:
                raise RuntimeError(f"refusing to remove runtime for active vm {vm_id} in state={state}")
            _virsh(["undefine", vm_id], check=False)
        deleted: list[str] = []
        for candidate in (runtime, runtime_xml):
            if candidate.exists():
                candidate.unlink()
                deleted.append(str(candidate))
        return {"result": "ok", "deleted_runtime_files": deleted, "planned_commands": planned_commands, "dry_run": config.dry_run}

    raise AssertionError("unreachable")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-file", required=True)
    parser.add_argument("--config")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    request_path = Path(args.request_file)
    if request_path.is_symlink():
        raise SystemExit("request file must not be a symlink")
    data = json.loads(request_path.read_text())
    config = load_config(args.config)
    if args.dry_run:
        config.dry_run = True
    result = handle_request(config, data["action"], data["payload"])
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
