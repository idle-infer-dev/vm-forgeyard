from __future__ import annotations

from pathlib import Path


def probe_nested_virtualization() -> dict[str, object]:
    cpu_flags = _cpu_flags()
    has_vmx = "vmx" in cpu_flags
    has_svm = "svm" in cpu_flags
    module_probe = _module_nested_probe(has_vmx=has_vmx, has_svm=has_svm)
    kvm_device_present = Path("/dev/kvm").exists()
    supported = bool((has_vmx or has_svm) and module_probe["enabled"] and kvm_device_present)
    reasons: list[str] = []
    if not (has_vmx or has_svm):
        reasons.append("CPU virtualization flags vmx/svm are missing")
    if not module_probe["enabled"]:
        reasons.append(str(module_probe["reason"]))
    if not kvm_device_present:
        reasons.append("/dev/kvm is missing")
    return {
        "supported": supported,
        "cpu_flags": sorted(flag for flag in ("vmx", "svm") if flag in cpu_flags),
        "module": module_probe["module"],
        "module_nested_enabled": module_probe["enabled"],
        "kvm_device_present": kvm_device_present,
        "reason": "; ".join(reasons) if reasons else None,
    }


def _cpu_flags(cpuinfo_path: Path = Path("/proc/cpuinfo")) -> set[str]:
    try:
        text = cpuinfo_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return set()
    flags: set[str] = set()
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        if key.strip() in {"flags", "Features"}:
            flags.update(value.split())
    return flags


def _module_nested_probe(*, has_vmx: bool, has_svm: bool) -> dict[str, object]:
    candidates: list[tuple[str, Path]] = []
    if has_vmx:
        candidates.append(("kvm_intel", Path("/sys/module/kvm_intel/parameters/nested")))
    if has_svm:
        candidates.append(("kvm_amd", Path("/sys/module/kvm_amd/parameters/nested")))
    if not candidates:
        return {"module": None, "enabled": False, "reason": "no CPU virtualization module matches vmx/svm"}
    for module, path in candidates:
        if not path.exists():
            continue
        try:
            value = path.read_text(encoding="utf-8").strip().lower()
        except OSError as exc:
            return {"module": module, "enabled": False, "reason": f"cannot read {path}: {exc}"}
        enabled = value in {"1", "y", "yes", "true", "on"}
        return {
            "module": module,
            "enabled": enabled,
            "reason": None if enabled else f"{module} nested parameter is disabled",
        }
    modules = ", ".join(module for module, _ in candidates)
    return {"module": None, "enabled": False, "reason": f"nested parameter is missing for {modules}"}
