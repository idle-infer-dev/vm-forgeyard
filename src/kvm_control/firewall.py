from __future__ import annotations

import ipaddress

from .service import Services


def reconcile_firewall_egress(services: Services) -> dict:
    return _reconcile_firewall_ipset(
        services,
        action="sync-firewall-egress",
        entries=services.registry.effective_firewall_egress_entries(),
        ipset_name="kvmEgressNetV4",
        vm_id="firewall-egress",
        target_zone="net",
    )


_TARGET_IPSETS = {
    "net": "kvmAccessNetV4",
    "dev": "kvmIngressDevV4",
    "stage": "kvmIngressStageV4",
    "misc": "kvmIngressMiscV4",
    "live": "kvmIngressLiveV4",
}


def reconcile_firewall_access(services: Services) -> dict[str, dict]:
    entries_by_zone = services.registry.effective_firewall_access_entries()
    default_ingress_sources = _normalize_ipv4_cidrs(services.config.firewall.default_ingress_sources)
    results: dict[str, dict] = {}
    for target_zone, ipset_name in _TARGET_IPSETS.items():
        entries = set(entries_by_zone.get(target_zone, []))
        if target_zone in {"dev", "stage", "misc", "live"}:
            entries.update(default_ingress_sources)
        results[target_zone] = _reconcile_firewall_ipset(
            services,
            action="sync-firewall-ipset",
            entries=sorted(entries),
            ipset_name=ipset_name,
            vm_id=f"firewall-{target_zone}",
            target_zone=target_zone,
        )
    return results


def _normalize_ipv4_cidrs(values: list[str]) -> list[str]:
    normalized: set[str] = set()
    for value in values:
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4:
            raise ValueError(f"only IPv4 default ingress sources are supported: {value}")
        if network.prefixlen == 32:
            normalized.add(str(network.network_address))
        else:
            normalized.add(str(network))
    return sorted(normalized)


def _reconcile_firewall_ipset(
    services: Services,
    *,
    action: str,
    entries: list[str],
    ipset_name: str,
    vm_id: str,
    target_zone: str,
) -> dict:
    operation_id = services.registry.create_operation(
        action=action,
        vm_id=None,
        namespace=None,
        status="running",
        details={"entries": entries, "ipset_name": ipset_name, "target_zone": target_zone},
    )
    try:
        result = services.executor.run(
            action,
            {
                "operation_id": operation_id,
                "vm_id": vm_id,
                "layer2_path": str(services.config.storage.layer2_dir / f"{vm_id}.unused"),
                "layer3_path": str(services.config.storage.layer3_dir / f"{vm_id}.unused"),
                "entries": entries,
                "ipset_name": ipset_name,
                "target_zone": target_zone,
            },
        )
        services.registry.update_operation(operation_id, "completed", details=result)
        return result
    except Exception as exc:
        services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
        raise
