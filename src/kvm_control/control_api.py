from __future__ import annotations

import json
import hashlib
import hmac
import ipaddress
import re
import time
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from .auth import (
    AuthPrincipal,
    current_principal,
    default_zone,
    effective_namespace,
    generate_self_registration_key,
    generate_token,
    hash_token_secret,
    principal_to_dict,
    require_admin,
    require_auth,
    require_zone,
    resolve_source_ip,
    split_self_registration_key,
)
from .config import base_image_recipe_map, config_to_dict, layer2_image_recipe_map, template_map
from .firewall import reconcile_firewall_access, reconcile_firewall_egress
from .host_capabilities import probe_nested_virtualization
from .models import (
    CreateLockRequest,
    CreateRunRequest,
    BaseImageBuildPlanResponse,
    BaseImageRecipeResponse,
    BuildBaseImageRequest,
    BuildLayer2ImageRequest,
    CreateAuthTokenRequest,
    CreateEndpointWorkaroundRuleRequest,
    CreateFirewallEgressRuleRequest,
    CreateFirewallAccessRuleRequest,
    CreateRepositorySelfRegistrationKeyRequest,
    CreateTestsuiteDependencyDocumentRequest,
    RefreshLeaseRequest,
    ReleaseLockRequest,
    RepositorySelfRegistrationKeyCreateResponse,
    RepositorySelfRegistrationKeyResponse,
    RepositorySelfRegistrationRequest,
    RepositorySelfRegistrationResponse,
    ResizeLayer3Request,
    ResizeLayer3Response,
    SetVmRetentionRequest,
    CreateVmRequest,
    FirewallEgressRuleResponse,
    FirewallAccessRuleResponse,
    FinishRunRequest,
    ImageActionResponse,
    ImageRecordResponse,
    IgnoreRunForLearningRequest,
    Layer2ImageRecipeResponse,
    Layer2ImageBuildResponse,
    PublishImageRequest,
    PromoteLayer2Request,
    PromoteLayer2Response,
    RunEstimateRequest,
    RunEventRequest,
    RunReportRequest,
    RunReportResponse,
    RunResponse,
    RunUsageResponse,
    StageFinishRequest,
    StageStartRequest,
    TestsuiteDependencyDocumentResponse,
    AuthTokenCreateResponse,
    AuthTokenResponse,
    EndpointWorkaroundRuleResponse,
    VmActionResponse,
    WaitVmReadyRequest,
    WaitVmReadyResponse,
    WebrootArtifactDeleteResponse,
    WebrootArtifactResponse,
)
from .service import Services, build_services
from .status_api import create_status_router, status_assets_dir


MAX_WEBROOT_ARTIFACT_BYTES = 32 * 1024 * 1024


def _model_validate(model: type, payload: dict) -> object:
    if hasattr(model, "model_validate"):
        return model.model_validate(payload)
    return model.parse_obj(payload)


def _model_fields_set(model: object) -> set[str]:
    return set(getattr(model, "model_fields_set", getattr(model, "__fields_set__", set())))


def _normalize_source_cidr(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid source_cidr: {value}") from exc
    if network.version != 4:
        raise HTTPException(status_code=422, detail="only IPv4 source_cidr is supported")
    if network.prefixlen == 32:
        return str(network.network_address)
    return str(network)


def _image_id_component(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._:-]+", "-", value).strip(".:-")
    return normalized or "image"

def _normalize_target_cidr(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid target_cidr: {value}") from exc
    if network.version != 4:
        raise HTTPException(status_code=422, detail="only IPv4 target_cidr is supported")
    if network.prefixlen == 32:
        return str(network.network_address)
    return str(network)


def _normalize_single_ipv4(value: str, field_name: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid {field_name}: {value}") from exc
    if address.version != 4:
        raise HTTPException(status_code=422, detail=f"only IPv4 {field_name} is supported")
    return str(address)


def _normalize_fqdn(value: str) -> str:
    hostname = value.rstrip(".").lower()
    if not hostname or len(hostname) > 253:
        raise HTTPException(status_code=422, detail=f"invalid fqdn: {value}")
    if re.fullmatch(r"\d+(?:\.\d+){3}", hostname):
        raise HTTPException(status_code=422, detail="fqdn workaround value must not be an IP address")
    labels = hostname.split(".")
    if len(labels) < 2:
        raise HTTPException(status_code=422, detail="fqdn workaround value must contain at least two labels")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(label_pattern.fullmatch(label) is None for label in labels):
        raise HTTPException(status_code=422, detail=f"invalid fqdn: {value}")
    return hostname


def _normalize_apply_on(values: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9._:-]+", item):
            raise HTTPException(status_code=422, detail=f"invalid apply_on target: {value}")
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    if not normalized:
        raise HTTPException(status_code=422, detail="apply_on must not be empty")
    return normalized


ENDPOINT_WORKAROUND_EVIDENCE_TYPES = {
    "endpoint_workaround_applied",
    "endpoint_workaround_checked",
    "endpoint_workaround_reapplied",
    "endpoint_workaround_failed",
}


def _validate_endpoint_workaround_evidence(details: dict[str, Any], run: dict[str, Any], services: Services) -> dict[str, Any]:
    for field in ("rule_id", "kind", "workaround_type", "value", "target_ip", "apply_on", "status"):
        if field not in details:
            raise HTTPException(status_code=422, detail=f"endpoint workaround evidence requires details.{field}")
    if details["kind"] not in {"fqdn", "ip"}:
        raise HTTPException(status_code=422, detail="endpoint workaround evidence kind must be fqdn or ip")
    if details["workaround_type"] not in {"hosts_entry", "dnat"}:
        raise HTTPException(status_code=422, detail="endpoint workaround evidence workaround_type must be hosts_entry or dnat")
    if details["kind"] == "fqdn" and details["workaround_type"] != "hosts_entry":
        raise HTTPException(status_code=422, detail="fqdn endpoint workaround evidence must use hosts_entry")
    if details["kind"] == "ip" and details["workaround_type"] != "dnat":
        raise HTTPException(status_code=422, detail="ip endpoint workaround evidence must use dnat")
    if details["status"] not in {"completed", "failed"}:
        raise HTTPException(status_code=422, detail="endpoint workaround evidence status must be completed or failed")

    target_ip = _normalize_single_ipv4(str(details["target_ip"]), "target_ip")
    try:
        rule_id = int(details["rule_id"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="endpoint workaround evidence rule_id must be an integer") from exc
    rule = services.registry.get_endpoint_workaround_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=422, detail=f"endpoint workaround rule {rule_id} not found")
    if rule["namespace"] != run["namespace"]:
        raise HTTPException(status_code=422, detail=f"endpoint workaround rule {rule_id} is outside run namespace")

    apply_on = str(details["apply_on"])
    if apply_on not in rule["apply_on"]:
        raise HTTPException(status_code=422, detail=f"endpoint workaround rule {rule_id} does not apply on {apply_on}")
    for field in ("kind", "workaround_type", "value"):
        if str(details[field]) != str(rule[field]):
            raise HTTPException(status_code=422, detail=f"endpoint workaround evidence details.{field} does not match rule {rule_id}")
    if target_ip != rule["target_ip"]:
        raise HTTPException(status_code=422, detail=f"endpoint workaround evidence target_ip does not match rule {rule_id}")
    if details.get("constraint_id") and rule.get("constraint_id") and details["constraint_id"] != rule["constraint_id"]:
        raise HTTPException(status_code=422, detail=f"endpoint workaround evidence constraint_id does not match rule {rule_id}")

    details = dict(details)
    details["rule_id"] = rule_id
    details["target_ip"] = target_ip
    return details


def _validate_run_event_details(payload: RunEventRequest, run: dict[str, Any], services: Services) -> dict[str, Any]:
    details = dict(payload.details or {})
    if details.get("type") in ENDPOINT_WORKAROUND_EVIDENCE_TYPES:
        return _validate_endpoint_workaround_evidence(details, run, services)
    return details


def _canonicalize_firewall_egress_row(row: dict) -> dict:
    canonical = dict(row)
    mode = canonical.get("mode")
    if mode == "single_ip":
        mode = "cidr"
    canonical["mode"] = mode
    canonical["target_cidr"] = canonical.get("target_ip")
    canonical.pop("target_ip", None)
    return canonical


def create_app(services: Services | None = None) -> FastAPI:
    services = services or build_services()
    app = FastAPI(
        title="kvm-control control-api",
        version="0.2.0",
    )
    app.state.services = services
    api = APIRouter(dependencies=[Depends(require_auth(services.config))])
    templates = template_map(services.config)
    base_image_recipes = base_image_recipe_map(services.config)
    layer2_image_recipes = layer2_image_recipe_map(services.config)
    network_segments = {segment.id: segment for segment in services.config.network.segments}

    @app.middleware("http")
    async def record_request_status(request: Request, call_next) -> Response:
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception as exc:
            _record_request_event(request, 500, start, error=str(exc))
            raise
        _record_request_event(request, response.status_code, start)
        return response

    def _record_request_event(request: Request, status_code: int, started_at: float, error: str | None = None) -> None:
        if not request.url.path.startswith("/v1/"):
            return
        if status_code >= 500:
            level = "error"
            status = "failed"
        elif status_code >= 400:
            level = "warning"
            status = "rejected"
        else:
            level = "info"
            status = "completed"
        services.registry.record_status_event(
            kind="api_request",
            level=level,
            status=status,
            summary=f"{request.method} {request.url.path} -> {status_code}",
            details={
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "duration_ms": round((time.perf_counter() - started_at) * 1000, 3),
                "error": error,
            },
        )

    def build_paths(namespace: str, template_id: str, vm_slot: str) -> tuple[Path, Path]:
        layer2 = services.config.storage.layer2_dir / f"{namespace}--{template_id}.qcow2"
        layer3 = services.config.storage.layer3_dir / f"{namespace}--{vm_slot}.qcow2"
        return layer2, layer3

    def ensure_lock(namespace: str, resource_id: str) -> tuple[bool, str | None]:
        request = services.registry.ensure_lock_request(resource_id, namespace)
        if request["status"] != "granted":
            return False, f"namespace is queued for lock {resource_id}"
        if _namespace_lock_lease_expired(request):
            return False, f"namespace lock lease expired for {namespace}; refresh lease"
        return True, None

    def _namespace_lock_lease_expired(lock: dict) -> bool:
        if lock.get("resource_id") != f"namespace:{lock.get('namespace')}":
            return False
        if lock.get("lease_expired_at"):
            return True
        expires_at = lock.get("lease_expires_at")
        if not expires_at:
            return False
        try:
            expires = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            return False
        return expires <= datetime.now(UTC)

    def _decorate_auth(record: dict, principal: AuthPrincipal) -> dict:
        decorated = dict(record)
        decorated["authenticated_as"] = principal.username
        decorated["effective_namespace"] = record.get("namespace")
        return decorated

    def _role_for_username(username: str, requested_role: str | None) -> str:
        if username == "admin":
            role = "admin"
        elif username == "dev":
            role = "dev"
        elif username == "staging":
            role = "staging"
        elif username == "live":
            role = "live"
        elif username.startswith("git."):
            role = "repository"
        else:
            raise HTTPException(status_code=422, detail="unsupported username")
        if requested_role is not None and requested_role != role:
            raise HTTPException(status_code=422, detail="role does not match username")
        return role

    def _namespace_for_token(username: str, role: str) -> str | None:
        if role == "repository":
            return username
        return None

    def _environment_docs(principal: AuthPrincipal) -> dict:
        environments = {
            "dev": {
                "name": "dev",
                "intention": "Free development playground for repository agents and exploratory work.",
                "users": ["dev", "git.*", "admin"],
                "network_id": "dev",
            },
            "stage": {
                "name": "stage",
                "intention": "Automated staging and qualified test execution across repositories.",
                "users": ["staging", "admin"],
                "network_id": "stage",
            },
            "misc": {
                "name": "misc",
                "intention": "Admin-reserved miscellaneous and qualification work.",
                "users": ["admin"],
                "network_id": "misc",
            },
            "live": {
                "name": "live",
                "intention": "Live-node control for rollout automation.",
                "users": ["live", "admin"],
                "network_id": "live",
            },
        }
        return {
            "authenticated_as": principal.username,
            "effective_namespace": principal.namespace,
            "allowed_zones": list(principal.allowed_zones),
            "environments": [environments[zone] for zone in principal.allowed_zones if zone in environments],
        }

    def _flatten_planned_commands(executor_results: list[dict] | None) -> list[list[str]]:
        commands: list[list[str]] = []
        for result in executor_results or []:
            commands.extend(result.get("planned_commands", []))
        return commands

    def _layer3_disposition(executor_results: list[dict] | None) -> dict | None:
        for result in executor_results or []:
            if "layer3_path_exists_after" in result or "trash_path_exists_after" in result:
                return {
                    "mode": result.get("disposition"),
                    "layer3_path": result.get("layer3_path"),
                    "layer3_path_exists_after": result.get("layer3_path_exists_after"),
                    "trash_path": result.get("trashed_path"),
                    "trash_path_exists_after": result.get("trash_path_exists_after"),
                }
        return None

    def response_for(
        vm: dict,
        operation_id: int,
        action: str,
        status: str,
        rejection_category: str | None = None,
        rejection_reason: str | None = None,
        executor_results: list[dict] | None = None,
    ) -> VmActionResponse:
        return VmActionResponse(
            operation_id=operation_id,
            vm_id=vm["vm_id"],
            namespace=vm["namespace"],
            action=action,
            status=status,
            power_state=vm["power_state"],
            readiness_state=vm["readiness_state"],
            reserved_ip=vm["reserved_ip"],
            rejection_category=rejection_category,
            rejection_reason=rejection_reason,
            dry_run=any(result.get("dry_run") for result in executor_results or []),
            planned_commands=_flatten_planned_commands(executor_results),
            executor_results=executor_results or [],
            layer3_disposition=_layer3_disposition(executor_results),
            retention=vm.get("retention") or "ephemeral",
            retention_reason=vm.get("retention_reason"),
            purpose=vm.get("purpose"),
            agent_session_id=vm.get("agent_session_id"),
            agent_label=vm.get("agent_label"),
            handoff=vm.get("handoff"),
            nested_virtualization=bool(vm.get("nested_virtualization")),
        )

    def promote_response_for(
        vm: dict,
        operation_id: int,
        source_layer3_path: str,
        target_layer2_path: str,
        image_id: str | None = None,
        executor_results: list[dict] | None = None,
    ) -> PromoteLayer2Response:
        return PromoteLayer2Response(
            operation_id=operation_id,
            vm_id=vm["vm_id"],
            namespace=vm["namespace"],
            action="promote-layer2",
            status="completed",
            power_state=vm["power_state"],
            readiness_state=vm["readiness_state"],
            source_layer3_path=source_layer3_path,
            target_layer2_path=target_layer2_path,
            image_id=image_id,
            dry_run=any(result.get("dry_run") for result in executor_results or []),
            planned_commands=_flatten_planned_commands(executor_results),
            executor_results=executor_results or [],
        )

    def image_response_for(image: dict, operation_id: int, action: str, executor_results: list[dict] | None = None) -> ImageActionResponse:
        return ImageActionResponse(
            operation_id=operation_id,
            image_id=image["image_id"],
            action=action,
            status="completed",
            cache_state=image["cache_state"],
            local_path=image["local_path"],
            remote_path=image["remote_path"],
            checksum_sha256=image.get("checksum_sha256"),
            size_bytes=image.get("size_bytes"),
            remote_backend=image.get("remote_backend") or image.get("metadata", {}).get("remote_backend"),
            remote_verified=next((result.get("remote_verified") for result in executor_results or [] if "remote_verified" in result), None),
            dry_run=any(result.get("dry_run") for result in executor_results or []),
            planned_commands=_flatten_planned_commands(executor_results),
            executor_results=executor_results or [],
        )

    def resize_layer3_response_for(
        vm: dict,
        operation_id: int,
        previous_virtual_size_bytes: int,
        new_virtual_size_bytes: int,
        executor_results: list[dict] | None = None,
    ) -> ResizeLayer3Response:
        return ResizeLayer3Response(
            operation_id=operation_id,
            vm_id=vm["vm_id"],
            namespace=vm["namespace"],
            action="resize-layer3",
            status="completed",
            power_state=vm["power_state"],
            readiness_state=vm["readiness_state"],
            reserved_ip=vm["reserved_ip"],
            layer3_path=vm["layer3_path"],
            previous_virtual_size_bytes=previous_virtual_size_bytes,
            new_virtual_size_bytes=new_virtual_size_bytes,
            dry_run=any(result.get("dry_run") for result in executor_results or []),
            planned_commands=_flatten_planned_commands(executor_results),
            executor_results=executor_results or [],
        )

    def _load_vm(vm_id: str) -> dict:
        vm = services.registry.get_vm(vm_id)
        if vm is None:
            raise HTTPException(status_code=404, detail="vm not found")
        return vm

    def _require_vm_access(vm: dict, principal: AuthPrincipal) -> None:
        effective_namespace(principal, vm["namespace"])
        require_zone(principal, vm["network_id"])

    def _require_namespace_access(namespace: str, principal: AuthPrincipal) -> None:
        if namespace == "default":
            return
        effective_namespace(principal, namespace)

    def _default_retention(payload: CreateVmRequest) -> str:
        if payload.retention:
            return payload.retention
        if payload.network_id == "live":
            return "live"
        return "ephemeral"

    def _validate_retention(retention: str, principal: AuthPrincipal) -> None:
        if retention == "protected" and not principal.is_admin:
            raise HTTPException(status_code=403, detail="retention denied")
        if retention == "live" and not (principal.is_admin or principal.role == "live"):
            raise HTTPException(status_code=403, detail="retention denied")

    def _validate_nested_virtualization(requested: bool, principal: AuthPrincipal) -> None:
        if not requested:
            return
        if not services.config.host.nested_virtualization_enabled:
            raise HTTPException(status_code=503, detail="nested virtualization is not enabled on this host")
        if not services.config.dry_run:
            probe = probe_nested_virtualization()
            if not probe["supported"]:
                reason = probe.get("reason") or "host probe failed"
                raise HTTPException(status_code=503, detail=f"nested virtualization is not supported on this host: {reason}")
        allowed_repository_users = {"git.kvm-control", "git.vm-forgeyard"}
        if principal.is_admin or principal.username in allowed_repository_users:
            return
        raise HTTPException(status_code=403, detail="nested virtualization denied")

    def _validate_ssh_public_key(value: str | None) -> str | None:
        if value is None:
            return None
        key = value.strip()
        if "\n" in key or "\r" in key:
            raise HTTPException(status_code=422, detail="ssh_public_key must be a single public key line")
        key_types = ("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-nistp256 ", "ecdsa-sha2-nistp384 ", "ecdsa-sha2-nistp521 ")
        if not key.startswith(key_types):
            raise HTTPException(status_code=422, detail="ssh_public_key must be an OpenSSH public key")
        return key

    def _vm_executor_payload(vm: dict, operation_id: int, template_id: str | None = None) -> dict:
        template = templates.get(template_id or vm["template_id"])
        if template is None:
            raise HTTPException(status_code=422, detail="unknown template")
        network = network_segments.get(vm["network_id"])
        if network is None:
            raise HTTPException(status_code=422, detail=f"unknown network {vm['network_id']}")
        return {
            "operation_id": operation_id,
            "vm_id": vm["vm_id"],
            "namespace": vm["namespace"],
            "network_id": vm["network_id"],
            "network_bridge": network.bridge,
            "vcpus": vm["vcpus"],
            "memory_mb": vm["memory_mb"],
            "reserved_ip": vm["reserved_ip"],
            "reserved_mac": vm["reserved_mac"],
            "layer2_path": vm["layer2_path"],
            "layer3_path": vm["layer3_path"],
            "layer3_format": "qcow2",
            "base_image": str(services.config.storage.base_dir / template.base_image),
            "base_image_format": template.base_image_format,
            "template_architecture": template.architecture,
            "template_machine_type": template.machine_type,
            "template_boot_mode": template.boot_mode,
            "template_kernel_path": template.kernel_path,
            "template_initrd_path": template.initrd_path,
            "template_kernel_append": template.kernel_append,
            "authorized_keys_path": str(services.config.image_factory.authorized_keys_path),
            "nested_virtualization": bool(vm.get("nested_virtualization")),
            **({"ssh_public_key": vm["ssh_public_key"]} if vm.get("ssh_public_key") else {}),
        }

    def _image_executor_payload(
        image: dict,
        operation_id: int,
        *,
        source_layer2_path: str | None = None,
    ) -> dict:
        return {
            "operation_id": operation_id,
            "vm_id": image["image_id"],
            "image_id": image["image_id"],
            "layer2_path": image["local_path"],
            "layer3_path": str(services.config.storage.layer3_dir / f"{image['image_id']}.unused.qcow2"),
            "local_path": image["local_path"],
            "remote_path": image["remote_path"],
            "remote_backend": image.get("remote_backend") or image.get("metadata", {}).get("remote_backend") or "local",
            "remote_timeout_s": services.config.storage.image_remote_rsync_timeout_s,
            "source_layer2_path": source_layer2_path or image["local_path"],
            "metadata": image.get("metadata", {}),
        }

    def _image_remote_path(image_id: str) -> str:
        safe_image_id = image_id.replace(":", "-")
        storage = services.config.storage
        if storage.image_remote_backend == "rsync":
            if not storage.image_remote_rsync_host or not storage.image_remote_rsync_module:
                raise HTTPException(status_code=503, detail="rsync remote image storage is not configured")
            subdir = storage.image_remote_rsync_subdir.strip("/")
            parts = [f"rsync://{storage.image_remote_rsync_host}", storage.image_remote_rsync_module]
            if subdir:
                parts.append(subdir)
            parts.extend([safe_image_id, "image.qcow2"])
            return "/".join(parts)
        return str(storage.image_remote_dir / f"{safe_image_id}.qcow2")

    def _sync_vm_runtime_state(vm: dict) -> dict:
        operation_id = services.registry.create_operation("inspect", vm["vm_id"], vm["namespace"], "running")
        try:
            result = services.executor.run("inspect-vm", _vm_executor_payload(vm, operation_id))
            updates: dict[str, str | None] = {}
            power_state = result.get("power_state")
            if power_state == "running":
                updates["power_state"] = "running"
                updates["status"] = "running"
            elif power_state == "paused":
                updates["power_state"] = "paused"
                updates["status"] = "paused"
            elif power_state == "stopped":
                updates["power_state"] = "stopped"
                updates["status"] = "stopped"
                updates["readiness_state"] = "configuring"
            elif power_state == "failed":
                updates["power_state"] = "failed"
                updates["status"] = "failed"
                updates["readiness_state"] = "failed"
            if updates:
                vm = services.registry.patch_vm(vm["vm_id"], **updates)
            services.registry.update_operation(operation_id, "completed", details=result)
            vm = dict(vm)
            vm["current_ip"] = result.get("current_ip")
            vm["domain_state"] = result.get("domain_state")
            return vm
        except Exception as exc:
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            vm = dict(vm)
            vm["current_ip"] = None
            vm["domain_state"] = None
            return vm

    def _load_run(run_id: int) -> dict:
        run = services.registry.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        return run

    def _load_image(image_id: str) -> dict:
        image = services.registry.get_image(image_id)
        if image is None:
            raise HTTPException(status_code=404, detail="image not found")
        return image

    def _load_base_image_recipe(recipe_id: str) -> dict:
        recipe = base_image_recipes.get(recipe_id)
        if recipe is None:
            raise HTTPException(status_code=404, detail="base image recipe not found")
        payload = config_to_dict(recipe)
        return payload

    def _load_layer2_image_recipe(recipe_id: str) -> dict:
        recipe = layer2_image_recipes.get(recipe_id)
        if recipe is None:
            raise HTTPException(status_code=404, detail="layer2 image recipe not found")
        return config_to_dict(recipe)

    def _recipe_matches_keyword(recipe: dict, keyword: str) -> bool:
        wanted = keyword.casefold()
        return wanted in [str(item).casefold() for item in recipe.get("keywords") or []]

    def _safe_webroot_relative_path(namespace: str, artifact_path: str) -> PurePosixPath:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", namespace):
            raise HTTPException(status_code=422, detail="invalid namespace")
        if not artifact_path or artifact_path.endswith("/"):
            raise HTTPException(status_code=422, detail="artifact path must name a file")
        if "\\" in artifact_path:
            raise HTTPException(status_code=422, detail="artifact path must use POSIX separators")
        relative = PurePosixPath(namespace) / PurePosixPath(artifact_path)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise HTTPException(status_code=422, detail="artifact path must stay under namespace")
        return relative

    def _webroot_artifact_path(namespace: str, artifact_path: str) -> tuple[PurePosixPath, Path]:
        relative = _safe_webroot_relative_path(namespace, artifact_path)
        root = services.config.storage.webroot_dir.resolve()
        absolute = (root / Path(*relative.parts)).resolve()
        if absolute == root or root not in absolute.parents:
            raise HTTPException(status_code=422, detail="artifact path must stay under webroot")
        return relative, absolute

    def _webroot_artifact_response(namespace: str, relative: PurePosixPath, path: Path) -> WebrootArtifactResponse:
        stat = path.stat()
        return _model_validate(
            WebrootArtifactResponse,
            {
                "namespace": namespace,
                "path": str(PurePosixPath(*relative.parts[1:])),
                "public_path": f"/{relative.as_posix()}",
                "size_bytes": stat.st_size,
                "checksum_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "updated_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
            },
        )

    def _remove_empty_webroot_parents(path: Path, namespace: str) -> None:
        root = services.config.storage.webroot_dir.resolve()
        namespace_root = (root / namespace).resolve()
        current = path.parent
        while current != namespace_root and current != root and root in current.parents:
            try:
                current.rmdir()
            except OSError:
                return
            current = current.parent

    def _require_admin_token(principal: AuthPrincipal) -> None:
        if not principal.is_admin:
            raise HTTPException(status_code=403, detail="admin token required")
        if services.config.auth.enabled and not principal.authenticated:
            raise HTTPException(status_code=401, detail="admin token required")

    def _source_allowed(source_ip: str, source_cidrs: list[str]) -> bool:
        if not source_cidrs:
            return True
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        for cidr in source_cidrs:
            if address in ipaddress.ip_network(cidr, strict=False):
                return True
        return False

    def _repository_self_registration_key(request: Request) -> dict:
        authorization = request.headers.get("authorization", "")
        if not authorization.lower().startswith("bearer "):
            raise HTTPException(
                status_code=401,
                detail="repository self-registration key required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        split = split_self_registration_key(authorization.split(" ", 1)[1].strip())
        if split is None:
            raise HTTPException(
                status_code=401,
                detail="invalid repository self-registration key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        key_id, secret = split
        record = services.registry.get_repository_self_registration_key(key_id)
        if record is None or record.get("revoked_at"):
            raise HTTPException(
                status_code=401,
                detail="invalid repository self-registration key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        expected = record["secret_hash"]
        actual = hash_token_secret(secret)
        if not hmac.compare_digest(actual, expected):
            raise HTTPException(
                status_code=401,
                detail="invalid repository self-registration key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        source_ip = resolve_source_ip(services.config, request)
        if not _source_allowed(source_ip, record.get("source_cidrs") or []):
            raise HTTPException(status_code=403, detail="repository self-registration source denied")
        return record

    def _repository_username(repository: str) -> str:
        if repository.startswith("git."):
            raise HTTPException(status_code=422, detail="repository must not include git. prefix")
        return f"git.{repository}"

    @app.post(
        "/v1/auth/repository-self-registration",
        response_model=RepositorySelfRegistrationResponse,
        status_code=201,
    )
    def self_register_repository(
        payload: RepositorySelfRegistrationRequest,
        request: Request,
    ) -> RepositorySelfRegistrationResponse:
        key = _repository_self_registration_key(request)
        username = _repository_username(payload.repository)
        existing = services.registry.get_auth_token_by_username(username)
        if existing is not None and not existing.get("revoked_at"):
            raise HTTPException(status_code=409, detail="repository is already registered")
        token_id, secret, token = generate_token()
        try:
            record = services.registry.replace_revoked_auth_token(
                token_id=token_id,
                username=username,
                role="repository",
                namespace=username,
                secret_hash=hash_token_secret(secret),
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        services.registry.mark_repository_self_registration_key_used(key["key_id"])
        services.registry.record_status_event(
            kind="auth",
            level="info",
            status="completed",
            summary=f"repository self-registered {username}",
            details={
                "username": username,
                "namespace": username,
                "registration_key_id": key["key_id"],
                "registration_key_name": key["name"],
                "source_ip": resolve_source_ip(services.config, request),
                "agent_session_id": payload.agent_session_id,
            },
        )
        response = dict(record)
        response["token"] = token
        response["token_file"] = "repo.auth.token"
        response["token_file_comment"] = "kvm-control MCP/API bearer token for this repository."
        return _model_validate(RepositorySelfRegistrationResponse, response)

    def _base_image_output_paths(recipe: dict) -> tuple[Path, Path, Path]:
        suffix = recipe["output_format"]
        image_path = services.config.storage.base_dir / f"{recipe['catalog_image_id']}.{suffix}"
        metadata_path = image_path.with_suffix(image_path.suffix + ".meta")
        suite = recipe.get("suite") or recipe["id"]
        kernel_dir = services.config.storage.base_dir.parent / "vm-kernels" / suite
        return image_path, metadata_path, kernel_dir

    def _layer2_image_output_path(recipe: dict) -> Path:
        return services.config.storage.layer2_dir / f"{recipe['catalog_image_id']}.qcow2"

    def _build_base_image_executor_payload(recipe: dict, operation_id: int, payload: BuildBaseImageRequest) -> dict:
        image_path, metadata_path, kernel_dir = _base_image_output_paths(recipe)
        return {
            "operation_id": operation_id,
            "vm_id": recipe["id"],
            "image_id": recipe["catalog_image_id"],
            "recipe": recipe,
            "image_path": str(image_path),
            "metadata_path": str(metadata_path),
            "kernel_dir": str(kernel_dir),
            "authorized_keys_path": str(services.config.image_factory.authorized_keys_path),
            "image_size_mb": payload.image_size_mb,
            "force": payload.force,
            "publish": payload.publish,
            "notes": payload.notes,
        }

    def _build_layer2_image_executor_payload(
        recipe: dict,
        base_recipe: dict,
        operation_id: int,
        payload: BuildLayer2ImageRequest,
    ) -> dict:
        base_image_path, _, _ = _base_image_output_paths(base_recipe)
        template = template_map(services.config).get(recipe["template_id"])
        return {
            "operation_id": operation_id,
            "vm_id": recipe["id"],
            "image_id": recipe["catalog_image_id"],
            "recipe": recipe,
            "base_image_recipe": base_recipe,
            "base_image_path": str(base_image_path),
            "base_image_format": base_recipe["output_format"],
            "layer2_path": str(_layer2_image_output_path(recipe)),
            "authorized_keys_path": str(services.config.image_factory.authorized_keys_path),
            "template_id": template.id if template else recipe["template_id"],
            "template_architecture": template.architecture if template else "x86_64",
            "template_machine_type": template.machine_type if template else "pc-i440fx-10.0",
            "template_boot_mode": template.boot_mode if template else "disk",
            "template_kernel_path": template.kernel_path if template else None,
            "template_initrd_path": template.initrd_path if template else None,
            "template_kernel_append": template.kernel_append if template else None,
            "force": payload.force,
            "publish": payload.publish,
            "notes": payload.notes,
        }

    def _layer2_build_response(
        recipe: dict,
        base_recipe: dict,
        payload: BuildLayer2ImageRequest,
        operation_id: int,
        build_result: dict,
    ) -> Layer2ImageBuildResponse:
        base_image_path, _, _ = _base_image_output_paths(base_recipe)
        layer2_path = _layer2_image_output_path(recipe)
        response = {
            "operation_id": operation_id,
            "recipe_id": recipe["id"],
            "status": "completed",
            "required_role": "admin",
            "builder_implemented": True,
            "would_publish": payload.publish,
            "force": payload.force,
            "catalog_image_id": recipe["catalog_image_id"],
            "layer2_path": build_result.get("layer2_path") or str(layer2_path),
            "base_image_path": build_result.get("base_image_path") or str(base_image_path),
            "checksum_sha256": build_result.get("checksum_sha256"),
            "size_bytes": build_result.get("size_bytes"),
            "architecture": recipe["architecture"],
            "planned_steps": [" ".join(str(part) for part in command) for command in build_result.get("planned_commands", [])],
            "idempotent": build_result.get("idempotent", False),
            "notes": payload.notes or recipe.get("notes"),
        }
        return _model_validate(Layer2ImageBuildResponse, response)

    def _register_layer2_catalog_image(recipe: dict, build_result: dict) -> None:
        now = datetime.now(UTC).isoformat()
        layer2_path = build_result.get("layer2_path") or str(_layer2_image_output_path(recipe))
        image = {
            "image_id": recipe["catalog_image_id"],
            "namespace": "default",
            "source_vm_id": recipe["id"],
            "source_template_id": recipe["template_id"],
            "workflow_name": "default-layer2-image",
            "workflow_version": "v1",
            "git_ref": None,
            "local_path": layer2_path,
            "remote_path": layer2_path,
            "remote_backend": "local",
            "cache_state": "present",
            "checksum_sha256": build_result.get("checksum_sha256"),
            "size_bytes": build_result.get("size_bytes"),
            "metadata": {
                "visible_name": recipe["id"],
                "description": recipe["description"],
                "keywords": recipe["keywords"],
                "layer2_recipe_id": recipe["id"],
                "base_image_recipe_id": recipe["base_image_recipe_id"],
                "template_id": recipe["template_id"],
                "default_access": recipe["default_access"],
                "network_interfaces": recipe["network_interfaces"],
                "system_packages": recipe["system_packages"],
                "python_venv_tools": recipe["python_venv_tools"],
                "layer2_size_mb": recipe.get("layer2_size_mb"),
                "user_accounts": recipe["user_accounts"],
                "services": recipe["services"],
                "idempotent": build_result.get("idempotent", False),
            },
            "last_published_at": now,
            "last_fetched_at": None,
            "last_retired_at": None,
        }
        services.registry.upsert_image(image)

    def _run_layer2_image_build(recipe: dict, payload: BuildLayer2ImageRequest) -> Layer2ImageBuildResponse:
        if not recipe.get("builder_implemented"):
            raise HTTPException(status_code=501, detail=f"builder is not implemented for layer2 recipe {recipe['id']}")
        base_recipe = _load_base_image_recipe(recipe["base_image_recipe_id"])
        operation_id = services.registry.create_operation(
            "build-layer2-image",
            None,
            "admin",
            "running",
            details={
                "recipe_id": recipe["id"],
                "catalog_image_id": recipe["catalog_image_id"],
                "base_image_recipe_id": recipe["base_image_recipe_id"],
                "force": payload.force,
                "publish": payload.publish,
            },
        )
        try:
            build_result = services.executor.run(
                "build-layer2-image",
                _build_layer2_image_executor_payload(recipe, base_recipe, operation_id, payload),
            )
            if payload.publish:
                _register_layer2_catalog_image(recipe, build_result)
            services.registry.update_operation(operation_id, "completed", details={"recipe_id": recipe["id"], **build_result})
        except Exception as exc:
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            raise HTTPException(status_code=503, detail={"operation_id": operation_id, "reason": str(exc)}) from exc
        return _layer2_build_response(recipe, base_recipe, payload, operation_id, build_result)

    def _sample_run(run_id: int) -> None:
        run = _load_run(run_id)
        disk_bytes, ram_mb, _ = services.monitor._measure_run(run)
        services.registry.record_run_usage_sample(run_id, disk_bytes, ram_mb)

    @api.get("/v1/templates")
    def list_templates() -> list[dict]:
        return services.registry.list_templates()

    @api.get("/v1/capacity")
    def capacity() -> dict:
        return services.registry.current_capacity()

    @api.post("/v1/admin/monitor/sample")
    def sample_monitor() -> dict:
        services.monitor.sample_all_runs()
        return {"status": "ok"}

    @api.get("/v1/auth/whoami")
    def whoami(principal: AuthPrincipal = Depends(current_principal)) -> dict:
        return principal_to_dict(principal)

    @api.get("/v1/environments")
    def describe_environments(principal: AuthPrincipal = Depends(current_principal)) -> dict:
        return _environment_docs(principal)

    @api.post("/v1/admin/auth/tokens", response_model=AuthTokenCreateResponse, status_code=201)
    def create_auth_token(payload: CreateAuthTokenRequest, principal: AuthPrincipal = Depends(require_admin)) -> AuthTokenCreateResponse:
        role = _role_for_username(payload.username, payload.role)
        namespace = _namespace_for_token(payload.username, role)
        token_id, secret, token = generate_token()
        try:
            record = services.registry.create_auth_token(
                token_id=token_id,
                username=payload.username,
                role=role,
                namespace=namespace,
                secret_hash=hash_token_secret(secret),
            )
        except Exception as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        response = dict(record)
        response["token"] = token
        return _model_validate(AuthTokenCreateResponse, response)

    @api.post(
        "/v1/admin/auth/repository-self-registration-keys",
        response_model=RepositorySelfRegistrationKeyCreateResponse,
        status_code=201,
    )
    def create_repository_self_registration_key(
        payload: CreateRepositorySelfRegistrationKeyRequest,
        principal: AuthPrincipal = Depends(require_admin),
    ) -> RepositorySelfRegistrationKeyCreateResponse:
        source_cidrs = [_normalize_source_cidr(value) for value in payload.source_cidrs]
        key_id, secret, key = generate_self_registration_key()
        try:
            record = services.registry.create_repository_self_registration_key(
                key_id=key_id,
                name=payload.name,
                secret_hash=hash_token_secret(secret),
                source_cidrs=source_cidrs,
            )
        except Exception as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        response = dict(record)
        response["key"] = key
        return _model_validate(RepositorySelfRegistrationKeyCreateResponse, response)

    @api.get(
        "/v1/admin/auth/repository-self-registration-keys",
        response_model=list[RepositorySelfRegistrationKeyResponse],
    )
    def list_repository_self_registration_keys(
        principal: AuthPrincipal = Depends(require_admin),
    ) -> list[RepositorySelfRegistrationKeyResponse]:
        return [
            _model_validate(RepositorySelfRegistrationKeyResponse, row)
            for row in services.registry.list_repository_self_registration_keys()
        ]

    @api.post(
        "/v1/admin/auth/repository-self-registration-keys/{key_id}/revoke",
        response_model=RepositorySelfRegistrationKeyResponse,
    )
    def revoke_repository_self_registration_key(
        key_id: str,
        principal: AuthPrincipal = Depends(require_admin),
    ) -> RepositorySelfRegistrationKeyResponse:
        record = services.registry.revoke_repository_self_registration_key(key_id)
        if record is None:
            raise HTTPException(status_code=404, detail="repository self-registration key not found")
        return _model_validate(RepositorySelfRegistrationKeyResponse, record)

    @api.get("/v1/admin/auth/tokens", response_model=list[AuthTokenResponse])
    def list_auth_tokens(principal: AuthPrincipal = Depends(require_admin)) -> list[AuthTokenResponse]:
        return [_model_validate(AuthTokenResponse, row) for row in services.registry.list_auth_tokens()]

    @api.post("/v1/admin/auth/tokens/{token_id}/revoke", response_model=AuthTokenResponse)
    def revoke_auth_token(token_id: str, principal: AuthPrincipal = Depends(require_admin)) -> AuthTokenResponse:
        record = services.registry.revoke_auth_token(token_id)
        if record is None:
            raise HTTPException(status_code=404, detail="token not found")
        return _model_validate(AuthTokenResponse, record)

    @api.post("/v1/locks/requests", status_code=201)
    def create_lock_request(request: CreateLockRequest, principal: AuthPrincipal = Depends(current_principal)) -> dict:
        namespace = effective_namespace(principal, request.namespace)
        if request.lease_ttl_seconds is not None and request.lease_ttl_seconds > services.config.leases.max_namespace_lock_ttl_seconds:
            raise HTTPException(status_code=422, detail="lease_ttl_seconds exceeds maximum")
        return _decorate_auth(services.registry.ensure_lock_request(request.resource_id, namespace, ttl_seconds=request.lease_ttl_seconds), principal)

    @api.get("/v1/locks/resources")
    def list_lock_resources() -> list[dict]:
        return services.registry.list_lock_resources()

    @api.get("/v1/locks/resources/{resource_id}/queue")
    def get_lock_queue(resource_id: str) -> list[dict]:
        return services.registry.lock_queue(resource_id)

    @api.get("/v1/locks/requests/{request_id}")
    def get_lock_request(request_id: int) -> dict:
        record = services.registry.get_lock_request(request_id)
        if record is None:
            raise HTTPException(status_code=404, detail="lock request not found")
        return record

    @api.post("/v1/locks/requests/{request_id}/release")
    def release_lock_request(request_id: int, payload: ReleaseLockRequest, principal: AuthPrincipal = Depends(current_principal)) -> dict:
        try:
            record = services.registry.get_lock_request(request_id)
            released_by = effective_namespace(principal, payload.released_by or (record["namespace"] if record else None))
            released = services.registry.release_lock(request_id, released_by)
            if record is not None:
                removed_egress = services.registry.delete_firewall_egress_rules_for_lock(record["namespace"], record["resource_id"])
                if removed_egress:
                    reconcile_firewall_egress(services)
                removed_access = services.registry.delete_firewall_access_rules_for_lock(record["namespace"], record["resource_id"])
                if removed_access:
                    reconcile_firewall_access(services)
            return _decorate_auth(released, principal)
        except KeyError:
            raise HTTPException(status_code=404, detail="lock request not found") from None
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @api.post("/v1/locks/requests/{request_id}/lease/refresh")
    def refresh_lock_lease(request_id: int, payload: RefreshLeaseRequest | None = None, principal: AuthPrincipal = Depends(current_principal)) -> dict:
        try:
            payload = payload or RefreshLeaseRequest()
            if payload.lease_ttl_seconds is not None and payload.lease_ttl_seconds > services.config.leases.max_namespace_lock_ttl_seconds:
                raise HTTPException(status_code=422, detail="lease_ttl_seconds exceeds maximum")
            record = services.registry.get_lock_request(request_id)
            if record is None:
                raise KeyError(request_id)
            namespace = effective_namespace(principal, record["namespace"])
            refreshed = services.registry.refresh_lock_lease(request_id, namespace, ttl_seconds=payload.lease_ttl_seconds)
            return _decorate_auth(refreshed, principal)
        except KeyError:
            raise HTTPException(status_code=404, detail="lock request not found") from None
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @api.get("/v1/images")
    def list_images(
        namespace: str | None = None,
        q: str | None = None,
        keyword: str | None = None,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> list[ImageRecordResponse]:
        if principal.namespace is not None and namespace is None:
            allowed_namespaces = {principal.namespace, "default"}
            images = [
                image
                for image in services.registry.list_images(query=q, keyword=keyword)
                if image.get("namespace") in allowed_namespaces
            ]
            return [_model_validate(ImageRecordResponse, image) for image in images]
        namespace = effective_namespace(principal, namespace) if principal.namespace is not None else namespace
        return [_model_validate(ImageRecordResponse, image) for image in services.registry.list_images(namespace=namespace, query=q, keyword=keyword)]

    @api.get("/v1/images/{image_id}")
    def get_image(image_id: str, principal: AuthPrincipal = Depends(current_principal)) -> ImageRecordResponse:
        image = _load_image(image_id)
        _require_namespace_access(image["namespace"], principal)
        return _model_validate(ImageRecordResponse, image)

    @api.get("/v1/base-image-recipes", response_model=list[BaseImageRecipeResponse])
    def list_base_image_recipes(
        architecture: str | None = None,
        include_development: bool = False,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> list[BaseImageRecipeResponse]:
        recipes = [_load_base_image_recipe(recipe_id) for recipe_id in sorted(base_image_recipes)]
        if architecture is not None:
            recipes = [recipe for recipe in recipes if recipe["architecture"] == architecture]
        if not include_development:
            recipes = [recipe for recipe in recipes if not recipe.get("development_only")]
        return [_model_validate(BaseImageRecipeResponse, recipe) for recipe in recipes]

    @api.get("/v1/base-image-recipes/{recipe_id}", response_model=BaseImageRecipeResponse)
    def get_base_image_recipe(recipe_id: str, principal: AuthPrincipal = Depends(current_principal)) -> BaseImageRecipeResponse:
        return _model_validate(BaseImageRecipeResponse, _load_base_image_recipe(recipe_id))

    @api.get("/v1/layer2-image-recipes", response_model=list[Layer2ImageRecipeResponse])
    def list_layer2_image_recipes(
        architecture: str | None = None,
        base_image_recipe_id: str | None = None,
        keyword: str | None = None,
        include_development: bool = False,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> list[Layer2ImageRecipeResponse]:
        recipes = [_load_layer2_image_recipe(recipe_id) for recipe_id in sorted(layer2_image_recipes)]
        if architecture is not None:
            recipes = [recipe for recipe in recipes if recipe["architecture"] == architecture]
        if base_image_recipe_id is not None:
            recipes = [recipe for recipe in recipes if recipe["base_image_recipe_id"] == base_image_recipe_id]
        if keyword is not None:
            recipes = [recipe for recipe in recipes if _recipe_matches_keyword(recipe, keyword)]
        if not include_development:
            recipes = [recipe for recipe in recipes if not recipe.get("development_only")]
        return [_model_validate(Layer2ImageRecipeResponse, recipe) for recipe in recipes]

    @api.get("/v1/layer2-image-recipes/{recipe_id}", response_model=Layer2ImageRecipeResponse)
    def get_layer2_image_recipe(recipe_id: str, principal: AuthPrincipal = Depends(current_principal)) -> Layer2ImageRecipeResponse:
        return _model_validate(Layer2ImageRecipeResponse, _load_layer2_image_recipe(recipe_id))

    @api.post("/v1/admin/base-image-recipes/{recipe_id}/build", response_model=BaseImageBuildPlanResponse, status_code=202)
    def plan_base_image_build(
        recipe_id: str,
        payload: BuildBaseImageRequest,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> BaseImageBuildPlanResponse:
        _require_admin_token(principal)
        recipe = _load_base_image_recipe(recipe_id)
        if recipe["id"] not in {"ubuntu-24.04-noble-amd64", "devuan-6-excalibur-amd64"}:
            raise HTTPException(status_code=501, detail=f"builder is not implemented for recipe {recipe_id}")
        image_path, metadata_path, kernel_dir = _base_image_output_paths(recipe)
        operation_id = services.registry.create_operation(
            "build-base-image",
            None,
            "admin",
            "running",
            details={
                "recipe_id": recipe_id,
                "catalog_image_id": recipe["catalog_image_id"],
                "builder_implemented": True,
                "force": payload.force,
                "publish": payload.publish,
                "build_default_layer2": payload.build_default_layer2,
                "image_size_mb": payload.image_size_mb,
            },
        )
        layer2_builds: list[Layer2ImageBuildResponse] = []
        try:
            build_result = services.executor.run("build-base-image", _build_base_image_executor_payload(recipe, operation_id, payload))
            if payload.build_default_layer2:
                for layer2_recipe_id in sorted(layer2_image_recipes):
                    layer2_recipe = _load_layer2_image_recipe(layer2_recipe_id)
                    if layer2_recipe["base_image_recipe_id"] != recipe_id:
                        continue
                    if not layer2_recipe.get("auto_build_after_base_image", True):
                        continue
                    if not layer2_recipe.get("builder_implemented"):
                        continue
                    layer2_builds.append(
                        _run_layer2_image_build(
                            layer2_recipe,
                            BuildLayer2ImageRequest(force=payload.force, publish=payload.publish, notes=payload.notes),
                        )
                    )
            services.registry.update_operation(operation_id, "completed", details={"recipe_id": recipe_id, **build_result})
        except Exception as exc:
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            raise HTTPException(status_code=503, detail={"operation_id": operation_id, "reason": str(exc)}) from exc
        response = {
            "operation_id": operation_id,
            "recipe_id": recipe_id,
            "status": "completed",
            "required_role": "admin",
            "builder_implemented": True,
            "would_publish": payload.publish,
            "force": payload.force,
            "image_size_mb": payload.image_size_mb,
            "catalog_image_id": recipe["catalog_image_id"],
            "image_path": build_result.get("image_path") or str(image_path),
            "metadata_path": build_result.get("metadata_path") or str(metadata_path),
            "kernel_dir": build_result.get("kernel_dir") or str(kernel_dir),
            "kernel_path": build_result.get("kernel_path"),
            "initrd_path": build_result.get("initrd_path"),
            "checksum_sha256": build_result.get("checksum_sha256"),
            "size_bytes": build_result.get("size_bytes"),
            "output_format": recipe["output_format"],
            "boot_mode": recipe["boot_mode"],
            "disk_layout": recipe["disk_layout"],
            "method": recipe["method"],
            "architecture": recipe["architecture"],
            "planned_steps": [" ".join(str(part) for part in command) for command in build_result.get("planned_commands", [])],
            "layer2_builds": [
                build.model_dump(mode="json") if hasattr(build, "model_dump") else build.dict()
                for build in layer2_builds
            ],
            "notes": payload.notes or recipe.get("notes"),
        }
        return _model_validate(BaseImageBuildPlanResponse, response)

    @api.post("/v1/admin/layer2-image-recipes/{recipe_id}/build", response_model=Layer2ImageBuildResponse, status_code=202)
    def build_layer2_image(
        recipe_id: str,
        payload: BuildLayer2ImageRequest,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> Layer2ImageBuildResponse:
        _require_admin_token(principal)
        recipe = _load_layer2_image_recipe(recipe_id)
        return _run_layer2_image_build(recipe, payload)

    @api.get("/v1/webroot-artifacts/{namespace}", response_model=list[WebrootArtifactResponse])
    def list_webroot_artifacts(namespace: str, principal: AuthPrincipal = Depends(current_principal)) -> list[WebrootArtifactResponse]:
        namespace = effective_namespace(principal, namespace)
        _, namespace_root = _webroot_artifact_path(namespace, ".keep")
        namespace_root = namespace_root.parent
        if not namespace_root.exists():
            return []
        if not namespace_root.is_dir():
            raise HTTPException(status_code=409, detail="namespace webroot path is not a directory")
        artifacts: list[WebrootArtifactResponse] = []
        root = services.config.storage.webroot_dir.resolve()
        for path in sorted(candidate for candidate in namespace_root.rglob("*") if candidate.is_file()):
            try:
                relative = PurePosixPath(*path.resolve().relative_to(root).parts)
            except ValueError:
                continue
            artifacts.append(_webroot_artifact_response(namespace, relative, path))
        return artifacts

    @api.put("/v1/webroot-artifacts/{namespace}/{artifact_path:path}", response_model=WebrootArtifactResponse)
    async def put_webroot_artifact(
        namespace: str,
        artifact_path: str,
        request: Request,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> WebrootArtifactResponse:
        namespace = effective_namespace(principal, namespace)
        relative, target = _webroot_artifact_path(namespace, artifact_path)
        body = await request.body()
        if len(body) > MAX_WEBROOT_ARTIFACT_BYTES:
            raise HTTPException(status_code=413, detail=f"artifact exceeds {MAX_WEBROOT_ARTIFACT_BYTES} byte limit")
        if target.exists() and target.is_dir():
            raise HTTPException(status_code=409, detail="artifact path is a directory")
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_name(f".{target.name}.tmp-{time.time_ns()}")
        temp.write_bytes(body)
        temp.chmod(0o644)
        temp.replace(target)
        return _webroot_artifact_response(namespace, relative, target)

    @api.delete("/v1/webroot-artifacts/{namespace}/{artifact_path:path}", response_model=WebrootArtifactDeleteResponse)
    def delete_webroot_artifact(
        namespace: str,
        artifact_path: str,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> WebrootArtifactDeleteResponse:
        namespace = effective_namespace(principal, namespace)
        relative, target = _webroot_artifact_path(namespace, artifact_path)
        if not target.exists():
            raise HTTPException(status_code=404, detail="webroot artifact not found")
        if target.is_dir():
            raise HTTPException(status_code=409, detail="artifact path is a directory")
        target.unlink()
        _remove_empty_webroot_parents(target, namespace)
        return _model_validate(
            WebrootArtifactDeleteResponse,
            {
                "namespace": namespace,
                "path": str(PurePosixPath(*relative.parts[1:])),
                "public_path": f"/{relative.as_posix()}",
                "deleted": True,
            },
        )

    @api.get("/v1/testsuite-dependencies")
    def list_testsuite_dependency_documents(
        namespace: str | None = None,
        testsuite_id: str | None = None,
        image_id: str | None = None,
        artifact_id: str | None = None,
        status: str | None = None,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> list[TestsuiteDependencyDocumentResponse]:
        namespace = effective_namespace(principal, namespace) if principal.namespace is not None else namespace
        if status is not None and status not in {"active", "obsolete"}:
            raise HTTPException(status_code=422, detail="status must be active or obsolete")
        return [
            _model_validate(TestsuiteDependencyDocumentResponse, row)
            for row in services.registry.list_testsuite_dependency_documents(
                namespace=namespace,
                testsuite_id=testsuite_id,
                image_id=image_id,
                artifact_id=artifact_id,
                status=status,
            )
        ]

    @api.get("/v1/testsuite-dependencies/graph")
    def get_testsuite_dependency_graph(
        namespace: str | None = None,
        testsuite_id: str | None = None,
        image_id: str | None = None,
        artifact_id: str | None = None,
        status: str | None = None,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> dict:
        namespace = effective_namespace(principal, namespace) if principal.namespace is not None else namespace
        if status is not None and status not in {"active", "obsolete"}:
            raise HTTPException(status_code=422, detail="status must be active or obsolete")
        return services.registry.testsuite_dependency_graph(
            namespace=namespace,
            testsuite_id=testsuite_id,
            image_id=image_id,
            artifact_id=artifact_id,
            status=status,
        )

    @api.get("/v1/testsuite-dependencies/{document_id}")
    def get_testsuite_dependency_document(document_id: int, principal: AuthPrincipal = Depends(current_principal)) -> TestsuiteDependencyDocumentResponse:
        row = services.registry.get_testsuite_dependency_document(document_id)
        if row is None:
            raise HTTPException(status_code=404, detail="testsuite dependency document not found")
        _require_namespace_access(row["namespace"], principal)
        return _model_validate(TestsuiteDependencyDocumentResponse, row)

    @api.post("/v1/testsuite-dependencies", status_code=201)
    def create_testsuite_dependency_document(
        payload: CreateTestsuiteDependencyDocumentRequest,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> TestsuiteDependencyDocumentResponse:
        payload.namespace = effective_namespace(principal, payload.namespace)
        missing_images = [image_id for image_id in payload.image_ids if services.registry.get_image(image_id) is None]
        if missing_images:
            raise HTTPException(status_code=422, detail={"reason": "unknown image_id", "image_ids": missing_images})
        artifacts = []
        for artifact in payload.artifacts:
            item = artifact.model_dump() if hasattr(artifact, "model_dump") else artifact.dict()
            if item.get("checksum_sha256"):
                item["checksum_sha256"] = item["checksum_sha256"].lower()
            artifacts.append(item)
        row = services.registry.upsert_testsuite_dependency_document(
            namespace=payload.namespace,
            testsuite_id=payload.testsuite_id,
            testsuite_version=payload.testsuite_version,
            git_ref=payload.git_ref,
            image_ids=payload.image_ids,
            artifacts=artifacts,
            status=payload.status,
            notes=payload.notes,
            metadata=payload.metadata,
        )
        return _model_validate(TestsuiteDependencyDocumentResponse, row)

    @api.delete("/v1/testsuite-dependencies/{document_id}")
    def delete_testsuite_dependency_document(document_id: int) -> dict:
        row = services.registry.delete_testsuite_dependency_document(document_id)
        if row is None:
            raise HTTPException(status_code=404, detail="testsuite dependency document not found")
        return {"deleted": row}

    @api.get("/v1/firewall/egress-rules")
    def list_firewall_egress_rules(namespace: str | None = None, principal: AuthPrincipal = Depends(current_principal)) -> list[FirewallEgressRuleResponse]:
        namespace = effective_namespace(principal, namespace) if principal.namespace is not None else namespace
        return [
            _model_validate(FirewallEgressRuleResponse, _canonicalize_firewall_egress_row(row))
            for row in services.registry.list_firewall_egress_rules(namespace=namespace)
        ]

    @api.post("/v1/firewall/egress-rules", status_code=201)
    def create_firewall_egress_rule(payload: CreateFirewallEgressRuleRequest, principal: AuthPrincipal = Depends(current_principal)) -> FirewallEgressRuleResponse:
        namespace = effective_namespace(principal, payload.namespace)
        granted, reason = ensure_lock(namespace, payload.lock_resource_id)
        if not granted:
            raise HTTPException(status_code=423, detail={"reason": reason})
        requested_target = payload.target_cidr if payload.target_cidr is not None else payload.target_ip
        mode = "cidr" if payload.mode == "single_ip" else payload.mode
        if mode == "cidr" and requested_target is None:
            raise HTTPException(status_code=422, detail="target_cidr is required for cidr mode")
        if mode == "allow_all" and requested_target is not None:
            raise HTTPException(status_code=422, detail="target_cidr must be omitted for allow_all mode")
        target_cidr = _normalize_target_cidr(requested_target) if requested_target is not None else None
        row = services.registry.create_firewall_egress_rule(
            namespace=namespace,
            lock_resource_id=payload.lock_resource_id,
            mode=mode,
            target_cidr=target_cidr,
        )
        reconcile_firewall_egress(services)
        return _model_validate(FirewallEgressRuleResponse, _canonicalize_firewall_egress_row(row))

    @api.delete("/v1/firewall/egress-rules/{rule_id}")
    def delete_firewall_egress_rule(rule_id: int) -> dict:
        row = services.registry.delete_firewall_egress_rule(rule_id)
        if row is None:
            raise HTTPException(status_code=404, detail="firewall egress rule not found")
        reconcile_firewall_egress(services)
        return {"deleted": _canonicalize_firewall_egress_row(row)}

    @api.get("/v1/firewall/access-rules")
    def list_firewall_access_rules(namespace: str | None = None, principal: AuthPrincipal = Depends(current_principal)) -> list[FirewallAccessRuleResponse]:
        namespace = effective_namespace(principal, namespace) if principal.namespace is not None else namespace
        return [_model_validate(FirewallAccessRuleResponse, row) for row in services.registry.list_firewall_access_rules(namespace=namespace)]

    @api.post("/v1/firewall/access-rules", status_code=201)
    def create_firewall_access_rule(payload: CreateFirewallAccessRuleRequest, principal: AuthPrincipal = Depends(current_principal)) -> FirewallAccessRuleResponse:
        namespace = effective_namespace(principal, payload.namespace)
        require_zone(principal, payload.target_zone)
        granted, reason = ensure_lock(namespace, payload.lock_resource_id)
        if not granted:
            raise HTTPException(status_code=423, detail={"reason": reason})
        source_cidr = _normalize_source_cidr(payload.source_cidr)
        row = services.registry.create_firewall_access_rule(
            namespace=namespace,
            lock_resource_id=payload.lock_resource_id,
            target_zone=payload.target_zone,
            source_cidr=source_cidr,
        )
        reconcile_firewall_access(services)
        return _model_validate(FirewallAccessRuleResponse, row)

    @api.delete("/v1/firewall/access-rules/{rule_id}")
    def delete_firewall_access_rule(rule_id: int) -> dict:
        row = services.registry.delete_firewall_access_rule(rule_id)
        if row is None:
            raise HTTPException(status_code=404, detail="firewall access rule not found")
        reconcile_firewall_access(services)
        return {"deleted": row}

    @api.get("/v1/endpoint-workarounds")
    def list_endpoint_workaround_rules(
        namespace: str | None = None,
        lock_resource_id: str | None = None,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> list[EndpointWorkaroundRuleResponse]:
        namespace = effective_namespace(principal, namespace) if principal.namespace is not None else namespace
        return [
            _model_validate(EndpointWorkaroundRuleResponse, row)
            for row in services.registry.list_endpoint_workaround_rules(namespace=namespace, lock_resource_id=lock_resource_id)
        ]

    @api.post("/v1/endpoint-workarounds", status_code=201)
    def create_endpoint_workaround_rule(
        payload: CreateEndpointWorkaroundRuleRequest,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> EndpointWorkaroundRuleResponse:
        namespace = effective_namespace(principal, payload.namespace)
        granted, reason = ensure_lock(namespace, payload.lock_resource_id)
        if not granted:
            raise HTTPException(status_code=423, detail={"reason": reason})
        if payload.kind == "fqdn":
            value = _normalize_fqdn(payload.value)
            if payload.workaround_type != "hosts_entry":
                raise HTTPException(status_code=422, detail="fqdn endpoint workarounds must use hosts_entry")
        else:
            value = _normalize_single_ipv4(payload.value, "value")
            if payload.workaround_type != "dnat":
                raise HTTPException(status_code=422, detail="ip endpoint workarounds must use dnat")
        target_ip = _normalize_single_ipv4(payload.target_ip, "target_ip")
        apply_on = _normalize_apply_on(payload.apply_on)
        row = services.registry.create_endpoint_workaround_rule(
            namespace=namespace,
            lock_resource_id=payload.lock_resource_id,
            kind=payload.kind,
            value=value,
            workaround_type=payload.workaround_type,
            target_ip=target_ip,
            apply_on=apply_on,
            maps_to_service=payload.maps_to_service,
            manifest_id=payload.manifest_id,
            constraint_id=payload.constraint_id,
            notes=payload.notes,
            metadata=payload.metadata,
        )
        return _model_validate(EndpointWorkaroundRuleResponse, row)

    @api.delete("/v1/endpoint-workarounds/{rule_id}")
    def delete_endpoint_workaround_rule(rule_id: int, principal: AuthPrincipal = Depends(current_principal)) -> dict:
        row = services.registry.get_endpoint_workaround_rule(rule_id)
        if row is None:
            raise HTTPException(status_code=404, detail="endpoint workaround rule not found")
        _require_namespace_access(row["namespace"], principal)
        deleted = services.registry.delete_endpoint_workaround_rule(rule_id)
        return {"deleted": deleted}

    @api.post("/v1/images/publish", response_model=ImageActionResponse, status_code=202)
    def publish_image(payload: PublishImageRequest, principal: AuthPrincipal = Depends(current_principal)) -> ImageActionResponse:
        _require_admin_token(principal)
        if services.registry.get_image(payload.image_id) is not None:
            raise HTTPException(status_code=409, detail="image already exists")
        vm = _load_vm(payload.source_vm_id)
        _require_vm_access(vm, principal)
        if vm["power_state"] != "stopped":
            raise HTTPException(status_code=422, detail="source vm must be stopped before publishing image")
        source_layer2_path = str(services.config.storage.layer2_dir / f"{vm['namespace']}--{vm['vm_slot']}--promoted.qcow2")
        local_path = source_layer2_path
        remote_path = _image_remote_path(payload.image_id)
        image = {
            "image_id": payload.image_id,
            "namespace": vm["namespace"],
            "source_vm_id": vm["vm_id"],
            "source_template_id": vm["template_id"],
            "workflow_name": payload.workflow_name,
            "workflow_version": payload.workflow_version,
            "git_ref": payload.git_ref,
            "local_path": local_path,
            "remote_path": remote_path,
            "remote_backend": services.config.storage.image_remote_backend,
            "cache_state": "present",
            "checksum_sha256": None,
            "size_bytes": None,
            "metadata": {
                "visible_name": payload.visible_name,
                "comment": payload.comment,
                "tags": payload.tags,
                "source_vm_slot": vm["vm_slot"],
                "test_id": "basic-vm-handling.v1",
            },
            "last_published_at": None,
            "last_fetched_at": None,
            "last_retired_at": None,
        }
        operation_id = services.registry.create_operation("publish-image", vm["vm_id"], vm["namespace"], "running", details={"image_id": payload.image_id})
        executor_results: list[dict] = []
        try:
            executor_results.append(services.executor.run("publish-image", _image_executor_payload(image, operation_id, source_layer2_path=source_layer2_path)))
            publish_result = executor_results[-1]
            image["checksum_sha256"] = publish_result.get("checksum_sha256")
            image["size_bytes"] = publish_result.get("size_bytes")
            image["last_published_at"] = publish_result.get("published_at")
            stored = services.registry.upsert_image(image)
            services.registry.update_operation(operation_id, "completed", details={"image_id": payload.image_id, **publish_result})
        except Exception as exc:
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            raise HTTPException(status_code=503, detail={"operation_id": operation_id, "reason": str(exc)}) from exc
        return image_response_for(stored, operation_id, "publish-image", executor_results=executor_results)

    @api.post("/v1/images/{image_id}/fetch", response_model=ImageActionResponse, status_code=202)
    def fetch_image(image_id: str, principal: AuthPrincipal = Depends(current_principal)) -> ImageActionResponse:
        _require_admin_token(principal)
        image = _load_image(image_id)
        _require_namespace_access(image["namespace"], principal)
        operation_id = services.registry.create_operation("fetch-image", None, image["namespace"], "running", details={"image_id": image_id})
        services.registry.patch_image(image_id, cache_state="fetching")
        executor_results: list[dict] = []
        try:
            executor_results.append(services.executor.run("fetch-image", _image_executor_payload(image, operation_id)))
            fetch_result = executor_results[-1]
            stored = services.registry.patch_image(
                image_id,
                cache_state="present",
                checksum_sha256=fetch_result.get("checksum_sha256"),
                size_bytes=fetch_result.get("size_bytes"),
                last_fetched_at=fetch_result.get("fetched_at"),
            )
            services.registry.update_operation(operation_id, "completed", details={"image_id": image_id, **fetch_result})
        except Exception as exc:
            services.registry.patch_image(image_id, cache_state="failed")
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            raise HTTPException(status_code=503, detail={"operation_id": operation_id, "reason": str(exc)}) from exc
        return image_response_for(stored, operation_id, "fetch-image", executor_results=executor_results)

    @api.post("/v1/images/{image_id}/retire", response_model=ImageActionResponse, status_code=202)
    def retire_image(image_id: str, principal: AuthPrincipal = Depends(current_principal)) -> ImageActionResponse:
        _require_admin_token(principal)
        image = _load_image(image_id)
        _require_namespace_access(image["namespace"], principal)
        if services.registry.image_active_vm_count(image_id) > 0:
            raise HTTPException(status_code=409, detail="image is in use by active vms")
        operation_id = services.registry.create_operation("retire-image", None, image["namespace"], "running", details={"image_id": image_id})
        services.registry.patch_image(image_id, cache_state="retiring")
        executor_results: list[dict] = []
        try:
            executor_results.append(services.executor.run("retire-image", _image_executor_payload(image, operation_id)))
            retire_result = executor_results[-1]
            stored = services.registry.patch_image(image_id, cache_state="known", last_retired_at=retire_result.get("retired_at"))
            services.registry.update_operation(operation_id, "completed", details={"image_id": image_id, **retire_result})
        except Exception as exc:
            services.registry.patch_image(image_id, cache_state="failed")
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            raise HTTPException(status_code=503, detail={"operation_id": operation_id, "reason": str(exc)}) from exc
        return image_response_for(stored, operation_id, "retire-image", executor_results=executor_results)

    @api.delete("/v1/images/{image_id}", response_model=ImageActionResponse, status_code=202)
    def delete_image(image_id: str, principal: AuthPrincipal = Depends(current_principal)) -> ImageActionResponse:
        _require_admin_token(principal)
        image = _load_image(image_id)
        _require_namespace_access(image["namespace"], principal)
        if services.registry.image_active_vm_count(image_id) > 0:
            raise HTTPException(status_code=409, detail="image is in use by active vms")
        operation_id = services.registry.create_operation("delete-image", None, image["namespace"], "running", details={"image_id": image_id})
        executor_results: list[dict] = []
        try:
            executor_results.append(services.executor.run("delete-image", _image_executor_payload(image, operation_id)))
            services.registry.update_operation(operation_id, "completed", details={"image_id": image_id, **executor_results[-1]})
            deleted_image = dict(image)
            deleted_image["cache_state"] = "known"
            services.registry.delete_image(image_id)
        except Exception as exc:
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            raise HTTPException(status_code=503, detail={"operation_id": operation_id, "reason": str(exc)}) from exc
        return image_response_for(deleted_image, operation_id, "delete-image", executor_results=executor_results)

    @api.get("/v1/vms")
    def list_vms(principal: AuthPrincipal = Depends(current_principal)) -> list[dict]:
        vms = services.registry.list_vms()
        if principal.namespace is not None:
            vms = [vm for vm in vms if vm["namespace"] == principal.namespace]
        vms = [vm for vm in vms if vm["network_id"] in principal.allowed_zones]
        return [_sync_vm_runtime_state(vm) for vm in vms]

    @api.get("/v1/archived-vms")
    def list_archived_vms(namespace: str | None = None, principal: AuthPrincipal = Depends(current_principal)) -> list[dict]:
        namespace = effective_namespace(principal, namespace) if principal.namespace is not None else namespace
        rows = services.registry.list_archived_vms(namespace=namespace)
        if principal.namespace is None:
            rows = [row for row in rows if row.get("network_id") in principal.allowed_zones]
        return rows

    @api.get("/v1/vms/{vm_id}")
    def get_vm(vm_id: str, principal: AuthPrincipal = Depends(current_principal)) -> dict:
        vm = _load_vm(vm_id)
        _require_vm_access(vm, principal)
        return _sync_vm_runtime_state(vm)

    @api.get("/v1/namespaces/{namespace}/disk-usage")
    def namespace_disk_usage(namespace: str, principal: AuthPrincipal = Depends(current_principal)) -> dict:
        namespace = effective_namespace(principal, namespace)
        return services.registry.namespace_disk_usage(namespace)

    @api.get("/v1/namespaces/{namespace}/ips")
    def namespace_ips(namespace: str, principal: AuthPrincipal = Depends(current_principal)) -> list[dict]:
        namespace = effective_namespace(principal, namespace)
        return services.registry.namespace_ips(namespace)

    @api.get("/v1/runs")
    def list_runs(namespace: str | None = None, principal: AuthPrincipal = Depends(current_principal)) -> list[dict]:
        namespace = effective_namespace(principal, namespace) if principal.namespace is not None else namespace
        return services.registry.list_runs(namespace=namespace)

    @api.get("/v1/runs/{run_id}", response_model=RunResponse)
    def get_run(run_id: int) -> RunResponse:
        return _model_validate(RunResponse, _load_run(run_id))

    @api.get("/v1/operations/{operation_id}")
    def get_operation(operation_id: int) -> dict:
        operation = services.registry.get_operation(operation_id)
        if operation is None:
            raise HTTPException(status_code=404, detail="operation not found")
        return operation

    @api.post("/v1/runs", response_model=RunResponse, status_code=201)
    def create_run(payload: CreateRunRequest, principal: AuthPrincipal = Depends(current_principal)) -> RunResponse:
        payload.namespace = effective_namespace(principal, payload.namespace)
        if payload.selected_tests and not set(payload.selected_tests).issubset(set(payload.declared_tests)):
            raise HTTPException(status_code=422, detail="selected_tests must be a subset of declared_tests")
        for vm_id in payload.vm_ids:
            vm = services.registry.get_vm(vm_id)
            if vm is None or vm["namespace"] != payload.namespace:
                raise HTTPException(status_code=422, detail=f"vm {vm_id} not found in namespace")
        run = services.registry.create_run(
            namespace=payload.namespace,
            workflow_name=payload.workflow_name,
            workflow_version=payload.workflow_version,
            git_ref=payload.git_ref,
            vm_ids=payload.vm_ids,
            declared_tests=payload.declared_tests,
            selected_tests=payload.selected_tests,
        )
        _sample_run(run["id"])
        return _model_validate(RunResponse, run)

    @api.post("/v1/runs/{run_id}/estimate")
    def update_run_estimate(run_id: int, payload: RunEstimateRequest) -> dict:
        _load_run(run_id)
        return services.registry.update_run_estimate(
            run_id=run_id,
            estimated_disk_mb=payload.estimated_disk_mb,
            estimated_ram_mb=payload.estimated_ram_mb,
            estimated_duration_s=payload.estimated_duration_s,
            source=payload.source,
            confidence=payload.confidence,
            notes=payload.notes,
        )

    @api.post("/v1/runs/{run_id}/report", response_model=RunReportResponse, status_code=201)
    def upsert_run_report(run_id: int, payload: RunReportRequest) -> RunReportResponse:
        _load_run(run_id)
        result_userdata = []
        for item in payload.result_userdata:
            row = item.model_dump() if hasattr(item, "model_dump") else item.dict()
            if row.get("checksum_sha256"):
                row["checksum_sha256"] = row["checksum_sha256"].lower()
            result_userdata.append(row)
        report = services.registry.upsert_run_report(
            run_id=run_id,
            report_id=payload.report_id,
            report_uri=payload.report_uri,
            schema_version=payload.schema_version,
            checksum_sha256=payload.checksum_sha256.lower() if payload.checksum_sha256 else None,
            signature_uri=payload.signature_uri,
            signer_id=payload.signer_id,
            validation_status=payload.validation_status,
            result_userdata=result_userdata,
            metadata=payload.metadata,
        )
        return _model_validate(RunReportResponse, report)

    @api.get("/v1/runs/{run_id}/report", response_model=RunReportResponse)
    def get_run_report(run_id: int) -> RunReportResponse:
        _load_run(run_id)
        report = services.registry.get_run_report(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail="run report not found")
        return _model_validate(RunReportResponse, report)

    @api.post("/v1/runs/{run_id}/stages/{stage_id}/start")
    def start_run_stage(run_id: int, stage_id: str, payload: StageStartRequest) -> dict:
        _load_run(run_id)
        return services.registry.start_run_stage(run_id, stage_id, payload.name, payload.order_index)

    @api.post("/v1/runs/{run_id}/stages/{stage_id}/finish")
    def finish_run_stage(run_id: int, stage_id: str, payload: StageFinishRequest) -> dict:
        _load_run(run_id)
        return services.registry.finish_run_stage(run_id, stage_id, payload.status, payload.notes)

    @api.post("/v1/runs/{run_id}/events", status_code=201)
    def create_run_event(run_id: int, payload: RunEventRequest) -> dict:
        run = _load_run(run_id)
        details = _validate_run_event_details(payload, run, services)
        return services.registry.create_run_event(
            run_id=run_id,
            stage_id=payload.stage_id,
            event_type=payload.event_type,
            message=payload.message,
            details=details,
        )

    @api.get("/v1/runs/{run_id}/usage", response_model=RunUsageResponse)
    def get_run_usage(run_id: int) -> RunUsageResponse:
        _sample_run(run_id)
        return _model_validate(RunUsageResponse, services.registry.get_run_usage(run_id))

    @api.get("/v1/runs/{run_id}/events")
    def list_run_events(run_id: int) -> list[dict]:
        _load_run(run_id)
        return services.registry.list_run_events(run_id)

    @api.get("/v1/runs/{run_id}/summary")
    def get_run_summary(run_id: int) -> dict:
        _sample_run(run_id)
        try:
            return services.registry.get_run_summary(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc

    @api.post("/v1/runs/{run_id}/finish")
    def finish_run(run_id: int, payload: FinishRunRequest) -> dict:
        _sample_run(run_id)
        try:
            return services.registry.finish_run(run_id, payload.status, payload.notes)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc

    @api.post("/v1/runs/{run_id}/ignore-for-learning")
    def ignore_run_for_learning(run_id: int, payload: IgnoreRunForLearningRequest) -> dict:
        _load_run(run_id)
        return services.registry.mark_run_learning_excluded(run_id, payload.reason, payload.bug_reference)

    @api.post("/v1/vms", response_model=VmActionResponse, status_code=202)
    def create_vm(payload: CreateVmRequest, principal: AuthPrincipal = Depends(current_principal)) -> VmActionResponse:
        if principal.authenticated and not payload.agent_session_id:
            raise HTTPException(status_code=422, detail="agent_session_id is required for authenticated VM orders")
        namespace = effective_namespace(principal, payload.namespace)
        payload.namespace = namespace
        if payload.network_id == "dev" and "dev" not in principal.allowed_zones and len(principal.allowed_zones) == 1:
            payload.network_id = default_zone(principal)
        require_zone(principal, payload.network_id)
        retention = _default_retention(payload)
        _validate_retention(retention, principal)
        _validate_nested_virtualization(payload.nested_virtualization, principal)
        ssh_public_key = _validate_ssh_public_key(payload.ssh_public_key)
        template = templates.get(payload.template_id)
        if template is None:
            operation_id = services.registry.create_operation(
                action="create",
                vm_id=None,
                namespace=payload.namespace,
                status="rejected",
                rejection_category="policy",
                rejection_reason="unknown template",
            )
            raise HTTPException(status_code=422, detail={"operation_id": operation_id, "reason": "unknown template"})

        existing = services.registry.get_vm_by_slot(payload.namespace, payload.vm_slot)
        if existing is not None:
            raise HTTPException(status_code=409, detail="vm slot already exists")

        vcpus = payload.vcpus or template.default_vcpus
        memory_mb = payload.memory_mb or template.default_memory_mb
        network = network_segments.get(payload.network_id)
        if network is None:
            operation_id = services.registry.create_operation(
                action="create",
                vm_id=None,
                namespace=payload.namespace,
                status="rejected",
                rejection_category="policy",
                rejection_reason="unknown network",
            )
            raise HTTPException(status_code=422, detail={"operation_id": operation_id, "reason": "unknown network"})
        if vcpus > template.max_vcpus or memory_mb > template.max_memory_mb:
            operation_id = services.registry.create_operation(
                action="create",
                vm_id=None,
                namespace=payload.namespace,
                status="rejected",
                rejection_category="policy",
                rejection_reason="template resource limit exceeded",
            )
            raise HTTPException(status_code=422, detail={"operation_id": operation_id, "reason": "template resource limit exceeded"})

        if payload.lock_resource_id:
            granted, reason = ensure_lock(payload.namespace, payload.lock_resource_id)
            if not granted:
                operation_id = services.registry.create_operation(
                    action="create",
                    vm_id=None,
                    namespace=payload.namespace,
                    status="rejected",
                    rejection_category="lock",
                    rejection_reason=reason,
                )
                raise HTTPException(status_code=423, detail={"operation_id": operation_id, "reason": reason})

        admitted, reason = services.registry.ensure_capacity(vcpus, memory_mb)
        if not admitted:
            operation_id = services.registry.create_operation(
                action="create",
                vm_id=None,
                namespace=payload.namespace,
                status="rejected",
                rejection_category="policy",
                rejection_reason=reason,
            )
            raise HTTPException(status_code=422, detail={"operation_id": operation_id, "reason": reason})

        if payload.nested_virtualization:
            active_nested = services.registry.active_nested_virtualization_count(payload.namespace)
            nested_limit = services.config.host.max_nested_virtualization_vms_per_namespace
            if active_nested >= nested_limit:
                operation_id = services.registry.create_operation(
                    action="create",
                    vm_id=None,
                    namespace=payload.namespace,
                    status="rejected",
                    rejection_category="policy",
                    rejection_reason="nested virtualization namespace limit reached",
                    details={"active_nested_virtualization_vms": active_nested, "limit": nested_limit},
                )
                raise HTTPException(
                    status_code=422,
                    detail={"operation_id": operation_id, "reason": "nested virtualization namespace limit reached"},
                )

        if services.registry.active_layer3_count(payload.namespace, payload.template_id) >= services.config.host.max_layer3_per_layer2:
            operation_id = services.registry.create_operation(
                action="create",
                vm_id=None,
                namespace=payload.namespace,
                status="rejected",
                rejection_category="policy",
                rejection_reason="layer3 limit reached",
            )
            raise HTTPException(status_code=422, detail={"operation_id": operation_id, "reason": "layer3 limit reached"})

        reservation = services.registry.reserve_ip(payload.namespace, payload.vm_slot, payload.network_id)
        vm_id = services.registry.next_vm_id(payload.namespace, payload.vm_slot)
        source_image = None
        if payload.image_id:
            source_image = services.registry.get_image(payload.image_id)
            if source_image is None:
                raise HTTPException(status_code=404, detail="image not found")
            if source_image["cache_state"] != "present":
                raise HTTPException(status_code=422, detail={"reason": "image is not present on host"})
            if source_image["source_template_id"] != payload.template_id:
                raise HTTPException(status_code=422, detail={"reason": "image template does not match requested template"})
            layer2_path = Path(source_image["local_path"])
            layer3_path = services.config.storage.layer3_dir / f"{payload.namespace}--{payload.vm_slot}.qcow2"
        else:
            layer2_path, layer3_path = build_paths(payload.namespace, payload.template_id, payload.vm_slot)
        operation_id = services.registry.create_operation(
            action="create",
            vm_id=vm_id,
            namespace=payload.namespace,
            status="running",
            details={"autostart": payload.autostart},
        )

        vm = services.registry.upsert_vm(
            {
                "vm_id": vm_id,
                "namespace": payload.namespace,
                "vm_slot": payload.vm_slot,
                "template_id": payload.template_id,
                "network_id": payload.network_id,
                "vcpus": vcpus,
                "memory_mb": memory_mb,
                "estimated_layer3_growth_mb": payload.estimated_layer3_growth_mb,
                "reserved_ip": reservation["reserved_ip"],
                "reserved_mac": reservation["reserved_mac"],
                "power_state": "starting" if payload.autostart else "stopped",
                "readiness_state": "booting" if payload.autostart else "configuring",
                "status": "creating",
                "layer2_path": str(layer2_path),
                "layer2_presence": "present" if source_image is not None else "absent",
                "layer3_path": str(layer3_path),
                "layer3_presence": "absent",
                "pause_reason": None,
                "lock_resource_id": payload.lock_resource_id,
                "source_image_id": payload.image_id,
                "retention": retention,
                "retention_reason": payload.retention_reason,
                "purpose": payload.purpose,
                "agent_session_id": payload.agent_session_id,
                "agent_label": payload.agent_label,
                "handoff": payload.handoff,
                "ssh_public_key": ssh_public_key,
                "nested_virtualization": int(payload.nested_virtualization),
            }
        )

        executor_results: list[dict] = []
        try:
            base_image = services.config.storage.base_dir / template.base_image
            if vm["layer2_presence"] != "present":
                executor_results.append(services.executor.run(
                    "create-layer2",
                    {
                        "operation_id": operation_id,
                        "vm_id": vm_id,
                        "layer2_path": str(layer2_path),
                        "layer3_path": str(layer3_path),
                        "base_image": str(base_image),
                        "base_image_format": template.base_image_format,
                    },
                ))
                vm = services.registry.patch_vm(vm_id, layer2_presence="present")
            elif source_image is not None and not layer2_path.exists():
                raise FileNotFoundError(f"missing prepared image {layer2_path}")
            executor_results.append(services.executor.run(
                "create-layer3",
                {
                    "operation_id": operation_id,
                    "vm_id": vm_id,
                    "layer2_path": str(layer2_path),
                    "layer3_path": str(layer3_path),
                    **({"layer3_size_mb": payload.layer3_size_mb} if payload.layer3_size_mb is not None else {}),
                },
            ))
            vm = services.registry.patch_vm(vm_id, layer3_presence="present")
            if payload.autostart:
                executor_results.append(services.executor.run("start-vm", _vm_executor_payload(vm, operation_id, template_id=payload.template_id)))
                vm = services.registry.patch_vm(
                    vm_id,
                    power_state="running",
                    readiness_state="booting",
                    status="running",
                    pause_reason=None,
                )
            else:
                vm = services.registry.patch_vm(vm_id, power_state="stopped", readiness_state="configuring", status="stopped", pause_reason=None)
            services.registry.update_operation(operation_id, "completed")
        except Exception as exc:
            try:
                services.executor.run("delete-runtime", _vm_executor_payload(vm, operation_id, template_id=payload.template_id))
            except Exception:
                pass
            try:
                services.executor.run(
                    "delete-layer3",
                    {
                        "operation_id": operation_id,
                        "vm_id": vm_id,
                        "layer2_path": str(layer2_path),
                        "layer3_path": str(layer3_path),
                    },
                )
            except Exception:
                pass
            if source_image is None:
                try:
                    services.executor.run(
                        "delete-layer2",
                        {
                            "operation_id": operation_id,
                            "vm_id": vm_id,
                            "layer2_path": str(layer2_path),
                            "layer3_path": str(layer3_path),
                        },
                    )
                except Exception:
                    pass
            services.registry.delete_vm(vm_id)
            services.registry.delete_ip_reservation(payload.namespace, payload.vm_slot)
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            raise HTTPException(status_code=503, detail={"operation_id": operation_id, "reason": str(exc)}) from exc

        return response_for(vm, operation_id, "create", "completed", executor_results=executor_results)

    def _operate_vm(vm_id: str, action: str, executor_action: str, post_update: dict, principal: AuthPrincipal, recreate_layer3: bool = False) -> VmActionResponse:
        vm = _load_vm(vm_id)
        _require_vm_access(vm, principal)
        if vm["lock_resource_id"]:
            granted, reason = ensure_lock(vm["namespace"], vm["lock_resource_id"])
            if not granted:
                operation_id = services.registry.create_operation(action, vm_id, vm["namespace"], "rejected", rejection_category="lock", rejection_reason=reason)
                raise HTTPException(status_code=423, detail={"operation_id": operation_id, "reason": reason})

        if action in {"start", "restart"}:
            admitted, reason = services.registry.ensure_capacity(vm["vcpus"], vm["memory_mb"])
            if not admitted and vm["power_state"] != "running":
                operation_id = services.registry.create_operation(action, vm_id, vm["namespace"], "rejected", rejection_category="policy", rejection_reason=reason)
                raise HTTPException(status_code=422, detail={"operation_id": operation_id, "reason": reason})

        operation_id = services.registry.create_operation(action, vm_id, vm["namespace"], "running")
        transient_status = {
            "revert": "reverting",
            "stop": "stopping",
            "poweroff": "stopping",
            "pause": "running",
            "resume": "running",
        }.get(action, "creating")
        services.registry.patch_vm(vm_id, status=transient_status)
        executor_results: list[dict] = []
        try:
            template = templates.get(vm["template_id"])
            if template is None:
                raise HTTPException(status_code=422, detail="unknown template")
            if recreate_layer3 and vm["layer3_presence"] != "present":
                executor_results.append(services.executor.run(
                    "create-layer3",
                    {
                        "operation_id": operation_id,
                        "vm_id": vm_id,
                        "layer2_path": vm["layer2_path"],
                        "layer3_path": vm["layer3_path"],
                    },
                ))
                vm = services.registry.patch_vm(vm_id, layer3_presence="present")

            executor_results.append(services.executor.run(executor_action, _vm_executor_payload(vm, operation_id, template_id=template.id)))
            vm = services.registry.patch_vm(vm_id, **post_update)
            services.registry.update_operation(operation_id, "completed")
        except Exception as exc:
            vm = services.registry.patch_vm(vm_id, power_state="failed", readiness_state="failed", status="failed")
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            raise HTTPException(status_code=503, detail={"operation_id": operation_id, "reason": str(exc)}) from exc
        return response_for(vm, operation_id, action, "completed", executor_results=executor_results)

    @api.post("/v1/vms/{vm_id}/start", response_model=VmActionResponse, status_code=202)
    def start_vm(vm_id: str, principal: AuthPrincipal = Depends(current_principal)) -> VmActionResponse:
        vm = _load_vm(vm_id)
        return _operate_vm(
            vm_id,
            "start",
            "start-vm",
            {"power_state": "running", "readiness_state": "booting", "status": "running", "pause_reason": None},
            principal,
            recreate_layer3=vm["layer3_presence"] != "present",
        )

    @api.post("/v1/vms/{vm_id}/stop", response_model=VmActionResponse, status_code=202)
    def stop_vm(vm_id: str, principal: AuthPrincipal = Depends(current_principal)) -> VmActionResponse:
        return _operate_vm(
            vm_id,
            "stop",
            "stop-vm",
            {"power_state": "stopped", "readiness_state": "configuring", "status": "stopped", "pause_reason": None},
            principal,
        )

    @api.post("/v1/vms/{vm_id}/poweroff", response_model=VmActionResponse, status_code=202)
    def poweroff_vm(vm_id: str, principal: AuthPrincipal = Depends(current_principal)) -> VmActionResponse:
        return _operate_vm(
            vm_id,
            "poweroff",
            "poweroff-vm",
            {"power_state": "stopped", "readiness_state": "configuring", "status": "stopped", "pause_reason": None},
            principal,
        )

    @api.post("/v1/vms/{vm_id}/pause", response_model=VmActionResponse, status_code=202)
    def pause_vm(vm_id: str, principal: AuthPrincipal = Depends(current_principal)) -> VmActionResponse:
        return _operate_vm(
            vm_id,
            "pause",
            "pause-vm",
            {"power_state": "paused", "status": "paused", "pause_reason": "manual"},
            principal,
        )

    @api.post("/v1/vms/{vm_id}/resume", response_model=VmActionResponse, status_code=202)
    def resume_vm(vm_id: str, principal: AuthPrincipal = Depends(current_principal)) -> VmActionResponse:
        return _operate_vm(
            vm_id,
            "resume",
            "resume-vm",
            {"power_state": "running", "status": "running", "pause_reason": None},
            principal,
        )

    @api.post("/v1/vms/{vm_id}/restart", response_model=VmActionResponse, status_code=202)
    def restart_vm(vm_id: str, principal: AuthPrincipal = Depends(current_principal)) -> VmActionResponse:
        return _operate_vm(
            vm_id,
            "restart",
            "restart-vm",
            {"power_state": "running", "readiness_state": "booting", "status": "running", "pause_reason": None},
            principal,
            recreate_layer3=True,
        )

    @api.post("/v1/vms/{vm_id}/mark-ready")
    def mark_vm_ready(vm_id: str, principal: AuthPrincipal = Depends(current_principal)) -> None:
        vm = _load_vm(vm_id)
        _require_vm_access(vm, principal)
        operation_id = services.registry.create_operation(
            "mark-ready",
            vm_id,
            vm["namespace"],
            "rejected",
            rejection_category="state",
            rejection_reason="readiness is API-owned; use wait-ready",
        )
        raise HTTPException(
            status_code=410,
            detail={
                "operation_id": operation_id,
                "reason": "readiness is API-owned; use POST /v1/vms/{vm_id}/wait-ready",
            },
        )

    def _wait_ready_response(
        vm: dict,
        *,
        ready: bool,
        started_at: float,
        timed_out: bool = False,
        reason: str | None = None,
        readiness_probe: str = "root_ssh_command",
        ssh_login_verified: bool | None = None,
    ) -> WaitVmReadyResponse:
        verified = ready if ssh_login_verified is None else ssh_login_verified
        return _model_validate(
            WaitVmReadyResponse,
            {
                "vm_id": vm["vm_id"],
                "namespace": vm["namespace"],
                "ready": ready,
                "timed_out": timed_out,
                "elapsed_s": round(time.monotonic() - started_at, 3),
                "power_state": vm["power_state"],
                "readiness_state": vm["readiness_state"],
                "reserved_ip": vm["reserved_ip"],
                "ssh_target": f"root@{vm['reserved_ip']}",
                "readiness_probe": readiness_probe,
                "ssh_login_verified": verified,
                "scp_verified": False,
                "current_ip": vm.get("current_ip"),
                "reason": reason,
            },
        )

    @api.post("/v1/vms/{vm_id}/wait-ready", response_model=WaitVmReadyResponse)
    def wait_vm_ready(
        vm_id: str,
        payload: WaitVmReadyRequest | None = None,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> WaitVmReadyResponse:
        payload = payload or WaitVmReadyRequest()
        started_at = time.monotonic()
        deadline = started_at + payload.timeout_s
        operation_id: int | None = None
        last_ssh_error: str | None = None
        while True:
            vm = _sync_vm_runtime_state(_load_vm(vm_id))
            _require_vm_access(vm, principal)
            if vm["readiness_state"] == "ready" and not payload.check_ssh:
                return _wait_ready_response(vm, ready=True, started_at=started_at, ssh_login_verified=False)
            if vm["readiness_state"] == "failed" or vm["power_state"] == "failed":
                return _wait_ready_response(vm, ready=False, started_at=started_at, reason="VM is failed")
            if vm["power_state"] != "running":
                return _wait_ready_response(vm, ready=False, started_at=started_at, reason="VM is not running")
            if payload.check_ssh:
                if operation_id is None:
                    operation_id = services.registry.create_operation(
                        "wait-ready",
                        vm_id,
                        vm["namespace"],
                        "running",
                        details={"reserved_ip": vm["reserved_ip"], "probe": "root_ssh_command"},
                    )
                try:
                    probe = services.executor.run(
                        "wait-ssh",
                        {
                            "operation_id": operation_id,
                            "vm_id": vm_id,
                            "namespace": vm["namespace"],
                            "reserved_ip": vm["reserved_ip"],
                            "timeout_s": min(15, max(1, payload.poll_interval_s)),
                        },
                    )
                except RuntimeError as exc:
                    probe = {"ssh_login_verified": False, "readiness_probe": "root_ssh_command", "error": str(exc)}
                if probe.get("ssh_login_verified"):
                    vm = services.registry.patch_vm(vm_id, readiness_state="ready", status="running")
                    services.registry.update_operation(
                        operation_id,
                        "completed",
                        details={
                            "reserved_ip": vm["reserved_ip"],
                            "probe": probe.get("readiness_probe", "root_ssh_command"),
                            "ssh_login_verified": True,
                            "scp_verified": bool(probe.get("scp_verified", False)),
                        },
                    )
                    return _wait_ready_response(vm, ready=True, started_at=started_at, ssh_login_verified=True)
                last_ssh_error = str(probe.get("error") or "SSH login probe did not succeed")
            elif not payload.check_ssh:
                last_ssh_error = None
            now = time.monotonic()
            if now >= deadline:
                reason = "timed out waiting for root SSH login on reserved_ip" if payload.check_ssh else "timed out waiting for readiness_state=ready"
                if last_ssh_error:
                    reason = f"{reason}: {last_ssh_error}"
                if operation_id is not None:
                    services.registry.update_operation(
                        operation_id,
                        "failed",
                        details={"reserved_ip": vm["reserved_ip"], "probe": "root_ssh_command", "error": last_ssh_error},
                    )
                return _wait_ready_response(
                    vm,
                    ready=False,
                    started_at=started_at,
                    timed_out=True,
                    reason=reason,
                    ssh_login_verified=False,
                )
            time.sleep(min(payload.poll_interval_s, max(0.0, deadline - now)))

    @api.post("/v1/vms/{vm_id}/revert", response_model=VmActionResponse, status_code=202)
    def revert_vm(vm_id: str, principal: AuthPrincipal = Depends(current_principal)) -> VmActionResponse:
        return _operate_vm(
            vm_id,
            "revert",
            "revert-vm",
            {"power_state": "stopped", "readiness_state": "configuring", "status": "stopped", "layer3_presence": "present", "pause_reason": None},
            principal,
        )

    @api.post("/v1/vms/{vm_id}/promote-layer2", response_model=PromoteLayer2Response, status_code=202)
    def promote_vm_layer2(
        vm_id: str,
        payload: PromoteLayer2Request | None = None,
        principal: AuthPrincipal = Depends(current_principal),
    ) -> PromoteLayer2Response:
        payload = payload or PromoteLayer2Request()
        vm = _load_vm(vm_id)
        _require_vm_access(vm, principal)
        if vm["layer3_presence"] != "present":
            operation_id = services.registry.create_operation(
                "promote-layer2",
                vm_id,
                vm["namespace"],
                "rejected",
                rejection_category="policy",
                rejection_reason="layer3 image is not present",
            )
            raise HTTPException(status_code=422, detail={"operation_id": operation_id, "reason": "layer3 image is not present"})
        if vm["power_state"] != "stopped":
            operation_id = services.registry.create_operation(
                "promote-layer2",
                vm_id,
                vm["namespace"],
                "rejected",
                rejection_category="policy",
                rejection_reason="vm must be stopped before promoting layer3",
            )
            raise HTTPException(status_code=422, detail={"operation_id": operation_id, "reason": "vm must be stopped before promoting layer3"})

        template = templates.get(vm["template_id"])
        if template is None:
            operation_id = services.registry.create_operation(
                "promote-layer2",
                vm_id,
                vm["namespace"],
                "rejected",
                rejection_category="policy",
                rejection_reason="unknown template",
            )
            raise HTTPException(status_code=422, detail={"operation_id": operation_id, "reason": "unknown template"})

        target_layer2 = services.config.storage.layer2_dir / f"{vm['namespace']}--{vm['vm_slot']}--promoted.qcow2"
        image_id = payload.image_id or f"{_image_id_component(vm['namespace'])}.{_image_id_component(vm['vm_slot'])}.layer2"
        operation_id = services.registry.create_operation(
            "promote-layer2",
            vm_id,
            vm["namespace"],
            "running",
            details={"target_layer2_path": str(target_layer2), "image_id": image_id},
        )
        executor_results: list[dict] = []
        try:
            result = services.executor.run(
                "convert-layer3-to-layer2",
                {
                    **_vm_executor_payload(vm, operation_id, template_id=template.id),
                    "target_layer2_path": str(target_layer2),
                },
            )
            executor_results.append(result)
            target_path = Path(result["target_layer2_path"])
            supplied_fields = _model_fields_set(payload)
            existing_image = services.registry.get_image(image_id)
            metadata = dict((existing_image or {}).get("metadata") or {})
            if "visible_name" in supplied_fields or "visible_name" not in metadata:
                metadata["visible_name"] = payload.visible_name or metadata.get("visible_name") or f"{vm['namespace']} {vm['vm_slot']} layer2"
            if "description" in supplied_fields or "description" not in metadata:
                metadata["description"] = payload.description if "description" in supplied_fields else metadata.get("description")
            if "keywords" in supplied_fields or "keywords" not in metadata:
                metadata["keywords"] = payload.keywords if "keywords" in supplied_fields else metadata.get("keywords", [])
            metadata.update(
                {
                    "source_vm_slot": vm["vm_slot"],
                    "source_layer3_path": result["source_layer3_path"],
                    "target_layer2_path": result["target_layer2_path"],
                    "promotion_operation_id": operation_id,
                    "replaced_existing_target": result.get("replaced_existing_target", False),
                    "idempotent": result.get("idempotent", False),
                }
            )
            image = {
                "image_id": image_id,
                "namespace": vm["namespace"],
                "source_vm_id": vm["vm_id"],
                "source_template_id": vm["template_id"],
                "workflow_name": "promoted-layer2",
                "workflow_version": "v1",
                "git_ref": None,
                "local_path": str(target_path),
                "remote_path": str(target_path),
                "remote_backend": "local",
                "cache_state": "present",
                "checksum_sha256": None,
                "size_bytes": target_path.stat().st_size if target_path.exists() else result.get("size_bytes"),
                "metadata": metadata,
                "last_published_at": datetime.now(UTC).isoformat(),
                "last_fetched_at": None,
                "last_retired_at": None,
            }
            services.registry.upsert_image(image)
            services.registry.update_operation(
                operation_id,
                "completed",
                details={
                    "source_layer3_path": result["source_layer3_path"],
                    "target_layer2_path": result["target_layer2_path"],
                    "image_id": image_id,
                },
            )
        except Exception as exc:
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            raise HTTPException(status_code=503, detail={"operation_id": operation_id, "reason": str(exc)}) from exc
        return promote_response_for(vm, operation_id, result["source_layer3_path"], result["target_layer2_path"], image_id=image_id, executor_results=executor_results)

    @api.post("/v1/vms/{vm_id}/resize-layer3", response_model=ResizeLayer3Response, status_code=202)
    def resize_vm_layer3(vm_id: str, payload: ResizeLayer3Request, principal: AuthPrincipal = Depends(current_principal)) -> ResizeLayer3Response:
        vm = _sync_vm_runtime_state(_load_vm(vm_id))
        _require_vm_access(vm, principal)
        if vm["layer3_presence"] != "present":
            operation_id = services.registry.create_operation(
                "resize-layer3",
                vm_id,
                vm["namespace"],
                "rejected",
                rejection_category="policy",
                rejection_reason="layer3 image is not present",
            )
            raise HTTPException(status_code=422, detail={"operation_id": operation_id, "reason": "layer3 image is not present"})
        if vm["power_state"] != "stopped":
            operation_id = services.registry.create_operation(
                "resize-layer3",
                vm_id,
                vm["namespace"],
                "rejected",
                rejection_category="policy",
                rejection_reason="vm must be stopped before resizing layer3",
            )
            raise HTTPException(status_code=422, detail={"operation_id": operation_id, "reason": "vm must be stopped before resizing layer3"})

        operation_id = services.registry.create_operation(
            "resize-layer3",
            vm_id,
            vm["namespace"],
            "running",
            details={"requested_new_size_mb": payload.new_size_mb},
        )
        executor_results: list[dict] = []
        try:
            result = services.executor.run(
                "resize-layer3",
                {
                    **_vm_executor_payload(vm, operation_id),
                    "new_virtual_size_mb": payload.new_size_mb,
                },
            )
            executor_results.append(result)
            services.registry.update_operation(
                operation_id,
                "completed",
                details={
                    "layer3_path": result["layer3_path"],
                    "previous_virtual_size_bytes": result["previous_virtual_size_bytes"],
                    "new_virtual_size_bytes": result["new_virtual_size_bytes"],
                },
            )
        except ValueError as exc:
            services.registry.update_operation(operation_id, "rejected", rejection_category="policy", rejection_reason=str(exc))
            raise HTTPException(status_code=422, detail={"operation_id": operation_id, "reason": str(exc)}) from exc
        except Exception as exc:
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            raise HTTPException(status_code=503, detail={"operation_id": operation_id, "reason": str(exc)}) from exc
        return resize_layer3_response_for(
            vm,
            operation_id,
            result["previous_virtual_size_bytes"],
            result["new_virtual_size_bytes"],
            executor_results=executor_results,
        )

    @api.post("/v1/vms/{vm_id}/retention")
    def set_vm_retention(vm_id: str, payload: SetVmRetentionRequest, principal: AuthPrincipal = Depends(current_principal)) -> dict:
        vm = _load_vm(vm_id)
        _require_vm_access(vm, principal)
        _validate_retention(payload.retention, principal)
        updated = services.registry.patch_vm(
            vm_id,
            retention=payload.retention,
            retention_reason=payload.reason,
        )
        services.registry.record_status_event(
            kind="vm",
            level="info",
            status="retention_updated",
            namespace=updated["namespace"],
            vm_id=vm_id,
            summary=f"vm {vm_id} retention set to {payload.retention}",
            details={"retention": payload.retention, "reason": payload.reason},
        )
        return updated

    @api.delete("/v1/vms/{vm_id}", response_model=VmActionResponse, status_code=202)
    def delete_vm(vm_id: str, keep_layer2: bool = True, principal: AuthPrincipal = Depends(current_principal)) -> VmActionResponse:
        vm = _load_vm(vm_id)
        _require_vm_access(vm, principal)
        if not keep_layer2 and vm.get("source_image_id"):
            raise HTTPException(status_code=422, detail="cannot delete shared prepared image through vm delete; delete the image separately")
        vm_response_snapshot = dict(vm)
        operation_id = services.registry.create_operation("delete", vm_id, vm["namespace"], "running")
        executor_results: list[dict] = []
        try:
            executor_results.append(services.executor.run(
                "stop-vm",
                _vm_executor_payload(vm, operation_id),
            ))
            executor_results.append(services.executor.run(
                "delete-layer3",
                {
                    "operation_id": operation_id,
                    "vm_id": vm_id,
                    "layer2_path": vm["layer2_path"],
                    "layer3_path": vm["layer3_path"],
                },
            ))
            layer3_delete_result = executor_results[-1]
            trashed_path = layer3_delete_result.get("trashed_path")
            if trashed_path:
                services.registry.record_archived_vm(
                    vm,
                    trashed_path=trashed_path,
                    reason="delete_vm",
                    metadata={
                        "keep_layer2": keep_layer2,
                        "operation_id": operation_id,
                    },
                )
            if not keep_layer2:
                executor_results.append(services.executor.run(
                    "delete-layer2",
                    {
                        "operation_id": operation_id,
                        "vm_id": vm_id,
                        "layer2_path": vm["layer2_path"],
                        "layer3_path": vm["layer3_path"],
                    },
                ))
            executor_results.append(services.executor.run("delete-runtime", _vm_executor_payload(vm, operation_id)))
            services.registry.delete_vm(vm_id)
            services.registry.update_operation(operation_id, "completed")
        except Exception as exc:
            services.registry.update_operation(operation_id, "failed", rejection_reason=str(exc))
            raise HTTPException(status_code=503, detail={"operation_id": operation_id, "reason": str(exc)}) from exc
        vm_response_snapshot["power_state"] = "stopped"
        vm_response_snapshot["readiness_state"] = "configuring"
        return response_for(vm_response_snapshot, operation_id, "delete", "completed", executor_results=executor_results)

    app.include_router(api)
    app.include_router(create_status_router(services))
    app.mount(
        "/status/assets",
        StaticFiles(directory=status_assets_dir(), html=False),
        name="status-assets",
    )
    app.mount(
        "/",
        StaticFiles(directory=services.config.storage.webroot_dir, html=False),
        name="guest-config-webroot",
    )

    return app


app = create_app()
