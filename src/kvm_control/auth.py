from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import AppConfig, AuthAclConfig


bearer_security = HTTPBearer(auto_error=False)

ALL_ZONES = ("dev", "stage", "misc", "live")
ALL_CAPABILITIES = ("nested_kvm",)


@dataclass(frozen=True)
class AuthPrincipal:
    username: str
    role: str
    namespace: str | None
    allowed_zones: tuple[str, ...]
    capabilities: tuple[str, ...]
    source_ip: str
    token_id: str | None = None
    authenticated: bool = True
    is_admin: bool = False
    auth_mode: str = "enforced"
    credential_status: str = "valid"
    credential_principal: dict[str, Any] | None = None


def generate_token(token_id: str | None = None) -> tuple[str, str, str]:
    token_id = token_id or secrets.token_hex(12)
    secret = secrets.token_urlsafe(32)
    return token_id, secret, f"kvm_{token_id}_{secret}"


def generate_self_registration_key(key_id: str | None = None) -> tuple[str, str, str]:
    key_id = key_id or secrets.token_hex(12)
    secret = secrets.token_urlsafe(32)
    return key_id, secret, f"kvmreg_{key_id}_{secret}"


def hash_token_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def split_token(token: str) -> tuple[str, str] | None:
    if not token.startswith("kvm_"):
        return None
    parts = token.split("_", 2)
    if len(parts) != 3 or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def split_self_registration_key(token: str) -> tuple[str, str] | None:
    if not token.startswith("kvmreg_"):
        return None
    parts = token.split("_", 2)
    if len(parts) != 3 or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def require_auth(config: AppConfig):
    async def _require(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_security),
    ) -> AuthPrincipal:
        principal = authenticate_request(config, request, credentials)
        request.state.principal = principal
        return principal

    return _require


def current_principal(request: Request) -> AuthPrincipal:
    principal = getattr(request.state, "principal", None)
    if principal is None:
        raise HTTPException(status_code=500, detail="authentication principal missing")
    return principal


def authenticate_request(
    config: AppConfig,
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
) -> AuthPrincipal:
    source_ip = resolve_source_ip(config, request)
    if config.auth.mode == "open":
        return _open_mode_principal(config, request, credentials, source_ip)

    if not config.auth.enabled:
        return AuthPrincipal(
            username="anonymous",
            role="admin",
            namespace=None,
            allowed_zones=ALL_ZONES,
            capabilities=ALL_CAPABILITIES,
            source_ip=source_ip,
            authenticated=False,
            is_admin=True,
            auth_mode="disabled",
            credential_status="disabled",
        )

    return _authenticate_configured_credentials(config, request, credentials, source_ip, require_present=True)


def _authenticate_configured_credentials(
    config: AppConfig,
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
    source_ip: str,
    *,
    require_present: bool,
) -> AuthPrincipal:
    legacy_basic = _authenticate_legacy_basic(config, request.headers.get("authorization", ""))
    if legacy_basic is not None:
        return _with_acl_or_403(config, legacy_basic, source_ip)

    if credentials is None or credentials.scheme.lower() != "bearer":
        if request.headers.get("authorization") and not require_present:
            raise_invalid_auth()
        if not require_present:
            raise_auth_required()
        raise_auth_required()

    token = credentials.credentials
    bootstrap = _authenticate_bootstrap_admin(config, token)
    if bootstrap is not None:
        return _with_acl_or_403(config, bootstrap, source_ip)

    split = split_token(token)
    if split is None:
        raise_invalid_auth()
    token_id, secret = split
    record = request.app.state.services.registry.get_auth_token(token_id)
    if record is None or record.get("revoked_at"):
        raise_invalid_auth()
    expected = record["secret_hash"]
    actual = hash_token_secret(secret)
    if not hmac.compare_digest(actual, expected):
        raise_invalid_auth()
    request.app.state.services.registry.mark_auth_token_used(token_id)
    principal = AuthPrincipal(
        username=record["username"],
        role=record["role"],
        namespace=record["namespace"],
        allowed_zones=(),
        capabilities=(),
        source_ip=source_ip,
        token_id=token_id,
        is_admin=record["role"] == "admin",
    )
    return _with_acl_or_403(config, principal, source_ip)


def _open_mode_principal(
    config: AppConfig,
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
    source_ip: str,
) -> AuthPrincipal:
    if request.headers.get("authorization"):
        credential = _authenticate_configured_credentials(config, request, credentials, source_ip, require_present=False)
        return AuthPrincipal(
            username=credential.username,
            role=credential.role,
            namespace=credential.namespace,
            allowed_zones=credential.allowed_zones,
            capabilities=credential.capabilities,
            source_ip=credential.source_ip,
            token_id=credential.token_id,
            authenticated=credential.authenticated,
            is_admin=credential.is_admin,
            auth_mode="open",
            credential_status="valid",
            credential_principal=_credential_principal_to_dict(credential),
        )
    return AuthPrincipal(
        username="anonymous",
        role="admin",
        namespace=None,
        allowed_zones=ALL_ZONES,
        capabilities=ALL_CAPABILITIES,
        source_ip=source_ip,
        authenticated=False,
        is_admin=True,
        auth_mode="open",
        credential_status="missing",
        credential_principal=None,
    )


def require_admin(principal: AuthPrincipal = Depends(current_principal)) -> AuthPrincipal:
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="admin token required")
    return principal


def effective_namespace(principal: AuthPrincipal, requested: str | None) -> str:
    if principal.role == "dev":
        if not requested:
            raise HTTPException(status_code=422, detail="namespace is required")
        if requested == "dev" or requested.startswith("dev."):
            return requested
        if "." in requested:
            raise HTTPException(status_code=403, detail="namespace denied")
        return f"dev.{requested}"
    if principal.namespace is None:
        if not requested:
            raise HTTPException(status_code=422, detail="namespace is required")
        return requested
    if requested is not None and requested != principal.namespace:
        raise HTTPException(status_code=403, detail="namespace denied")
    return principal.namespace


def require_zone(principal: AuthPrincipal, zone: str) -> None:
    if zone == "net":
        return
    if zone not in principal.allowed_zones:
        raise HTTPException(status_code=403, detail="zone denied")


def default_zone(principal: AuthPrincipal) -> str:
    if len(principal.allowed_zones) == 1:
        return principal.allowed_zones[0]
    return "dev" if "dev" in principal.allowed_zones else principal.allowed_zones[0]


def principal_to_dict(principal: AuthPrincipal) -> dict[str, Any]:
    return {
        "username": principal.username,
        "role": principal.role,
        "namespace": principal.namespace,
        "allowed_zones": list(principal.allowed_zones),
        "capabilities": list(principal.capabilities),
        "source_ip": principal.source_ip,
        "authenticated": principal.authenticated,
        "auth_mode": principal.auth_mode,
        "credential_status": principal.credential_status,
        "credential_principal": principal.credential_principal,
    }


def _credential_principal_to_dict(principal: AuthPrincipal) -> dict[str, Any]:
    return {
        "username": principal.username,
        "role": principal.role,
        "namespace": principal.namespace,
        "allowed_zones": list(principal.allowed_zones),
        "capabilities": list(principal.capabilities),
        "source_ip": principal.source_ip,
        "authenticated": principal.authenticated,
    }


def resolve_source_ip(config: AppConfig, request: Request) -> str:
    peer = request.client.host if request.client else ""
    if _ip_in_cidrs(peer, config.auth.trusted_proxy_cidrs):
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            candidate = forwarded_for.split(",", 1)[0].strip()
            if _valid_ip(candidate):
                return candidate
    return peer


def _authenticate_bootstrap_admin(config: AppConfig, token: str) -> AuthPrincipal | None:
    if config.auth.admin_token and hmac.compare_digest(token, config.auth.admin_token):
        return AuthPrincipal(username="admin", role="admin", namespace=None, allowed_zones=(), capabilities=(), source_ip="", is_admin=True)
    if config.auth.admin_token_hash and hmac.compare_digest(hash_token_secret(token), config.auth.admin_token_hash):
        return AuthPrincipal(username="admin", role="admin", namespace=None, allowed_zones=(), capabilities=(), source_ip="", is_admin=True)
    return None


def _authenticate_legacy_basic(config: AppConfig, authorization: str) -> AuthPrincipal | None:
    if not config.auth.username or not config.auth.password:
        return None
    if not authorization.lower().startswith("basic "):
        return None
    encoded = authorization.split(" ", 1)[1]
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
    except Exception:
        return None
    username, separator, password = decoded.partition(":")
    if not separator:
        return None
    username_ok = hmac.compare_digest(username, config.auth.username)
    password_ok = hmac.compare_digest(password, config.auth.password)
    if not (username_ok and password_ok):
        raise_invalid_auth()
    return AuthPrincipal(username=username, role="admin", namespace=None, allowed_zones=(), capabilities=(), source_ip="", is_admin=True)


def _with_acl_or_403(config: AppConfig, principal: AuthPrincipal, source_ip: str) -> AuthPrincipal:
    zones, capabilities = _acl_policy_for_principal(config.auth.acl, principal.username, principal.role, source_ip)
    if not zones:
        raise HTTPException(status_code=403, detail="access denied")
    return AuthPrincipal(
        username=principal.username,
        role=principal.role,
        namespace=principal.namespace,
        allowed_zones=tuple(zones),
        capabilities=tuple(capabilities),
        source_ip=source_ip,
        token_id=principal.token_id,
        authenticated=principal.authenticated,
        is_admin=principal.is_admin,
        auth_mode=principal.auth_mode,
        credential_status=principal.credential_status,
        credential_principal=principal.credential_principal,
    )


def _acl_policy_for_principal(acls: list[AuthAclConfig], username: str, role: str, source_ip: str) -> tuple[list[str], list[str]]:
    zones: list[str] = []
    capabilities: list[str] = []
    for acl in acls:
        if not _principal_matches(acl.users, username, role):
            continue
        if acl.source_cidrs and not _ip_in_cidrs(source_ip, acl.source_cidrs):
            continue
        for zone in acl.zones:
            if zone not in zones:
                zones.append(zone)
        for capability in acl.capabilities:
            if capability not in capabilities:
                capabilities.append(capability)
    return zones, capabilities


def _principal_matches(patterns: list[str], username: str, role: str) -> bool:
    for pattern in patterns:
        if pattern == username or pattern == role:
            return True
        if pattern.endswith("*") and username.startswith(pattern[:-1]):
            return True
    return False


def _ip_in_cidrs(value: str, cidrs: list[str]) -> bool:
    if not cidrs:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def raise_auth_required() -> None:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def raise_invalid_auth() -> None:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
