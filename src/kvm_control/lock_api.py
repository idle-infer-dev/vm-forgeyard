from __future__ import annotations

import time

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import Response

from .auth import AuthPrincipal, current_principal, effective_namespace, require_auth
from .firewall import reconcile_firewall_access, reconcile_firewall_egress
from .models import CreateLockRequest, RefreshLeaseRequest, ReleaseLockRequest
from .service import Services, build_services


def create_app(services: Services | None = None) -> FastAPI:
    services = services or build_services(start_monitor=False)
    app = FastAPI(
        title="kvm-control lock-api",
        version="0.1.0",
        dependencies=[Depends(require_auth(services.config))],
    )
    app.state.services = services

    @app.middleware("http")
    async def record_request_status(request: Request, call_next) -> Response:
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception as exc:
            services.registry.record_status_event(
                kind="api_request",
                level="error",
                status="failed",
                summary=f"{request.method} {request.url.path} -> 500",
                details={
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": 500,
                    "duration_ms": round((time.perf_counter() - start) * 1000, 3),
                    "error": str(exc),
                },
            )
            raise
        services.registry.record_status_event(
            kind="api_request",
            level="warning" if response.status_code >= 400 else "info",
            status="rejected" if response.status_code >= 400 else "completed",
            summary=f"{request.method} {request.url.path} -> {response.status_code}",
            details={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round((time.perf_counter() - start) * 1000, 3),
            },
        )
        return response

    @app.post("/v1/locks/requests", status_code=201)
    def create_lock_request(request: CreateLockRequest, principal: AuthPrincipal = Depends(current_principal)) -> dict:
        namespace = effective_namespace(principal, request.namespace)
        if request.lease_ttl_seconds is not None and request.lease_ttl_seconds > services.config.leases.max_namespace_lock_ttl_seconds:
            raise HTTPException(status_code=422, detail="lease_ttl_seconds exceeds maximum")
        record = services.registry.ensure_lock_request(request.resource_id, namespace, ttl_seconds=request.lease_ttl_seconds)
        record = dict(record)
        record["authenticated_as"] = principal.username
        record["effective_namespace"] = record.get("namespace")
        return record

    @app.get("/v1/locks/resources")
    def list_resources() -> list[dict]:
        return services.registry.list_lock_resources()

    @app.get("/v1/locks/resources/{resource_id}/queue")
    def get_queue(resource_id: str) -> list[dict]:
        return services.registry.lock_queue(resource_id)

    @app.get("/v1/locks/requests/{request_id}")
    def get_request(request_id: int) -> dict:
        record = services.registry.get_lock_request(request_id)
        if record is None:
            raise HTTPException(status_code=404, detail="lock request not found")
        return record

    @app.post("/v1/locks/requests/{request_id}/release")
    def release_request(request_id: int, payload: ReleaseLockRequest, principal: AuthPrincipal = Depends(current_principal)) -> dict:
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
                services.registry.delete_endpoint_workaround_rules_for_lock(record["namespace"], record["resource_id"])
            released = dict(released)
            released["authenticated_as"] = principal.username
            released["effective_namespace"] = released.get("namespace")
            return released
        except KeyError:
            raise HTTPException(status_code=404, detail="lock request not found") from None
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/locks/requests/{request_id}/lease/refresh")
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
            refreshed = dict(refreshed)
            refreshed["authenticated_as"] = principal.username
            refreshed["effective_namespace"] = refreshed.get("namespace")
            return refreshed
        except KeyError:
            raise HTTPException(status_code=404, detail="lock request not found") from None
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    return app


app = create_app()
