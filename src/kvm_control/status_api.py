from __future__ import annotations

import asyncio
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from .service import Services


def status_assets_dir() -> Path:
    return Path(__file__).resolve().parent / "status_assets"


def create_status_router(services: Services) -> APIRouter:
    router = APIRouter()

    @router.get("/status", include_in_schema=False)
    def status_page() -> FileResponse:
        return FileResponse(status_assets_dir() / "index.html")

    @router.get("/status/api/snapshot", include_in_schema=False)
    def status_snapshot() -> JSONResponse:
        return JSONResponse(build_status_snapshot(services))

    @router.websocket("/status/ws")
    async def status_ws(websocket: WebSocket) -> None:
        await websocket.accept()
        after_id = _parse_after_id(websocket.query_params.get("after_id"))
        subscription = services.status_bus.subscribe(after_id=after_id)
        receive_task: asyncio.Task[dict[str, Any]] | None = None
        queue_task: asyncio.Task[dict[str, Any] | None] | None = None
        try:
            for event in subscription.replay:
                await websocket.send_json(event)
            while True:
                if receive_task is None:
                    receive_task = asyncio.create_task(websocket.receive())
                if queue_task is None:
                    queue_task = asyncio.create_task(asyncio.to_thread(subscription.queue.get))
                done, _ = await asyncio.wait({receive_task, queue_task}, return_when=asyncio.FIRST_COMPLETED)
                if receive_task in done:
                    message = receive_task.result()
                    receive_task = None
                    if message.get("type") == "websocket.disconnect":
                        break
                    continue
                event = queue_task.result()
                queue_task = None
                if event is None:
                    break
                await websocket.send_json(event)
        except WebSocketDisconnect:
            return
        finally:
            if receive_task is not None:
                receive_task.cancel()
            if queue_task is not None:
                queue_task.cancel()
            services.status_bus.unsubscribe(subscription.subscriber_id)

    return router


def build_status_snapshot(services: Services) -> dict[str, Any]:
    templates = {template["template_id"]: template for template in services.registry.list_templates()}
    vms = services.registry.list_vms()
    runs = services.registry.active_runs()
    active_run_ids = {int(run["id"]) for run in runs}
    run_stages = {
        run_id: services.registry.get_active_run_stage(run_id)
        for run_id in active_run_ids
    }
    run_usage = {
        run_id: services.registry.get_run_usage(run_id)
        for run_id in active_run_ids
    }
    lock_status = services.registry.list_lock_status()
    recent_events = list(reversed(services.registry.list_status_events(limit=120)))
    active_operations = services.registry.list_operations(statuses=["running", "queued"], limit=100)

    vm_groups: dict[str, list[dict[str, Any]]] = {}
    namespaces: dict[str, dict[str, Any]] = {}
    for vm in vms:
        template = templates.get(vm["template_id"], {})
        namespace = vm["namespace"]
        capabilities = ["nested_kvm"] if bool(vm.get("nested_virtualization")) else []
        vm_view = {
            "vm_id": vm["vm_id"],
            "namespace": namespace,
            "vm_slot": vm["vm_slot"],
            "template_id": vm["template_id"],
            "network_id": vm["network_id"],
            "power_state": vm["power_state"],
            "readiness_state": vm["readiness_state"],
            "status": vm["status"],
            "pause_reason": vm.get("pause_reason"),
            "vcpus": vm["vcpus"],
            "memory_mb": vm["memory_mb"],
            "requested_capabilities": capabilities,
            "granted_capabilities": capabilities,
            "nested_virtualization": bool(vm.get("nested_virtualization")),
            "reserved_ip": vm["reserved_ip"],
            "reserved_mac": vm["reserved_mac"],
            "layer2_path": vm["layer2_path"],
            "layer2_presence": vm["layer2_presence"],
            "layer3_path": vm["layer3_path"],
            "layer3_presence": vm["layer3_presence"],
            "base_image": template.get("base_image"),
            "base_image_format": template.get("base_image_format"),
            "image_chain": [
                template.get("base_image"),
                vm["layer2_path"] if vm["layer2_presence"] == "present" else None,
                vm["layer3_path"] if vm["layer3_presence"] == "present" else None,
            ],
        }
        vm_groups.setdefault(namespace, []).append(vm_view)
        ns = namespaces.setdefault(
            namespace,
            {
                "namespace": namespace,
                "vm_count": 0,
                "running_vm_count": 0,
                "paused_vm_count": 0,
                "active_run_count": 0,
                "queued_lock_count": 0,
                "granted_lock_count": 0,
            },
        )
        ns["vm_count"] += 1
        if vm["power_state"] == "running":
            ns["running_vm_count"] += 1
        if vm["power_state"] == "paused":
            ns["paused_vm_count"] += 1

    for namespace, items in vm_groups.items():
        items.sort(key=lambda item: (item["power_state"] != "running", item["vm_slot"]))

    run_views: list[dict[str, Any]] = []
    for run in runs:
        namespace = run["namespace"]
        namespaces.setdefault(
            namespace,
            {
                "namespace": namespace,
                "vm_count": 0,
                "running_vm_count": 0,
                "paused_vm_count": 0,
                "active_run_count": 0,
                "queued_lock_count": 0,
                "granted_lock_count": 0,
            },
        )["active_run_count"] += 1
        run_views.append(
            {
                "id": run["id"],
                "namespace": namespace,
                "workflow_name": run["workflow_name"],
                "workflow_version": run["workflow_version"],
                "git_ref": run.get("git_ref"),
                "status": run["status"],
                "started_at": run.get("started_at"),
                "active_stage": run_stages.get(int(run["id"])),
                "usage": run_usage.get(int(run["id"])),
            }
        )

    locks: list[dict[str, Any]] = []
    for lock in lock_status:
        if lock["holder_namespace"]:
            namespaces.setdefault(
                lock["holder_namespace"],
                {
                    "namespace": lock["holder_namespace"],
                    "vm_count": 0,
                    "running_vm_count": 0,
                    "paused_vm_count": 0,
                    "active_run_count": 0,
                    "queued_lock_count": 0,
                    "granted_lock_count": 0,
                },
            )["granted_lock_count"] += int(lock["granted_count"])
        queue_items = services.registry.lock_queue(lock["resource_id"])
        for queue_item in queue_items:
            if queue_item["status"] == "queued":
                namespaces.setdefault(
                    queue_item["namespace"],
                    {
                        "namespace": queue_item["namespace"],
                        "vm_count": 0,
                        "running_vm_count": 0,
                        "paused_vm_count": 0,
                        "active_run_count": 0,
                        "queued_lock_count": 0,
                        "granted_lock_count": 0,
                    },
                )["queued_lock_count"] += 1
        locks.append(
            {
                "resource_id": lock["resource_id"],
                "holder_namespace": lock["holder_namespace"],
                "queued_count": int(lock["queued_count"]),
                "granted_count": int(lock["granted_count"]),
                "queue": queue_items,
            }
        )

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "host_capacity": services.registry.current_capacity(),
        "namespaces": sorted(namespaces.values(), key=lambda item: item["namespace"]),
        "vms": vm_groups,
        "runs": run_views,
        "locks": locks,
        "recent_events": recent_events,
        "active_operations": active_operations,
    }


def _parse_after_id(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
