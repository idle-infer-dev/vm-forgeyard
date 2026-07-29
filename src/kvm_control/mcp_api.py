from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from fastapi import FastAPI, Request as FastAPIRequest
from fastapi.responses import JSONResponse, StreamingResponse


MCP_PROTOCOL_VERSION = "2025-06-18"


LAYER_CONCEPT_TEXT = """# kvm-control VM image model

kvm-control uses a three-layer disk model:

- layer1: imported template/base images. These are reference inputs and may live on regular reference storage.
- layer2: reusable namespace/template qcow2 images. These are active shared layers used to avoid rebuilding setup state.
- layer3: per-VM writable qcow2 overlays. These are the disposable or retained runtime state for a single ordered VM.

A typical deployment keeps imported base images and retained catalog blobs under
reference storage, while active writable layer2/layer3 state lives under durable
host-local VM storage.

Testsuite dependency documents link testsuite identity/version to retained image IDs and artifact-server
objects. The dependency document owns the testsuite-to-image/artifact relationship; image lifecycle remains
independent from testsuite artifact churn.
"""


NETWORK_CONCEPT_TEXT = """# kvm-control VM networking model

kvm-control places VMs on named bridge networks. The current production networks are:

- `dev`: development/test-prep VMs, currently backed by the `10.80.1.0/24` bridge.
- `stage`: staging VMs, currently backed by the `10.80.2.0/24` bridge.
- `misc`: admin-reserved miscellaneous and qualification VMs, currently backed by the `10.80.3.0/24` bridge.

When ordering a VM, choose one of the `network_id` values offered by this authenticated MCP server.
kvm-control returns a `reserved_ip` and `reserved_mac` for that VM slot. The guest may initially
appear on a temporary DHCP address from the selected bridge, but that DHCP address is only for
bootstrap. Agents should treat `reserved_ip` as the intended stable address and should not assume
that the first DHCP lease is the final VM address.

Under normal circumstances, agents should connect to the VM through `reserved_ip`. The normal SSH
login for ordered VMs is `root@reserved_ip` unless a template or handoff explicitly says otherwise.
If VM records or inspection results include
`current_ip`, that value is DHCP lease observation for debugging and bootstrap diagnosis only. Do
not use `current_ip` as the normal SSH/API target, do not publish it to tests, and do not treat a
mismatch between `current_ip` and `reserved_ip` as a second usable VM address.

Agents that need SSH access should pass their own OpenSSH public key as `ssh_public_key` when
calling `order_vm`. kvm-control appends that key to root's authorized_keys inside the VM's writable
layer3 during guest bootstrap. If `ssh_public_key` is omitted, access depends on host-default keys
already present in the image and the requesting agent may not have the matching private key.

The target bootstrap flow is owned by kvm-control: boot on DHCP, apply host-required patches, run
the caller's update bundle, configure the reserved static IP inside the guest, verify reserved-IP
SSH reachability, and only then mark the VM ready.

kvm-control installs its guest-owned maintenance as visible cron configuration under
`/etc/cron.d/kvm-control`. Until the next accumulated base-image rebuild, kvm-control injects this
maintenance into each VM's writable layer3 before start; base images and shared layer2 images are
treated as immutable. The cron entry reruns reserved-IP configuration and ext4 root filesystem
growth on reboot; both scripts are idempotent and exit successfully when no change is possible.
Clients should not install competing network configuration for the reserved NIC.
"""


WEBROOT_ARTIFACT_TEXT = """# kvm-control managed webroot artifacts

The control API serves `storage.webroot_dir` directly from `/` for small guest bootstrap and
testsuite files.

Use the HTTP control API to manage namespace-scoped files:

- `PUT /v1/webroot-artifacts/{namespace}/{path}` with the raw file bytes as the request body.
- `GET /v1/webroot-artifacts/{namespace}` to list files visible in that namespace.
- `DELETE /v1/webroot-artifacts/{namespace}/{path}` to remove a file.

After upload, the public guest URL path is `/{namespace}/{path}`. For example, uploading
`PUT /v1/webroot-artifacts/git.repo-a/setup/autostart.sh` makes the file available as
`GET /git.repo-a/setup/autostart.sh`.

Repository tokens may manage only their own namespace. Paths are POSIX-style relative file paths
under the namespace and must not contain `.` or `..` path segments. This MCP server documents the
HTTP API; raw file upload should use the control API directly.
"""


ENDPOINT_WORKAROUND_TEXT = """# kvm-control endpoint workaround rules

Testsuite manifests should use logical service bindings instead of hard-coded environment
FQDNs or IP addresses. When tested software contains a fixed endpoint that cannot be changed
meaningfully by the testsuite, declare it as a fixed endpoint constraint and create a
lock-owned endpoint workaround rule.

Use `hosts_entry` rules for hard-coded FQDNs. The testsuite applies them as dynamic
`/etc/hosts` entries on the VM or VMs listed in `apply_on`.

Use `dnat` rules for hard-coded IPv4 addresses. The testsuite applies them on the VM, router,
or simulation host listed in `apply_on` that controls the relevant traffic path.

Each rule records the fixed literal value, the selected environment's resolved `target_ip`,
the target service name when known, and optional manifest/constraint IDs. Rules are owned by
the namespace lock and are deleted when that lock is released.
"""


TEST_SETUP_LAYER_TEXT = """# kvm-control test setup layer workflow

kvm-control uses layer promotion to separate reusable testsuite setup state from per-run test
state. Agents should treat promotion as a setup-image workflow, not as a way to preserve arbitrary
test execution output.

Recommended flow:

1. Order a setup VM for the intended namespace, template, and network.
2. Let kvm-control perform host-owned base patches, caller setup bundle execution, reserved-IP
   configuration, and readiness verification.
3. Use the ready setup VM only for reusable setup work: package installation, service installation,
   baseline configuration, fixtures, and other state that should seed later test VMs.
4. Verify that the setup state is correct.
5. Stop the VM.
6. Call `promote_vm_layer2` to convert that stopped VM's layer3 into a reusable layer2 image.
7. Publish or otherwise link the resulting image through the testsuite dependency metadata so future
   test runs can request it by image ID.
8. Order later execution VMs from that reusable image. Per-run logs, results, databases, traces, and
   destructive test mutations should remain in those later layer3 overlays and should not be promoted.

Do not promote a VM that contains one-off run output, secrets that should not become a reusable
image, or failed/incomplete setup state. Promotion requires a stopped VM; if the VM is still running,
stop it first and only promote after setup verification is complete.
"""


AGENT_WORKFLOW_TEXT = """# kvm-control agent workflow

Use this MCP server as the primary control surface for VM ordering and lifecycle.

Recommended sequence:

1. Read `kvm-control://environments`, then choose an offered `network_id`.
2. Request a namespace lock with `request_lock`, normally `resource_id=namespace:<namespace>`.
3. If the VM needs small guest bootstrap files, upload them through the HTTP API:
   `PUT /v1/webroot-artifacts/{namespace}/{path}`. The guest can fetch them from `/{namespace}/{path}`.
4. Call `order_vm` with `template_id`, `vm_slot`, `agent_session_id`, and the caller's `ssh_public_key`.
5. Call `wait_for_vm_ready` for the returned `vm_id`.
6. SSH to `root@reserved_ip`; this is the normal login unless the template or handoff says otherwise.
7. Do not use `current_ip` as the normal target.
8. Refresh the namespace lock lease with `refresh_lease` while the VM is in active use.
9. Stop, resize, promote, retain, archive, or delete the VM through MCP lifecycle tools.
10. Release the lock with `release_lock` when the namespace no longer needs protection.

If `ssh_public_key` is omitted, SSH access depends on keys already present in the image and may fail.
If `wait_for_vm_ready` returns `ready=false`, inspect `reason`, `power_state`, `readiness_state`,
and `reserved_ip` before retrying or cleaning up.
"""


@dataclass
class KvmControlHttpClient:
    control_url: str
    lock_url: str
    authorization_header: str | None = None
    forwarded_for: str | None = None
    token: str | None = None
    username: str | None = None
    password: str | None = None
    timeout_s: int = 30

    def get_control(self, path: str, query: dict[str, Any] | None = None) -> Any:
        return self._request("GET", self.control_url, path, query=query)

    def post_control(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        return self._request("POST", self.control_url, path, payload=payload or {})

    def delete_control(self, path: str) -> Any:
        return self._request("DELETE", self.control_url, path)

    def get_lock(self, path: str, query: dict[str, Any] | None = None) -> Any:
        return self._request("GET", self.lock_url, path, query=query)

    def post_lock(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        return self._request("POST", self.lock_url, path, payload=payload or {})

    def _request(
        self,
        method: str,
        base_url: str,
        path: str,
        payload: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        clean_query = {key: value for key, value in (query or {}).items() if value is not None}
        if clean_query:
            url = f"{url}?{urlencode(clean_query)}"
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.authorization_header:
            headers["Authorization"] = self.authorization_header
        elif self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.username and self.password:
            token = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        if self.forwarded_for:
            headers["X-Forwarded-For"] = self.forwarded_for
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout_s) as response:
                body = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {url} failed with HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"{method} {url} failed: {exc.reason}") from exc
        if not body:
            return None
        return json.loads(body)


def create_app(
    control_url: str = "http://127.0.0.1:8000",
    lock_url: str = "http://127.0.0.1:8001",
    username: str | None = None,
    password: str | None = None,
    token: str | None = None,
    client: KvmControlHttpClient | None = None,
) -> FastAPI:
    configured_http = client or KvmControlHttpClient(
        control_url=control_url,
        lock_url=lock_url,
        token=token,
        username=username,
        password=password,
    )
    app = FastAPI(title="kvm-control MCP API", version="0.1.0")

    def request_client(request: FastAPIRequest) -> KvmControlHttpClient:
        if client is not None:
            return client
        authorization = request.headers.get("authorization")
        if authorization:
            return KvmControlHttpClient(
                control_url=control_url,
                lock_url=lock_url,
                authorization_header=authorization,
                forwarded_for=request.client.host if request.client else None,
            )
        return configured_http

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/mcp")
    def mcp_event_stream() -> StreamingResponse:
        async def events():
            yield ": kvm-control MCP stream endpoint is ready\n\n"

        return StreamingResponse(events(), media_type="text/event-stream")

    @app.post("/mcp")
    async def mcp_rpc(request: FastAPIRequest) -> JSONResponse:
        payload = await request.json()
        http = request_client(request)
        if isinstance(payload, list):
            responses = [_handle_rpc(http, item) for item in payload]
            responses = [response for response in responses if response is not None]
            return JSONResponse(responses)
        response = _handle_rpc(http, payload)
        if response is None:
            return JSONResponse(None, status_code=202)
        return JSONResponse(response)

    return app


def _handle_rpc(client: KvmControlHttpClient, request: dict[str, Any]) -> dict[str, Any] | None:
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}
    try:
        if method == "initialize":
            result = {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {},
                    "resources": {},
                },
                "serverInfo": {
                    "name": "kvm-control",
                    "version": "0.1.0",
                },
            }
        elif method == "notifications/initialized":
            return None
        elif method == "tools/list":
            result = {"tools": _tools(_mcp_context(client))}
        elif method == "tools/call":
            result = _call_tool(client, params.get("name"), params.get("arguments") or {})
        elif method == "resources/list":
            result = {"resources": _resources()}
        elif method == "resources/read":
            result = _read_resource(client, params.get("uri"))
        else:
            return _error(request_id, -32601, f"unknown method {method!r}")
    except Exception as exc:
        return _error(request_id, -32000, str(exc))
    if request_id is None:
        return None
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _mcp_context(client: KvmControlHttpClient) -> dict[str, Any]:
    try:
        whoami = client.get_control("/v1/auth/whoami")
        environments = client.get_control("/v1/environments")
        return {"whoami": whoami, "environments": environments, "allowed_zones": whoami.get("allowed_zones") or ["dev", "stage", "misc", "live"]}
    except Exception:
        return {"whoami": None, "environments": None, "allowed_zones": ["dev", "stage", "misc", "live"]}


def _tools(context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    allowed_zones = (context or {}).get("allowed_zones") or ["dev", "stage", "misc", "live"]
    default_network = "dev" if "dev" in allowed_zones else allowed_zones[0]
    principal_namespace = ((context or {}).get("whoami") or {}).get("namespace")
    namespace_required = principal_namespace is None
    namespace_required_fields = ["namespace"] if namespace_required else []
    return [
        {
            "name": "list_templates",
            "description": "List VM templates available for new VM orders.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "get_capacity",
            "description": "Return current VM capacity and usage.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "list_vms",
            "description": (
                "List known VMs and their current state. Use each VM's reserved_ip for normal access; "
                "the normal SSH login is root@reserved_ip unless a template says otherwise. current_ip, "
                "when present, is only a DHCP/bootstrap diagnostic value."
            ),
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "get_vm",
            "description": (
                "Get one VM by vm_id. The normal SSH login is root@reserved_ip unless a template "
                "says otherwise; use reserved_ip for normal API access. current_ip, when present, is "
                "only a DHCP/bootstrap diagnostic value."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["vm_id"],
                "properties": {"vm_id": {"type": "string"}},
                "additionalProperties": False,
            },
        },
        {
            "name": "order_vm",
            "description": (
                "Order a VM through kvm-control. Choose network_id from the enum offered to this authenticated token; "
                "the normal SSH login is root@reserved_ip unless a template says otherwise, and use "
                "reserved_ip for normal API access. Any DHCP address or current_ip seen during boot "
                "is only temporary bootstrap/debug state and should not be used as the normal target. "
                "Provide ssh_public_key with the caller's OpenSSH public key so root@reserved_ip "
                "accepts that agent's SSH key; otherwise access depends on host-default keys already "
                "present in the image and may fail. Use layer3_size_mb when a test needs a larger root disk virtual "
                "size from first boot. agent_session_id is required so the VM can be traced "
                "back to the requesting agent session. By default the VM is started immediately. "
                "After ordering, call wait_for_vm_ready before using SSH."
            ),
            "inputSchema": {
                "type": "object",
                "required": [*namespace_required_fields, "template_id", "vm_slot", "agent_session_id"],
                "properties": {
                    "namespace": {"type": "string"},
                    "template_id": {"type": "string"},
                    "vm_slot": {"type": "string"},
                    "network_id": {"type": "string", "enum": allowed_zones, "default": default_network},
                    "vcpus": {"type": "integer", "minimum": 1},
                    "memory_mb": {"type": "integer", "minimum": 128},
                    "layer3_size_mb": {"type": "integer", "minimum": 1},
                    "lock_resource_id": {"type": "string"},
                    "autostart": {"type": "boolean", "default": True},
                    "image_id": {"type": "string"},
                    "retention": {"type": "string", "enum": ["ephemeral", "keep_stopped", "archive", "protected", "live"]},
                    "retention_reason": {"type": "string"},
                    "purpose": {"type": "string"},
                    "agent_session_id": {"type": "string"},
                    "agent_label": {"type": "string"},
                    "handoff": {"type": "string"},
                    "ssh_public_key": {
                        "type": "string",
                        "description": "Caller OpenSSH public key to append to root's authorized_keys in this VM.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "start_vm",
            "description": "Start an existing stopped VM.",
            "inputSchema": _vm_id_schema(),
        },
        {
            "name": "wait_for_vm_ready",
            "description": (
                "Ask kvm-control to wait until a VM is ready for normal access. The control API owns "
                "the readiness transition and marks the VM ready only after reserved_ip tcp/22 is reachable "
                "when check_ssh is true. On success, use ssh_target, normally root@reserved_ip."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["vm_id"],
                "properties": {
                    "vm_id": {"type": "string"},
                    "timeout_s": {"type": "integer", "minimum": 0, "maximum": 900, "default": 120},
                    "poll_interval_s": {"type": "integer", "minimum": 1, "maximum": 60, "default": 5},
                    "check_ssh": {"type": "boolean", "default": True},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "stop_vm",
            "description": "Gracefully stop a running VM.",
            "inputSchema": _vm_id_schema(),
        },
        {
            "name": "promote_vm_layer2",
            "description": (
                "Promote a stopped setup VM's layer3 image into a reusable layer2 image. "
                "Optionally provide description and keywords so other agents can find and confirm the image later. "
                "Use this only after reusable testsuite setup has been verified; per-run output "
                "and destructive test mutations should stay in later disposable layer3 overlays."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["vm_id"],
                "properties": {
                    "vm_id": {"type": "string"},
                    "image_id": {"type": "string"},
                    "description": {"type": "string"},
                    "visible_name": {"type": "string"},
                    "keywords": {"type": "array", "items": {"type": "string"}},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "resize_vm_layer3",
            "description": (
                "Increase a stopped VM's layer3 root disk virtual size. The VM must be stopped first; "
                "after the host-side resize, the guest partition/filesystem still needs to grow on next boot."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["vm_id", "new_size_mb"],
                "properties": {
                    "vm_id": {"type": "string"},
                    "new_size_mb": {"type": "integer", "minimum": 1},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "set_vm_retention",
            "description": "Update a VM retention mode and optional reason for later inspection or cleanup.",
            "inputSchema": {
                "type": "object",
                "required": ["vm_id", "retention"],
                "properties": {
                    "vm_id": {"type": "string"},
                    "retention": {"type": "string", "enum": ["ephemeral", "keep_stopped", "archive", "protected", "live"]},
                    "reason": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "delete_vm",
            "description": "Delete a VM and move its layer3 image to trash according to host policy.",
            "inputSchema": _vm_id_schema(),
        },
        {
            "name": "list_archived_vms",
            "description": "List archived VM/layer3 records visible to this authenticated namespace or role.",
            "inputSchema": _optional_namespace_schema(),
        },
        {
            "name": "list_images",
            "description": "List retained image catalog records, optionally filtered by namespace, text query, or exact keyword.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "namespace": {"type": "string"},
                    "q": {"type": "string"},
                    "keyword": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "list_base_image_recipes",
            "description": (
                "List pinned base-image factory recipes. This is read-only; base-image build and "
                "import actions are admin-only HTTP API operations and are not exposed as normal MCP tools."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "architecture": {"type": "string", "enum": ["amd64", "arm64", "armhf"]},
                    "include_development": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "list_layer2_image_recipes",
            "description": (
                "List planned default layer2 image recipes, including standard agent sandbox tooling "
                "and disabled-by-default network service lab images. This is read-only; automatic layer2 "
                "creation is admin-owned factory work."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "architecture": {"type": "string", "enum": ["amd64", "arm64", "armhf"]},
                    "base_image_recipe_id": {"type": "string"},
                    "keyword": {"type": "string"},
                    "include_development": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "get_testsuite_dependency_graph",
            "description": "Read the testsuite/image/artifact dependency graph.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "testsuite_id": {"type": "string"},
                    "image_id": {"type": "string"},
                    "artifact_id": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "list_firewall_egress_rules",
            "description": "List dynamic outbound firewall allow rules.",
            "inputSchema": _optional_namespace_schema(),
        },
        {
            "name": "create_firewall_egress_rule",
            "description": "Create a lock-owned outbound firewall allow rule.",
            "inputSchema": {
                "type": "object",
                "required": ["namespace", "lock_resource_id", "mode"],
                "properties": {
                    "namespace": {"type": "string"},
                    "lock_resource_id": {"type": "string"},
                    "mode": {"type": "string", "enum": ["allow_all", "cidr", "single_ip"]},
                    "target_cidr": {"type": "string"},
                    "target_ip": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "delete_firewall_egress_rule",
            "description": "Delete a dynamic outbound firewall allow rule by numeric rule_id.",
            "inputSchema": _rule_id_schema(),
        },
        {
            "name": "list_firewall_access_rules",
            "description": "List dynamic source access firewall rules.",
            "inputSchema": _optional_namespace_schema(),
        },
        {
            "name": "create_firewall_access_rule",
            "description": "Create a lock-owned source access firewall rule.",
            "inputSchema": {
                "type": "object",
                "required": ["namespace", "lock_resource_id", "target_zone", "source_cidr"],
                "properties": {
                    "namespace": {"type": "string"},
                    "lock_resource_id": {"type": "string"},
                    "target_zone": {"type": "string", "enum": ["net", *allowed_zones]},
                    "source_cidr": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "delete_firewall_access_rule",
            "description": "Delete a dynamic source access firewall rule by numeric rule_id.",
            "inputSchema": _rule_id_schema(),
        },
        {
            "name": "list_endpoint_workarounds",
            "description": "List lock-owned fixed endpoint workaround rules for hard-coded FQDNs and IPs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "namespace": {"type": "string"},
                    "lock_resource_id": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "create_endpoint_workaround",
            "description": (
                "Create a lock-owned fixed endpoint workaround. Use kind=fqdn with "
                "workaround_type=hosts_entry for hard-coded FQDNs, and kind=ip with "
                "workaround_type=dnat for hard-coded IPv4 addresses."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["namespace", "lock_resource_id", "kind", "value", "workaround_type", "target_ip", "apply_on"],
                "properties": {
                    "namespace": {"type": "string"},
                    "lock_resource_id": {"type": "string"},
                    "kind": {"type": "string", "enum": ["fqdn", "ip"]},
                    "value": {"type": "string"},
                    "workaround_type": {"type": "string", "enum": ["hosts_entry", "dnat"]},
                    "target_ip": {"type": "string"},
                    "apply_on": {"type": "array", "items": {"type": "string"}},
                    "maps_to_service": {"type": "string"},
                    "manifest_id": {"type": "string"},
                    "constraint_id": {"type": "string"},
                    "notes": {"type": "string"},
                    "metadata": {"type": "object"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "delete_endpoint_workaround",
            "description": "Delete a fixed endpoint workaround rule by numeric rule_id.",
            "inputSchema": _rule_id_schema(),
        },
        {
            "name": "request_lock",
            "description": "Request a FIFO lock for a namespace/resource.",
            "inputSchema": {
                "type": "object",
                "required": [*namespace_required_fields, "resource_id"],
                "properties": {
                    "namespace": {"type": "string"},
                    "resource_id": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "release_lock",
            "description": (
                "Release a lock request by numeric request_id. The released_by value must be the "
                "same namespace that created and owns the lock request, not the resource_id or VM ID."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["request_id"],
                "properties": {
                    "request_id": {"type": "integer"},
                    "released_by": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "refresh_lease",
            "description": (
                "Refresh the lease on a granted namespace lock request. Refreshing the namespace lock "
                "keeps all VMs in that namespace from being auto-shutdown by lease expiry."
            ),
            "inputSchema": {
                "type": "object",
                "required": ["request_id"],
                "properties": {"request_id": {"type": "integer"}},
                "additionalProperties": False,
            },
        },
    ]


def _vm_id_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "required": ["vm_id"],
        "properties": {"vm_id": {"type": "string"}},
        "additionalProperties": False,
    }


def _optional_namespace_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {"namespace": {"type": "string"}},
        "additionalProperties": False,
    }


def _rule_id_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "required": ["rule_id"],
        "properties": {"rule_id": {"type": "integer"}},
        "additionalProperties": False,
    }


def _resources() -> list[dict[str, Any]]:
    return [
        {
            "uri": "kvm-control://concepts/layers",
            "name": "kvm-control layer model",
            "description": "Explains layer1/layer2/layer3 and testsuite dependency graph semantics.",
            "mimeType": "text/markdown",
        },
        {
            "uri": "kvm-control://concepts/networking",
            "name": "kvm-control networking model",
            "description": "Explains dev/stage/misc/live networks, DHCP bootstrap, and reserved IP semantics.",
            "mimeType": "text/markdown",
        },
        {
            "uri": "kvm-control://environments",
            "name": "kvm-control authenticated environments",
            "description": "Describes the environments and zones available to this authenticated token.",
            "mimeType": "application/json",
        },
        {
            "uri": "kvm-control://concepts/test-setup-layers",
            "name": "kvm-control test setup layer workflow",
            "description": "Explains when to promote layer3 to layer2 and how reusable setup images relate to test runs.",
            "mimeType": "text/markdown",
        },
        {
            "uri": "kvm-control://concepts/webroot-artifacts",
            "name": "kvm-control managed webroot artifacts",
            "description": "Explains namespace-scoped HTTP upload, list, delete, and guest fetch paths for webroot files.",
            "mimeType": "text/markdown",
        },
        {
            "uri": "kvm-control://concepts/endpoint-workarounds",
            "name": "kvm-control endpoint workaround rules",
            "description": "Explains hard-coded FQDN /etc/hosts and hard-coded IP DNAT workaround records.",
            "mimeType": "text/markdown",
        },
        {
            "uri": "kvm-control://concepts/agent-workflow",
            "name": "kvm-control agent workflow",
            "description": "Concise VM ordering, readiness, SSH, lease, and cleanup sequence for agents.",
            "mimeType": "text/markdown",
        },
        {
            "uri": "kvm-control://status/overview",
            "name": "kvm-control live overview",
            "description": "Live templates, capacity, VMs, images, and dependency graph snapshot.",
            "mimeType": "application/json",
        },
    ]


def _read_resource(client: KvmControlHttpClient, uri: str | None) -> dict[str, Any]:
    if uri == "kvm-control://concepts/layers":
        return {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": LAYER_CONCEPT_TEXT}]}
    if uri == "kvm-control://concepts/networking":
        return {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": NETWORK_CONCEPT_TEXT}]}
    if uri == "kvm-control://concepts/test-setup-layers":
        return {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": TEST_SETUP_LAYER_TEXT}]}
    if uri == "kvm-control://concepts/webroot-artifacts":
        return {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": WEBROOT_ARTIFACT_TEXT}]}
    if uri == "kvm-control://concepts/endpoint-workarounds":
        return {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": ENDPOINT_WORKAROUND_TEXT}]}
    if uri == "kvm-control://concepts/agent-workflow":
        return {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": AGENT_WORKFLOW_TEXT}]}
    if uri == "kvm-control://environments":
        data = client.get_control("/v1/environments")
        return {"contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps(data, indent=2, sort_keys=True)}]}
    if uri == "kvm-control://status/overview":
        data = {
            "templates": client.get_control("/v1/templates"),
            "capacity": client.get_control("/v1/capacity"),
            "vms": client.get_control("/v1/vms"),
            "images": client.get_control("/v1/images"),
            "base_image_recipes": client.get_control("/v1/base-image-recipes"),
            "layer2_image_recipes": client.get_control("/v1/layer2-image-recipes"),
            "testsuite_dependency_graph": client.get_control("/v1/testsuite-dependencies/graph"),
            "firewall_egress_rules": client.get_control("/v1/firewall/egress-rules"),
            "firewall_access_rules": client.get_control("/v1/firewall/access-rules"),
            "endpoint_workarounds": client.get_control("/v1/endpoint-workarounds"),
        }
        return {"contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps(data, indent=2, sort_keys=True)}]}
    raise ValueError(f"unknown resource URI {uri!r}")


def _call_tool(client: KvmControlHttpClient, name: str | None, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "list_templates":
        data = client.get_control("/v1/templates")
    elif name == "get_capacity":
        data = client.get_control("/v1/capacity")
    elif name == "list_vms":
        data = client.get_control("/v1/vms")
    elif name == "get_vm":
        data = client.get_control(f"/v1/vms/{arguments['vm_id']}")
    elif name == "order_vm":
        payload = dict(arguments)
        context = _mcp_context(client)
        allowed_zones = context.get("allowed_zones") or ["dev"]
        payload.setdefault("network_id", "dev" if "dev" in allowed_zones else allowed_zones[0])
        payload.setdefault("autostart", True)
        data = client.post_control("/v1/vms", payload)
        if isinstance(data, dict):
            data.setdefault("next_step", "call wait_for_vm_ready, then SSH to ssh_target when ready")
            data.setdefault("ssh_target", f"root@{data['reserved_ip']}" if data.get("reserved_ip") else None)
            if not payload.get("ssh_public_key"):
                data.setdefault("warning", "ssh_public_key was omitted; SSH may fail unless the image already has a matching key")
    elif name == "start_vm":
        data = client.post_control(f"/v1/vms/{arguments['vm_id']}/start")
    elif name == "wait_for_vm_ready":
        payload = {key: arguments[key] for key in ("timeout_s", "poll_interval_s", "check_ssh") if key in arguments}
        data = client.post_control(f"/v1/vms/{arguments['vm_id']}/wait-ready", payload)
    elif name == "stop_vm":
        data = client.post_control(f"/v1/vms/{arguments['vm_id']}/stop")
    elif name == "promote_vm_layer2":
        payload = {key: arguments[key] for key in ("image_id", "description", "visible_name", "keywords") if key in arguments}
        data = client.post_control(f"/v1/vms/{arguments['vm_id']}/promote-layer2", payload)
    elif name == "resize_vm_layer3":
        data = client.post_control(
            f"/v1/vms/{arguments['vm_id']}/resize-layer3",
            {"new_size_mb": arguments["new_size_mb"]},
        )
    elif name == "set_vm_retention":
        data = client.post_control(
            f"/v1/vms/{arguments['vm_id']}/retention",
            {"retention": arguments["retention"], "reason": arguments.get("reason")},
        )
    elif name == "delete_vm":
        data = client.delete_control(f"/v1/vms/{arguments['vm_id']}")
    elif name == "list_archived_vms":
        data = client.get_control("/v1/archived-vms", query={"namespace": arguments.get("namespace")})
    elif name == "list_images":
        data = client.get_control(
            "/v1/images",
            query={"namespace": arguments.get("namespace"), "q": arguments.get("q"), "keyword": arguments.get("keyword")},
        )
    elif name == "list_base_image_recipes":
        data = client.get_control(
            "/v1/base-image-recipes",
            query={
                "architecture": arguments.get("architecture"),
                "include_development": arguments.get("include_development"),
            },
        )
    elif name == "list_layer2_image_recipes":
        data = client.get_control(
            "/v1/layer2-image-recipes",
            query={
                "architecture": arguments.get("architecture"),
                "base_image_recipe_id": arguments.get("base_image_recipe_id"),
                "keyword": arguments.get("keyword"),
                "include_development": arguments.get("include_development"),
            },
        )
    elif name == "get_testsuite_dependency_graph":
        data = client.get_control(
            "/v1/testsuite-dependencies/graph",
            query={
                "testsuite_id": arguments.get("testsuite_id"),
                "image_id": arguments.get("image_id"),
                "artifact_id": arguments.get("artifact_id"),
            },
        )
    elif name == "list_firewall_egress_rules":
        data = client.get_control("/v1/firewall/egress-rules", query={"namespace": arguments.get("namespace")})
    elif name == "create_firewall_egress_rule":
        data = client.post_control("/v1/firewall/egress-rules", arguments)
    elif name == "delete_firewall_egress_rule":
        data = client.delete_control(f"/v1/firewall/egress-rules/{arguments['rule_id']}")
    elif name == "list_firewall_access_rules":
        data = client.get_control("/v1/firewall/access-rules", query={"namespace": arguments.get("namespace")})
    elif name == "create_firewall_access_rule":
        data = client.post_control("/v1/firewall/access-rules", arguments)
    elif name == "delete_firewall_access_rule":
        data = client.delete_control(f"/v1/firewall/access-rules/{arguments['rule_id']}")
    elif name == "list_endpoint_workarounds":
        data = client.get_control(
            "/v1/endpoint-workarounds",
            query={"namespace": arguments.get("namespace"), "lock_resource_id": arguments.get("lock_resource_id")},
        )
    elif name == "create_endpoint_workaround":
        data = client.post_control("/v1/endpoint-workarounds", arguments)
    elif name == "delete_endpoint_workaround":
        data = client.delete_control(f"/v1/endpoint-workarounds/{arguments['rule_id']}")
    elif name == "request_lock":
        data = client.post_lock("/v1/locks/requests", arguments)
    elif name == "release_lock":
        data = client.post_lock(
            f"/v1/locks/requests/{arguments['request_id']}/release",
            {"released_by": arguments.get("released_by")},
        )
    elif name == "refresh_lease":
        data = client.post_lock(f"/v1/locks/requests/{arguments['request_id']}/lease/refresh")
    else:
        raise ValueError(f"unknown tool {name!r}")
    return _tool_result(data)


def _tool_result(data: Any) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(data, indent=2, sort_keys=True)}],
        "structuredContent": data,
    }


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def env_app() -> FastAPI:
    return create_app(
        control_url=os.environ.get("KVM_CONTROL_MCP_CONTROL_URL", "http://127.0.0.1:8000"),
        lock_url=os.environ.get("KVM_CONTROL_MCP_LOCK_URL", "http://127.0.0.1:8001"),
        token=os.environ.get("KVM_CONTROL_MCP_TOKEN"),
        username=os.environ.get("KVM_CONTROL_MCP_USERNAME"),
        password=os.environ.get("KVM_CONTROL_MCP_PASSWORD"),
    )
