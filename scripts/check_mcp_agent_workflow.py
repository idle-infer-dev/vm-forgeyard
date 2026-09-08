#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any


REQUIRED_TOOLS = {
    "request_lock",
    "refresh_lease",
    "release_lock",
    "list_templates",
    "list_images",
    "order_vm",
    "wait_for_vm_ready",
    "get_vm",
    "get_operation",
    "wait_for_operation",
    "stop_vm",
    "start_vm",
    "resize_vm_layer3",
    "promote_vm_layer2",
    "set_vm_retention",
    "delete_vm",
    "list_endpoint_workarounds",
    "create_endpoint_workaround",
    "delete_endpoint_workaround",
    "draft_contract_report",
}


def read_token(path: Path) -> str | None:
    if not path.exists():
        return None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            return line
    return None


def rpc(url: str, method: str, params: dict[str, Any] | None, token: str | None, request_id: int) -> Any:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
    with urllib.request.urlopen(request, timeout=20) as response:
        data = json.loads(response.read().decode("utf-8"))
    if "error" in data:
        raise RuntimeError(f"{method} failed: {data['error']}")
    return data["result"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check that kvm-control MCP exposes the agent VM workflow.")
    parser.add_argument("--url", default="http://127.0.0.1:8002/mcp", help="MCP JSON-RPC endpoint")
    parser.add_argument("--token-file", help="Optional bearer token file")
    args = parser.parse_args()

    token = read_token(Path(args.token_file)) if args.token_file else None
    tools_result = rpc(args.url, "tools/list", {}, token, 1)
    tools = {tool["name"]: tool for tool in tools_result["tools"]}
    missing = sorted(REQUIRED_TOOLS - set(tools))
    if missing:
        raise RuntimeError(f"missing required tools: {', '.join(missing)}")
    rpc(args.url, "tools/call", {"name": "get_capacity", "arguments": {}}, token, 6)

    order_schema = tools["order_vm"]["inputSchema"]
    wait_schema = tools["wait_for_vm_ready"]["inputSchema"]
    order_required = set(order_schema.get("required") or [])
    for field in ("template_id", "vm_slot", "agent_session_id"):
        if field not in order_required:
            raise RuntimeError(f"order_vm does not require {field}")
    if "ssh_public_key" not in order_schema.get("properties", {}):
        raise RuntimeError("order_vm does not expose ssh_public_key")
    if "check_ssh" not in wait_schema.get("properties", {}):
        raise RuntimeError("wait_for_vm_ready does not expose check_ssh")

    resources = rpc(args.url, "resources/list", {}, token, 2)["resources"]
    resource_uris = {resource["uri"] for resource in resources}
    if "kvm-control://concepts/agent-workflow" not in resource_uris:
        raise RuntimeError("agent workflow resource is missing")
    if "kvm-control://auth/onboarding" not in resource_uris:
        raise RuntimeError("auth onboarding resource is missing")
    if "kvm-control://concepts/webroot-artifacts" not in resource_uris:
        raise RuntimeError("webroot artifacts resource is missing")
    if "kvm-control://concepts/endpoint-workarounds" not in resource_uris:
        raise RuntimeError("endpoint workarounds resource is missing")
    if "kvm-control://contracts/capabilities.v1" not in resource_uris:
        raise RuntimeError("capability contract resource is missing")
    if "kvm-control://contracts/workflows/agent-vm-lifecycle.v1" not in resource_uris:
        raise RuntimeError("agent VM lifecycle contract resource is missing")
    workflow = rpc(args.url, "resources/read", {"uri": "kvm-control://concepts/agent-workflow"}, token, 3)
    workflow_text = workflow["contents"][0]["text"]
    for phrase in (
        "request_lock",
        "order_vm",
        "agent_session_id",
        "ssh_public_key",
        "wait_for_vm_ready",
        "root@reserved_ip",
        "non-interactive root SSH command",
        "SCP",
        "PUT /v1/webroot-artifacts/{namespace}/{path}",
        "wait_for_completion=false",
        "wait_for_operation",
        "refresh_lease",
    ):
        if phrase not in workflow_text:
            raise RuntimeError(f"agent workflow resource does not mention {phrase}")
    onboarding = rpc(args.url, "resources/read", {"uri": "kvm-control://auth/onboarding"}, token, 7)
    onboarding_text = onboarding["contents"][0]["text"]
    for phrase in (
        "Authorization: Bearer",
        "./repo.auth.token",
        "~/.kvm-control-self-register.key",
        "/v1/auth/repository-self-registration",
    ):
        if phrase not in onboarding_text:
            raise RuntimeError(f"auth onboarding resource does not mention {phrase}")
    webroot = rpc(args.url, "resources/read", {"uri": "kvm-control://concepts/webroot-artifacts"}, token, 4)
    webroot_text = webroot["contents"][0]["text"]
    for phrase in ("raw file bytes", "GET /v1/webroot-artifacts/{namespace}", "DELETE /v1/webroot-artifacts/{namespace}/{path}", "/{namespace}/{path}"):
        if phrase not in webroot_text:
            raise RuntimeError(f"webroot artifacts resource does not mention {phrase}")
    endpoint_workarounds = rpc(args.url, "resources/read", {"uri": "kvm-control://concepts/endpoint-workarounds"}, token, 5)
    endpoint_text = endpoint_workarounds["contents"][0]["text"]
    for phrase in ("/etc/hosts", "dnat", "target_ip", "namespace lock"):
        if phrase not in endpoint_text:
            raise RuntimeError(f"endpoint workarounds resource does not mention {phrase}")
    capabilities = rpc(args.url, "resources/read", {"uri": "kvm-control://contracts/capabilities.v1"}, token, 8)
    capabilities_text = capabilities["contents"][0]["text"]
    for phrase in ("feature_request", "documentation_gap", "repository-onboarding.v1", "agent-vm-lifecycle.v1", "namespace-lock-leases.v1", "trash-cleanup.v1"):
        if phrase not in capabilities_text:
            raise RuntimeError(f"capability contract resource does not mention {phrase}")
    lifecycle_contract = rpc(args.url, "resources/read", {"uri": "kvm-control://contracts/workflows/agent-vm-lifecycle.v1"}, token, 9)
    lifecycle_text = lifecycle_contract["contents"][0]["text"]
    for phrase in ("bug_indicators", "feature_request_indicators", "wait_for_vm_ready", "root_ssh_command", "SCP transfer"):
        if phrase not in lifecycle_text:
            raise RuntimeError(f"agent VM lifecycle contract resource does not mention {phrase}")
    drafted = rpc(
        args.url,
        "tools/call",
        {
            "name": "draft_contract_report",
            "arguments": {
                "workflow_id": "agent-vm-lifecycle.v1",
                "observed": "get_capacity returns 403 through MCP but direct HTTP accepts the same token from the same source",
                "expected": "Operational MCP tools should authorize like direct HTTP for the same effective source.",
            },
        },
        token,
        10,
    )
    if drafted["structuredContent"]["classification"] != "bug":
        raise RuntimeError("draft_contract_report did not classify the operational MCP auth complaint as a bug")

    print(json.dumps({"ok": True, "tool_count": len(tools), "checked_url": args.url}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
