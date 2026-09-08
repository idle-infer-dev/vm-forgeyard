from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import yaml
from fastapi.testclient import TestClient

from kvm_control.mcp_api import create_app


class FakeKvmClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, object]] = []

    def get_control(self, path: str, query: dict | None = None):
        self.calls.append(("get_control", path, query))
        if path == "/v1/templates":
            return [{"template_id": "devuan-daedalus"}]
        if path == "/v1/capacity":
            return {"max_vms": 4, "used_vms": 0}
        if path == "/v1/vms":
            return []
        if path == "/v1/archived-vms":
            return [{"vm_id": "vm-archived", "namespace": query.get("namespace") if query else None}]
        if path == "/v1/images":
            return [{"image_id": "image-a"}]
        if path == "/v1/base-image-recipes":
            return [{"id": "ubuntu-24.04-noble-amd64", "architecture": query.get("architecture") if query else "amd64"}]
        if path == "/v1/layer2-image-recipes":
            return [{"id": "agent-sandbox-tools-devuan-6-excalibur-amd64", "keyword": query.get("keyword") if query else None}]
        if path == "/v1/testsuite-dependencies/graph":
            return {"documents": [], "images": []}
        if path == "/v1/firewall/egress-rules":
            return [
                {
                    "id": 10,
                    "namespace": query.get("namespace") if query else None,
                    "mode": "cidr",
                    "target_cidr": "192.0.2.42",
                }
            ]
        if path == "/v1/firewall/access-rules":
            return [
                {
                    "id": 11,
                    "namespace": query.get("namespace") if query else None,
                    "target_zone": "dev",
                    "source_cidr": "192.0.2.42",
                }
            ]
        if path == "/v1/endpoint-workarounds":
            return [
                {
                    "id": 12,
                    "namespace": query.get("namespace") if query else None,
                    "lock_resource_id": query.get("lock_resource_id") if query else None,
                    "kind": "fqdn",
                    "value": "updates.example.test",
                    "workaround_type": "hosts_entry",
                    "target_ip": "192.0.2.42",
                    "apply_on": ["appliance"],
                }
            ]
        if path == "/v1/vms/vm-a":
            return {"vm_id": "vm-a", "power_state": "running"}
        raise AssertionError(path)

    def post_control(self, path: str, payload: dict | None = None):
        self.calls.append(("post_control", path, payload))
        if path == "/v1/vms":
            return {"vm_id": "repo-a-node1", "status": "completed", "reserved_ip": "10.80.1.23", "payload": payload}
        if path == "/v1/vms/vm-a/start":
            return {"vm_id": "vm-a", "action": "start"}
        if path == "/v1/vms/vm-a/wait-ready":
            return {
                "vm_id": "vm-a",
                "ready": True,
                "reserved_ip": "10.80.1.23",
                "ssh_target": "root@10.80.1.23",
                "payload": payload,
            }
        if path == "/v1/vms/vm-a/promote-layer2":
            return {"vm_id": "vm-a", "action": "promote-layer2"}
        if path == "/v1/vms/vm-a/resize-layer3":
            return {"vm_id": "vm-a", "action": "resize-layer3", "payload": payload}
        if path == "/v1/vms/vm-a/retention":
            return {"vm_id": "vm-a", "retention": payload["retention"], "retention_reason": payload.get("reason")}
        if path == "/v1/firewall/egress-rules":
            return {"id": 10, "payload": payload}
        if path == "/v1/firewall/access-rules":
            return {"id": 11, "payload": payload}
        if path == "/v1/endpoint-workarounds":
            return {"id": 12, "payload": payload}
        raise AssertionError(path)

    def delete_control(self, path: str):
        self.calls.append(("delete_control", path, None))
        if path == "/v1/firewall/egress-rules/10":
            return {"deleted": {"id": 10}}
        if path == "/v1/firewall/access-rules/11":
            return {"deleted": {"id": 11}}
        if path == "/v1/endpoint-workarounds/12":
            return {"deleted": {"id": 12}}
        return {"vm_id": path.rsplit("/", 1)[-1], "action": "delete"}

    def get_lock(self, path: str, query: dict | None = None):
        self.calls.append(("get_lock", path, query))
        return []

    def post_lock(self, path: str, payload: dict | None = None):
        self.calls.append(("post_lock", path, payload))
        if path == "/v1/locks/requests":
            return {"id": 1, "status": "granted"}
        if path == "/v1/locks/requests/1/release":
            return {"id": 1, "status": "released"}
        if path == "/v1/locks/requests/1/lease/refresh":
            return {"id": 1, "status": "granted", "lease_expires_at": "2030-01-01 00:00:00"}
        raise AssertionError(path)


class McpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeKvmClient()
        self.client = TestClient(create_app(client=self.fake))

    def rpc(self, method: str, params: dict | None = None, request_id: int = 1) -> dict:
        response = self.client.post("/mcp", json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_initialize_and_list_tools(self) -> None:
        initialized = self.rpc("initialize")
        self.assertEqual(initialized["result"]["serverInfo"]["name"], "kvm-control")

        tools = self.rpc("tools/list")
        listed_tools = tools["result"]["tools"]
        names = {tool["name"] for tool in listed_tools}
        self.assertIn("order_vm", names)
        self.assertIn("get_testsuite_dependency_graph", names)
        self.assertIn("promote_vm_layer2", names)
        self.assertIn("wait_for_vm_ready", names)
        self.assertIn("set_vm_retention", names)
        self.assertIn("list_archived_vms", names)
        self.assertIn("list_base_image_recipes", names)
        self.assertIn("list_layer2_image_recipes", names)
        self.assertNotIn("mark_vm_ready", names)
        self.assertIn("create_firewall_egress_rule", names)
        self.assertIn("create_firewall_access_rule", names)
        self.assertIn("create_endpoint_workaround", names)
        self.assertIn("refresh_lease", names)
        self.assertIn("draft_contract_report", names)
        request_lock = next(tool for tool in listed_tools if tool["name"] == "request_lock")
        self.assertIn("lease_ttl_seconds", request_lock["inputSchema"]["properties"])
        refresh_lease = next(tool for tool in listed_tools if tool["name"] == "refresh_lease")
        self.assertIn("lease_ttl_seconds", refresh_lease["inputSchema"]["properties"])
        list_vms = next(tool for tool in listed_tools if tool["name"] == "list_vms")
        self.assertIn("reserved_ip", list_vms["description"])
        self.assertIn("root@reserved_ip", list_vms["description"])
        self.assertIn("normal SSH login", list_vms["description"])
        self.assertIn("diagnostic", list_vms["description"])
        get_vm = next(tool for tool in listed_tools if tool["name"] == "get_vm")
        self.assertIn("reserved_ip", get_vm["description"])
        self.assertIn("root@reserved_ip", get_vm["description"])
        self.assertIn("normal SSH login", get_vm["description"])
        self.assertIn("current_ip", get_vm["description"])
        order_vm = next(tool for tool in listed_tools if tool["name"] == "order_vm")
        self.assertEqual(order_vm["inputSchema"]["properties"]["network_id"]["enum"], ["dev", "stage", "misc", "live"])
        self.assertIn("layer3_size_mb", order_vm["inputSchema"]["properties"])
        self.assertIn("purpose", order_vm["inputSchema"]["properties"])
        self.assertIn("agent_session_id", order_vm["inputSchema"]["properties"])
        self.assertIn("ssh_public_key", order_vm["inputSchema"]["properties"])
        self.assertIn("requested_capabilities", order_vm["inputSchema"]["properties"])
        self.assertEqual(order_vm["inputSchema"]["properties"]["requested_capabilities"]["items"]["enum"], ["nested_kvm"])
        self.assertIn("nested_virtualization", order_vm["inputSchema"]["properties"])
        self.assertIn("agent_session_id", order_vm["inputSchema"]["required"])
        self.assertIn("agent_session_id is required", order_vm["description"])
        self.assertIn("ssh_public_key", order_vm["description"])
        self.assertIn("requested_capabilities", order_vm["description"])
        self.assertIn("nested_virtualization", order_vm["description"])
        self.assertIn("reserved_ip", order_vm["description"])
        self.assertIn("root@reserved_ip", order_vm["description"])
        self.assertIn("normal SSH login", order_vm["description"])
        self.assertIn("normal API access", order_vm["description"])
        self.assertIn("current_ip", order_vm["description"])
        self.assertIn("wait_for_vm_ready", order_vm["description"])
        wait_ready = next(tool for tool in listed_tools if tool["name"] == "wait_for_vm_ready")
        self.assertIn("root SSH", wait_ready["description"])
        self.assertIn("ssh_target", wait_ready["description"])
        self.assertIn("SFTP", wait_ready["description"])
        self.assertIn("SCP", wait_ready["description"])
        self.assertIn("check_ssh", wait_ready["inputSchema"]["properties"])
        promote = next(tool for tool in listed_tools if tool["name"] == "promote_vm_layer2")
        self.assertIn("setup VM", promote["description"])
        self.assertIn("keywords", promote["description"])
        self.assertIn("description", promote["inputSchema"]["properties"])
        self.assertIn("per-run output", promote["description"])
        list_images = next(tool for tool in listed_tools if tool["name"] == "list_images")
        self.assertIn("q", list_images["inputSchema"]["properties"])
        self.assertIn("keyword", list_images["inputSchema"]["properties"])
        resize = next(tool for tool in listed_tools if tool["name"] == "resize_vm_layer3")
        self.assertIn("stopped", resize["description"])
        self.assertIn("filesystem", resize["description"])
        release_lock = next(tool for tool in listed_tools if tool["name"] == "release_lock")
        self.assertIn("same namespace", release_lock["description"])
        self.assertIn("not the resource_id", release_lock["description"])
        draft_report = next(tool for tool in listed_tools if tool["name"] == "draft_contract_report")
        self.assertIn("workflow_id", draft_report["inputSchema"]["required"])
        self.assertIn("observed", draft_report["inputSchema"]["required"])
        self.assertIn("feature-request", draft_report["description"])

    def test_list_resources_includes_machine_readable_contracts(self) -> None:
        result = self.rpc("resources/list")
        resources = result["result"]["resources"]
        by_uri = {resource["uri"]: resource for resource in resources}
        self.assertEqual(by_uri["kvm-control://contracts/capabilities.v1"]["mimeType"], "application/yaml")
        self.assertEqual(by_uri["kvm-control://contracts/workflow-contract.schema.v1"]["mimeType"], "application/yaml")
        self.assertEqual(by_uri["kvm-control://contracts/workflows/repository-onboarding.v1"]["mimeType"], "application/yaml")
        self.assertEqual(by_uri["kvm-control://contracts/workflows/agent-vm-lifecycle.v1"]["mimeType"], "application/yaml")
        self.assertEqual(by_uri["kvm-control://contracts/workflows/namespace-lock-leases.v1"]["mimeType"], "application/yaml")
        self.assertEqual(by_uri["kvm-control://contracts/workflows/trash-cleanup.v1"]["mimeType"], "application/yaml")
        self.assertIn("feature requests", by_uri["kvm-control://contracts/capabilities.v1"]["description"])

    def test_order_vm_forwards_to_control_api(self) -> None:
        result = self.rpc(
            "tools/call",
            {
                "name": "order_vm",
                "arguments": {
                    "namespace": "repo-a",
                    "template_id": "devuan-daedalus",
                    "vm_slot": "node1",
                    "layer3_size_mb": 4096,
                    "agent_session_id": "pytest-mcp-session",
                    "ssh_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey pytest-agent",
                    "requested_capabilities": ["nested_kvm"],
                },
            },
        )
        payload = result["result"]["structuredContent"]["payload"]
        self.assertEqual(payload["network_id"], "dev")
        self.assertTrue(payload["autostart"])
        self.assertEqual(payload["layer3_size_mb"], 4096)
        self.assertEqual(payload["agent_session_id"], "pytest-mcp-session")
        self.assertEqual(payload["ssh_public_key"], "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey pytest-agent")
        self.assertEqual(payload["requested_capabilities"], ["nested_kvm"])
        self.assertEqual(result["result"]["structuredContent"]["ssh_target"], "root@10.80.1.23")
        self.assertIn("wait_for_vm_ready", result["result"]["structuredContent"]["next_step"])
        self.assertIn(("post_control", "/v1/vms", payload), self.fake.calls)

    def test_order_vm_without_ssh_key_returns_agent_warning(self) -> None:
        result = self.rpc(
            "tools/call",
            {
                "name": "order_vm",
                "arguments": {
                    "namespace": "repo-a",
                    "template_id": "devuan-daedalus",
                    "vm_slot": "node1",
                    "agent_session_id": "pytest-mcp-session",
                },
            },
        )
        self.assertIn("ssh_public_key was omitted", result["result"]["structuredContent"]["warning"])

    def test_wait_for_vm_ready_forwards_to_control_api(self) -> None:
        result = self.rpc(
            "tools/call",
            {
                "name": "wait_for_vm_ready",
                "arguments": {
                    "vm_id": "vm-a",
                    "timeout_s": 30,
                    "poll_interval_s": 2,
                    "check_ssh": True,
                },
            },
        )
        payload = result["result"]["structuredContent"]["payload"]
        self.assertEqual(result["result"]["structuredContent"]["ssh_target"], "root@10.80.1.23")
        self.assertEqual(payload, {"timeout_s": 30, "poll_interval_s": 2, "check_ssh": True})
        self.assertIn(("post_control", "/v1/vms/vm-a/wait-ready", payload), self.fake.calls)

    def test_draft_contract_report_tool_uses_packaged_contracts(self) -> None:
        result = self.rpc(
            "tools/call",
            {
                "name": "draft_contract_report",
                "arguments": {
                    "workflow_id": "agent-vm-lifecycle.v1",
                    "observed": "get_capacity returns 403 through MCP but direct HTTP accepts the same token from the same source",
                    "expected": "Operational MCP calls should authorize like direct HTTP for the same effective source.",
                    "include_markdown": True,
                },
            },
        )
        payload = result["result"]["structuredContent"]
        self.assertEqual(payload["classification"], "bug")
        self.assertEqual(payload["workflow_id"], "agent-vm-lifecycle.v1")
        self.assertIn("get_capacity", payload["matched_indicators"]["bug"][0])
        self.assertIn("Classification: `bug`", payload["markdown"])
        self.assertNotIn("get_control", [call[0] for call in self.fake.calls])

    def test_promote_vm_layer2_forwards_to_control_api(self) -> None:
        result = self.rpc(
            "tools/call",
            {
                "name": "promote_vm_layer2",
                "arguments": {
                    "vm_id": "vm-a",
                    "description": "Tenstorrent toolchain setup",
                    "keywords": ["tenstorrent", "toolchain"],
                },
            },
        )
        self.assertEqual(result["result"]["structuredContent"]["action"], "promote-layer2")
        self.assertIn(
            (
                "post_control",
                "/v1/vms/vm-a/promote-layer2",
                {"description": "Tenstorrent toolchain setup", "keywords": ["tenstorrent", "toolchain"]},
            ),
            self.fake.calls,
        )

    def test_resize_vm_layer3_forwards_to_control_api(self) -> None:
        result = self.rpc(
            "tools/call",
            {
                "name": "resize_vm_layer3",
                "arguments": {
                    "vm_id": "vm-a",
                    "new_size_mb": 4096,
                },
            },
        )
        self.assertEqual(result["result"]["structuredContent"]["action"], "resize-layer3")
        self.assertIn(("post_control", "/v1/vms/vm-a/resize-layer3", {"new_size_mb": 4096}), self.fake.calls)

    def test_retention_and_archive_tools_forward_to_control_api(self) -> None:
        retained = self.rpc(
            "tools/call",
            {
                "name": "set_vm_retention",
                "arguments": {
                    "vm_id": "vm-a",
                    "retention": "keep_stopped",
                    "reason": "debug failed migration",
                },
            },
        )
        self.assertEqual(retained["result"]["structuredContent"]["retention"], "keep_stopped")
        self.assertIn(
            ("post_control", "/v1/vms/vm-a/retention", {"retention": "keep_stopped", "reason": "debug failed migration"}),
            self.fake.calls,
        )

        archived = self.rpc("tools/call", {"name": "list_archived_vms", "arguments": {"namespace": "repo-a"}})
        self.assertEqual(archived["result"]["structuredContent"][0]["vm_id"], "vm-archived")
        self.assertIn(("get_control", "/v1/archived-vms", {"namespace": "repo-a"}), self.fake.calls)

    def test_base_image_recipe_tool_forwards_to_control_api(self) -> None:
        result = self.rpc("tools/call", {"name": "list_base_image_recipes", "arguments": {"architecture": "amd64"}})
        self.assertEqual(result["result"]["structuredContent"][0]["id"], "ubuntu-24.04-noble-amd64")
        self.assertIn(
            ("get_control", "/v1/base-image-recipes", {"architecture": "amd64", "include_development": None}),
            self.fake.calls,
        )

    def test_layer2_image_recipe_tool_forwards_to_control_api(self) -> None:
        result = self.rpc("tools/call", {"name": "list_layer2_image_recipes", "arguments": {"keyword": "ripgrep"}})
        self.assertEqual(result["result"]["structuredContent"][0]["id"], "agent-sandbox-tools-devuan-6-excalibur-amd64")
        self.assertIn(
            (
                "get_control",
                "/v1/layer2-image-recipes",
                {"architecture": None, "base_image_recipe_id": None, "keyword": "ripgrep", "include_development": None},
            ),
            self.fake.calls,
        )

    def test_firewall_egress_tools_forward_to_control_api(self) -> None:
        listed = self.rpc(
            "tools/call",
            {"name": "list_firewall_egress_rules", "arguments": {"namespace": "repo-a"}},
        )
        self.assertEqual(listed["result"]["structuredContent"][0]["target_cidr"], "192.0.2.42")
        self.assertIn(("get_control", "/v1/firewall/egress-rules", {"namespace": "repo-a"}), self.fake.calls)

        created = self.rpc(
            "tools/call",
            {
                "name": "create_firewall_egress_rule",
                "arguments": {
                    "namespace": "repo-a",
                    "lock_resource_id": "namespace:repo-a",
                    "mode": "cidr",
                    "target_cidr": "192.0.2.42",
                },
            },
        )
        payload = created["result"]["structuredContent"]["payload"]
        self.assertEqual(payload["mode"], "cidr")
        self.assertIn(("post_control", "/v1/firewall/egress-rules", payload), self.fake.calls)

        deleted = self.rpc("tools/call", {"name": "delete_firewall_egress_rule", "arguments": {"rule_id": 10}})
        self.assertEqual(deleted["result"]["structuredContent"]["deleted"]["id"], 10)
        self.assertIn(("delete_control", "/v1/firewall/egress-rules/10", None), self.fake.calls)

    def test_firewall_access_tools_forward_to_control_api(self) -> None:
        listed = self.rpc(
            "tools/call",
            {"name": "list_firewall_access_rules", "arguments": {"namespace": "repo-a"}},
        )
        self.assertEqual(listed["result"]["structuredContent"][0]["target_zone"], "dev")
        self.assertIn(("get_control", "/v1/firewall/access-rules", {"namespace": "repo-a"}), self.fake.calls)

        created = self.rpc(
            "tools/call",
            {
                "name": "create_firewall_access_rule",
                "arguments": {
                    "namespace": "repo-a",
                    "lock_resource_id": "namespace:repo-a",
                    "target_zone": "dev",
                    "source_cidr": "192.0.2.42",
                },
            },
        )
        payload = created["result"]["structuredContent"]["payload"]
        self.assertEqual(payload["target_zone"], "dev")
        self.assertIn(("post_control", "/v1/firewall/access-rules", payload), self.fake.calls)

        deleted = self.rpc("tools/call", {"name": "delete_firewall_access_rule", "arguments": {"rule_id": 11}})
        self.assertEqual(deleted["result"]["structuredContent"]["deleted"]["id"], 11)
        self.assertIn(("delete_control", "/v1/firewall/access-rules/11", None), self.fake.calls)

    def test_endpoint_workaround_tools_forward_to_control_api(self) -> None:
        listed = self.rpc(
            "tools/call",
            {"name": "list_endpoint_workarounds", "arguments": {"namespace": "repo-a", "lock_resource_id": "namespace:repo-a"}},
        )
        self.assertEqual(listed["result"]["structuredContent"][0]["workaround_type"], "hosts_entry")
        self.assertIn(("get_control", "/v1/endpoint-workarounds", {"namespace": "repo-a", "lock_resource_id": "namespace:repo-a"}), self.fake.calls)

        created = self.rpc(
            "tools/call",
            {
                "name": "create_endpoint_workaround",
                "arguments": {
                    "namespace": "repo-a",
                    "lock_resource_id": "namespace:repo-a",
                    "kind": "ip",
                    "value": "203.0.113.10",
                    "workaround_type": "dnat",
                    "target_ip": "192.0.2.42",
                    "apply_on": ["appliance"],
                    "maps_to_service": "payment_simulator",
                },
            },
        )
        payload = created["result"]["structuredContent"]["payload"]
        self.assertEqual(payload["workaround_type"], "dnat")
        self.assertIn(("post_control", "/v1/endpoint-workarounds", payload), self.fake.calls)

        deleted = self.rpc("tools/call", {"name": "delete_endpoint_workaround", "arguments": {"rule_id": 12}})
        self.assertEqual(deleted["result"]["structuredContent"]["deleted"]["id"], 12)
        self.assertIn(("delete_control", "/v1/endpoint-workarounds/12", None), self.fake.calls)

    def test_read_layer_concept_resource(self) -> None:
        result = self.rpc("resources/read", {"uri": "kvm-control://concepts/layers"})
        text = result["result"]["contents"][0]["text"]
        self.assertIn("layer1", text)
        self.assertIn("Testsuite dependency documents", text)

    def test_read_networking_concept_resource(self) -> None:
        result = self.rpc("resources/read", {"uri": "kvm-control://concepts/networking"})
        text = result["result"]["contents"][0]["text"]
        self.assertIn("dev", text)
        self.assertIn("stage", text)
        self.assertIn("misc", text)
        self.assertIn("reserved_ip", text)
        self.assertIn("connect to the VM through `reserved_ip`", text)
        self.assertIn("normal SSH", text)
        self.assertIn("`root@reserved_ip`", text)
        self.assertIn("non-interactive root SSH command", text)
        self.assertIn("does not separately prove SCP", text)
        self.assertIn("SCP", text)
        self.assertIn("`ssh_public_key`", text)
        self.assertIn("`current_ip`", text)
        self.assertIn("debugging", text)
        self.assertIn("DHCP", text)

    def test_read_test_setup_layer_concept_resource(self) -> None:
        result = self.rpc("resources/read", {"uri": "kvm-control://concepts/test-setup-layers"})
        text = result["result"]["contents"][0]["text"]
        self.assertIn("promote_vm_layer2", text)
        self.assertIn("reusable setup", text)
        self.assertIn("Per-run logs", text)
        self.assertIn("layer3 overlays", text)

    def test_read_agent_workflow_resource(self) -> None:
        result = self.rpc("resources/read", {"uri": "kvm-control://concepts/agent-workflow"})
        text = result["result"]["contents"][0]["text"]
        self.assertIn("request_lock", text)
        self.assertIn("order_vm", text)
        self.assertIn("agent_session_id", text)
        self.assertIn("ssh_public_key", text)
        self.assertIn("whoami.capabilities", text)
        self.assertIn("requested_capabilities", text)
        self.assertIn("nested_kvm", text)
        self.assertIn("wait_for_vm_ready", text)
        self.assertIn("root@reserved_ip", text)
        self.assertIn("refresh_lease", text)

    def test_read_auth_onboarding_resource(self) -> None:
        result = self.rpc("resources/read", {"uri": "kvm-control://auth/onboarding"})
        text = result["result"]["contents"][0]["text"]
        self.assertIn("Authorization: Bearer", text)
        self.assertIn("./repo.auth.token", text)
        self.assertIn("~/.kvm-control-self-register.key", text)
        self.assertIn("/v1/auth/repository-self-registration", text)
        self.assertIn("whoami", text)
        self.assertIn("requested_capabilities", text)
        self.assertIn("nested_kvm", text)

    def test_read_capability_contract_resource(self) -> None:
        result = self.rpc("resources/read", {"uri": "kvm-control://contracts/capabilities.v1"})
        content = result["result"]["contents"][0]
        payload = yaml.safe_load(content["text"])
        self.assertEqual(content["mimeType"], "application/yaml")
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["id"], "kvm-control.capabilities.v1")
        self.assertIn("feature_request", [category["name"] for category in payload["classification"]["categories"]])
        self.assertIn("repository-onboarding.v1", [workflow["id"] for workflow in payload["workflows"]])
        self.assertIn("agent-vm-lifecycle.v1", [workflow["id"] for workflow in payload["workflows"]])

    def test_read_workflow_contract_resources(self) -> None:
        for uri, expected_id in [
            ("kvm-control://contracts/workflows/repository-onboarding.v1", "repository-onboarding.v1"),
            ("kvm-control://contracts/workflows/agent-vm-lifecycle.v1", "agent-vm-lifecycle.v1"),
            ("kvm-control://contracts/workflows/namespace-lock-leases.v1", "namespace-lock-leases.v1"),
            ("kvm-control://contracts/workflows/trash-cleanup.v1", "trash-cleanup.v1"),
        ]:
            with self.subTest(uri=uri):
                result = self.rpc("resources/read", {"uri": uri})
                content = result["result"]["contents"][0]
                payload = yaml.safe_load(content["text"])
                self.assertEqual(content["mimeType"], "application/yaml")
                self.assertEqual(payload["schema_version"], 1)
                self.assertEqual(payload["id"], expected_id)
                self.assertIn("bug_indicators", payload)
                self.assertIn("feature_request_indicators", payload)
                self.assertIn("documentation_gap_indicators", payload)

    def test_read_workflow_contract_schema_resource(self) -> None:
        result = self.rpc("resources/read", {"uri": "kvm-control://contracts/workflow-contract.schema.v1"})
        content = result["result"]["contents"][0]
        payload = yaml.safe_load(content["text"])
        self.assertEqual(content["mimeType"], "application/yaml")
        self.assertEqual(payload["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertIn("bug_indicators", payload["required"])
        self.assertIn("feature_request_indicators", payload["required"])

    def test_read_webroot_artifacts_resource(self) -> None:
        result = self.rpc("resources/read", {"uri": "kvm-control://concepts/webroot-artifacts"})
        text = result["result"]["contents"][0]["text"]
        self.assertIn("PUT /v1/webroot-artifacts/{namespace}/{path}", text)
        self.assertIn("GET /v1/webroot-artifacts/{namespace}", text)
        self.assertIn("DELETE /v1/webroot-artifacts/{namespace}/{path}", text)
        self.assertIn("/{namespace}/{path}", text)
        self.assertIn("raw file bytes", text)

    def test_read_endpoint_workarounds_resource(self) -> None:
        result = self.rpc("resources/read", {"uri": "kvm-control://concepts/endpoint-workarounds"})
        text = result["result"]["contents"][0]["text"]
        self.assertIn("/etc/hosts", text)
        self.assertIn("dnat", text)
        self.assertIn("target_ip", text)

    def test_read_overview_resource_fetches_live_data(self) -> None:
        result = self.rpc("resources/read", {"uri": "kvm-control://status/overview"})
        payload = json.loads(result["result"]["contents"][0]["text"])
        self.assertEqual(payload["capacity"]["max_vms"], 4)
        self.assertEqual(payload["templates"][0]["template_id"], "devuan-daedalus")
        self.assertEqual(payload["firewall_egress_rules"][0]["target_cidr"], "192.0.2.42")
        self.assertEqual(payload["firewall_access_rules"][0]["target_zone"], "dev")
        self.assertEqual(payload["endpoint_workarounds"][0]["workaround_type"], "hosts_entry")

    def test_lock_tools_forward_to_lock_api(self) -> None:
        created = self.rpc("tools/call", {"name": "request_lock", "arguments": {"namespace": "repo-a", "resource_id": "lab-a", "lease_ttl_seconds": 86400}})
        self.assertEqual(created["result"]["structuredContent"]["status"], "granted")
        released = self.rpc("tools/call", {"name": "release_lock", "arguments": {"request_id": 1, "released_by": "repo-a"}})
        self.assertEqual(released["result"]["structuredContent"]["status"], "released")
        refreshed = self.rpc("tools/call", {"name": "refresh_lease", "arguments": {"request_id": 1, "lease_ttl_seconds": 172800}})
        self.assertEqual(refreshed["result"]["structuredContent"]["lease_expires_at"], "2030-01-01 00:00:00")
        self.assertIn(("post_lock", "/v1/locks/requests", {"namespace": "repo-a", "resource_id": "lab-a", "lease_ttl_seconds": 86400}), self.fake.calls)
        self.assertIn(("post_lock", "/v1/locks/requests/1/lease/refresh", {"lease_ttl_seconds": 172800}), self.fake.calls)

    def test_inbound_authorization_header_is_forwarded_to_upstream_apis(self) -> None:
        class Response:
            def __init__(self, payload: dict) -> None:
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *args) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(self.payload).encode("utf-8")

        captured: list[tuple[str, dict[str, str]]] = []

        def fake_urlopen(request, timeout: int = 30):
            captured.append((request.full_url, dict(request.header_items())))
            if request.full_url == "http://control/v1/auth/whoami":
                return Response(
                    {
                        "username": "git.repo-a",
                        "role": "repository",
                        "namespace": "git.repo-a",
                        "allowed_zones": ["dev"],
                        "capabilities": [],
                        "source_ip": "192.0.2.14",
                        "authenticated": True,
                    }
                )
            if request.full_url == "http://control/v1/environments":
                return Response({"environments": [{"name": "dev"}]})
            raise AssertionError(request.full_url)

        client = TestClient(create_app(control_url="http://control", lock_url="http://lock"))
        with patch("kvm_control.mcp_api.urlopen", fake_urlopen):
            response = client.post(
                "/mcp",
                headers={"Authorization": "Bearer inbound-token"},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            {headers.get("Authorization") for _, headers in captured},
            {"Bearer inbound-token"},
        )
        self.assertEqual(
            {headers.get("X-forwarded-for") for _, headers in captured},
            {"testclient"},
        )
        order_vm = next(tool for tool in response.json()["result"]["tools"] if tool["name"] == "order_vm")
        self.assertEqual(order_vm["inputSchema"]["properties"]["network_id"]["enum"], ["dev"])


if __name__ == "__main__":
    unittest.main()
