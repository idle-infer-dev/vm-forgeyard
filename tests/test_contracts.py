from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from kvm_control.contracts.reporting import ContractReportInput, draft_contract_report, render_markdown_report
from kvm_control.contracts.validation import validate_packaged_contracts
from kvm_control.mcp_api import CONTRACT_RESOURCES


EXPECTED_WORKFLOW_IDS = [
    "repository-onboarding.v1",
    "agent-vm-lifecycle.v1",
    "namespace-lock-leases.v1",
    "trash-cleanup.v1",
]


class ContractValidationTests(unittest.TestCase):
    def test_packaged_contracts_validate(self) -> None:
        result = validate_packaged_contracts()
        self.assertEqual(result.capabilities_id, "kvm-control.capabilities.v1")
        self.assertEqual(result.workflow_ids, EXPECTED_WORKFLOW_IDS)

    def test_mcp_contract_resource_paths_are_packaged(self) -> None:
        result = validate_packaged_contracts()
        workflow_uris = {
            f"kvm-control://contracts/workflows/{workflow_id}"
            for workflow_id in result.workflow_ids
        }
        self.assertTrue(workflow_uris.issubset(CONTRACT_RESOURCES))
        for resource_path, _name, _description in CONTRACT_RESOURCES.values():
            self.assertTrue((Path("src/kvm_control/contracts") / resource_path).exists())

    def test_check_contracts_script(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/check_contracts.py"],
            check=True,
            cwd=Path(__file__).resolve().parents[1],
            env={"PYTHONPATH": "src"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["workflow_count"], 4)
        self.assertEqual(payload["workflow_ids"], EXPECTED_WORKFLOW_IDS)

    def test_draft_report_classifies_matching_bug_indicator(self) -> None:
        draft = draft_contract_report(
            ContractReportInput(
                workflow_id="agent-vm-lifecycle.v1",
                observed="get_capacity returns 403 through MCP but direct HTTP accepts the same token from the same source",
                expected="Operational MCP calls should use the same effective source-scoped bearer auth as direct HTTP.",
            )
        )
        self.assertEqual(draft["classification"], "bug")
        self.assertTrue(draft["matched_indicators"]["bug"])
        self.assertIn("get_capacity", draft["matched_indicators"]["bug"][0])

    def test_draft_report_classifies_explicit_feature_request(self) -> None:
        draft = draft_contract_report(
            ContractReportInput(
                workflow_id="agent-vm-lifecycle.v1",
                observed="Agents need priority queues instead of FIFO lock ordering.",
                outside_contract=True,
            )
        )
        self.assertEqual(draft["classification"], "feature_request")

    def test_draft_report_classifies_policy_rejection(self) -> None:
        draft = draft_contract_report(
            ContractReportInput(
                workflow_id="repository-onboarding.v1",
                observed="Self-registration returned 409 because the repository already has an active token.",
                policy_rejection=True,
            )
        )
        self.assertEqual(draft["classification"], "policy_rejection")

    def test_draft_report_classifies_lock_lease_bug(self) -> None:
        draft = draft_contract_report(
            ContractReportInput(
                workflow_id="namespace-lock-leases.v1",
                observed="refresh_lease reports success but does not extend lease_expires_at on a granted lock",
                expected="refresh_lease should extend lease_expires_at for the granted namespace lock request.",
            )
        )
        self.assertEqual(draft["classification"], "bug")
        self.assertTrue(draft["matched_indicators"]["bug"])

    def test_draft_report_classifies_trash_cleanup_feature_request(self) -> None:
        draft = draft_contract_report(
            ContractReportInput(
                workflow_id="trash-cleanup.v1",
                observed="We need recursive deletion of directories under storage.trash_dir.",
            )
        )
        self.assertEqual(draft["classification"], "feature_request")
        self.assertTrue(draft["matched_indicators"]["feature_request"])

    def test_draft_report_classifies_application_readiness_as_feature_request(self) -> None:
        draft = draft_contract_report(
            ContractReportInput(
                workflow_id="agent-vm-lifecycle.v1",
                observed="wait_for_vm_ready should verify application-level readiness beyond root SSH command execution.",
            )
        )
        self.assertEqual(draft["classification"], "feature_request")
        self.assertTrue(draft["matched_indicators"]["feature_request"])

    def test_draft_report_classifies_persistent_scp_refusal_as_bug(self) -> None:
        draft = draft_contract_report(
            ContractReportInput(
                workflow_id="agent-vm-lifecycle.v1",
                observed="SCP to ssh_target is refused after wait_for_vm_ready returned ready=true and ssh_login_verified=true.",
                expected="A ready VM should be usable for staging files through the returned SSH target.",
            )
        )
        self.assertEqual(draft["classification"], "bug")
        self.assertTrue(draft["matched_indicators"]["bug"])

    def test_draft_report_classifies_reserved_ip_in_dhcp_pool_as_bug(self) -> None:
        draft = draft_contract_report(
            ContractReportInput(
                workflow_id="agent-vm-lifecycle.v1",
                observed="reserved_ip for an ordered VM is inside the configured dynamic DHCP pool for its network segment.",
            )
        )
        self.assertEqual(draft["classification"], "bug")
        self.assertTrue(draft["matched_indicators"]["bug"])

    def test_draft_contract_report_script_outputs_json(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "scripts/draft_contract_report.py",
                "--workflow",
                "agent-vm-lifecycle.v1",
                "--observed",
                "wait_for_vm_ready returned ready=true while a non-interactive root SSH command against reserved_ip failed",
                "--expected",
                "ready=true only after root SSH command execution succeeds",
            ],
            check=True,
            cwd=Path(__file__).resolve().parents[1],
            env={"PYTHONPATH": "src"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["classification"], "bug")
        self.assertEqual(payload["workflow_id"], "agent-vm-lifecycle.v1")

    def test_markdown_report_rendering(self) -> None:
        draft = draft_contract_report(
            ContractReportInput(
                workflow_id="agent-vm-lifecycle.v1",
                observed="Agent could not discover that agent_session_id is required before order_vm.",
                docs_ambiguous=True,
            )
        )
        markdown = render_markdown_report(draft)
        self.assertIn("Classification: `documentation_gap`", markdown)
        self.assertIn("Preconditions To Verify", markdown)

    def test_public_hygiene_script_accepts_clean_public_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            (root / "tests" / "test_auth.py").write_text('headers = {"Authorization": "Bearer admin-secret"}\n')
            completed = subprocess.run(
                [sys.executable, "scripts/check_public_hygiene.py", str(root)],
                check=True,
                cwd=Path(__file__).resolve().parents[1],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertIn("public hygiene check passed", completed.stdout)

    def test_public_hygiene_script_rejects_private_leaks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text(
                "\n".join(
                    [
                        "host " + "kvm" + "0",
                        "api " + "10." + "7.31.41:8000",
                        "path " + "/home/" + "sven/git/kvm-control",
                        "token " + "TR" + "m49",
                        "file " + "admin-" + "token",
                        "header Authorization: Bearer " + "A" * 24,
                    ]
                )
            )
            completed = subprocess.run(
                [sys.executable, "scripts/check_public_hygiene.py", str(root)],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("private KVM host name", completed.stderr)
        self.assertIn("private 10.7.x address", completed.stderr)
        self.assertIn("local developer path", completed.stderr)
        self.assertIn("literal bearer token", completed.stderr)
