#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from kvm_control.contracts.reporting import (
    ContractReportInput,
    draft_contract_report,
    dumps_report,
    render_markdown_report,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Draft a bug or feature-request report from a kvm-control workflow contract.")
    parser.add_argument("--workflow", required=True, help="Workflow contract id, for example agent-vm-lifecycle.v1")
    parser.add_argument("--observed", required=True, help="Observed behavior or failure")
    parser.add_argument("--expected", default="", help="Expected behavior under the selected contract")
    parser.add_argument("--preconditions-not-met", action="store_true", help="Classify as policy_rejection because contract preconditions were not met")
    parser.add_argument("--policy-rejection", action="store_true", help="Classify as policy_rejection because the observed response was intentional policy enforcement")
    parser.add_argument("--docs-ambiguous", action="store_true", help="Classify as documentation_gap")
    parser.add_argument("--outside-contract", action="store_true", help="Classify as feature_request")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args()

    report_input = ContractReportInput(
        workflow_id=args.workflow,
        observed=args.observed,
        expected=args.expected,
        preconditions_met=not args.preconditions_not_met,
        policy_rejection=args.policy_rejection,
        docs_ambiguous=args.docs_ambiguous,
        outside_contract=args.outside_contract,
    )
    try:
        draft = draft_contract_report(report_input)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.format == "markdown":
        print(render_markdown_report(draft), end="")
    else:
        print(dumps_report(draft), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
