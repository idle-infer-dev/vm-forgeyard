from __future__ import annotations

import importlib.resources
import json
from dataclasses import dataclass
from typing import Any, Literal

import yaml


Classification = Literal["bug", "feature_request", "documentation_gap", "policy_rejection"]


@dataclass(frozen=True)
class ContractReportInput:
    workflow_id: str
    observed: str
    expected: str = ""
    preconditions_met: bool = True
    policy_rejection: bool = False
    docs_ambiguous: bool = False
    outside_contract: bool = False


def draft_contract_report(report_input: ContractReportInput) -> dict[str, Any]:
    workflow = load_workflow_contract(report_input.workflow_id)
    haystack = f"{report_input.observed}\n{report_input.expected}".lower()
    matched_indicators = {
        "bug": _matching_indicators(haystack, workflow["bug_indicators"]),
        "feature_request": _matching_indicators(haystack, workflow["feature_request_indicators"]),
        "documentation_gap": _matching_indicators(haystack, workflow["documentation_gap_indicators"]),
    }
    classification = _classify(report_input, workflow, matched_indicators)
    return {
        "classification": classification,
        "workflow_id": workflow["id"],
        "workflow_status": workflow["status"],
        "workflow_summary": workflow["summary"],
        "observed": report_input.observed,
        "expected": report_input.expected,
        "preconditions_met": report_input.preconditions_met,
        "matched_indicators": matched_indicators,
        "classification_rule": workflow["classification"]["default_rule"],
        "report": {
            "title": _draft_title(classification, workflow["id"], report_input.observed),
            "summary": _draft_summary(classification),
            "contract_reference": workflow["id"],
            "preconditions_to_verify": [item["text"] for item in workflow["preconditions"] if item["level"] == "MUST"],
            "success_criteria": workflow["success_criteria"],
            "related": workflow["related"],
        },
    }


def render_markdown_report(draft: dict[str, Any]) -> str:
    report = draft["report"]
    lines = [
        f"# {report['title']}",
        "",
        f"Classification: `{draft['classification']}`",
        f"Contract: `{draft['workflow_id']}` (`{draft['workflow_status']}`)",
        "",
        "## Summary",
        "",
        report["summary"],
        "",
        "## Observed",
        "",
        draft["observed"],
    ]
    if draft["expected"]:
        lines.extend(["", "## Expected", "", draft["expected"]])
    lines.extend(["", "## Preconditions To Verify", ""])
    lines.extend(f"- {item}" for item in report["preconditions_to_verify"])
    matched = [
        (category, indicators)
        for category, indicators in draft["matched_indicators"].items()
        if indicators
    ]
    if matched:
        lines.extend(["", "## Matched Contract Indicators", ""])
        for category, indicators in matched:
            lines.append(f"{category}:")
            lines.extend(f"- {indicator}" for indicator in indicators)
    lines.extend(["", "## Related", ""])
    for field, values in report["related"].items():
        if values:
            lines.append(f"{field}: {', '.join(values)}")
    return "\n".join(lines) + "\n"


def load_capabilities_contract() -> dict[str, Any]:
    return _load_contract_yaml("capabilities.v1.yaml")


def load_workflow_contract(workflow_id: str) -> dict[str, Any]:
    capabilities = load_capabilities_contract()
    for workflow in capabilities["workflows"]:
        if workflow["id"] == workflow_id:
            return _load_contract_yaml(workflow["file"])
    known = ", ".join(workflow["id"] for workflow in capabilities["workflows"])
    raise ValueError(f"unknown workflow contract {workflow_id!r}; known workflows: {known}")


def _classify(
    report_input: ContractReportInput,
    workflow: dict[str, Any],
    matched_indicators: dict[str, list[str]],
) -> Classification:
    if report_input.policy_rejection or not report_input.preconditions_met:
        return "policy_rejection"
    if report_input.docs_ambiguous:
        return "documentation_gap"
    if report_input.outside_contract:
        return "feature_request"
    scores = {category: len(indicators) for category, indicators in matched_indicators.items()}
    if scores["documentation_gap"] > max(scores["bug"], scores["feature_request"]):
        return "documentation_gap"
    if scores["feature_request"] > scores["bug"]:
        return "feature_request"
    if scores["bug"] > 0:
        return "bug"
    if workflow["status"] == "implemented" and report_input.expected:
        return "bug"
    return "feature_request"


def _matching_indicators(haystack: str, indicators: list[str]) -> list[str]:
    matches: list[str] = []
    haystack_tokens = set(_tokens(haystack))
    for indicator in indicators:
        normalized = indicator.lower()
        if normalized in haystack:
            matches.append(indicator)
            continue
        indicator_tokens = _tokens(normalized)
        if not indicator_tokens:
            continue
        overlap = haystack_tokens.intersection(indicator_tokens)
        required = min(4, max(2, len(indicator_tokens) // 3))
        if len(overlap) >= required:
            matches.append(indicator)
    return matches


def _tokens(value: str) -> list[str]:
    stopwords = {
        "a",
        "an",
        "and",
        "as",
        "by",
        "for",
        "from",
        "in",
        "is",
        "it",
        "of",
        "or",
        "the",
        "to",
        "with",
    }
    token = ""
    tokens: list[str] = []
    for char in value.lower():
        if char.isalnum() or char in {"_", "-", "/", "."}:
            token += char
        elif token:
            if len(token) > 2 and token not in stopwords:
                tokens.append(token)
            token = ""
    if token and len(token) > 2 and token not in stopwords:
        tokens.append(token)
    return tokens


def _draft_title(classification: Classification, workflow_id: str, observed: str) -> str:
    first_line = observed.strip().splitlines()[0] if observed.strip() else "reported behavior"
    return f"{classification}: {workflow_id}: {first_line[:96]}"


def _draft_summary(classification: Classification) -> str:
    if classification == "bug":
        return (
            "The observed behavior appears to violate an implemented workflow contract "
            "while the supplied preconditions are marked as met."
        )
    if classification == "feature_request":
        return "The requested behavior appears to be outside the implemented workflow contract."
    if classification == "documentation_gap":
        return "The report indicates the implemented behavior or support boundary is not documented clearly enough."
    return "The observed result appears consistent with an intentional auth, namespace, lock, quota, or policy rejection."


def _load_contract_yaml(relative_path: str) -> dict[str, Any]:
    resource = importlib.resources.files("kvm_control.contracts")
    for part in relative_path.split("/"):
        resource = resource.joinpath(part)
    payload = yaml.safe_load(resource.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{relative_path} did not contain a YAML object")
    return payload


def dumps_report(draft: dict[str, Any]) -> str:
    return json.dumps(draft, indent=2, sort_keys=True) + "\n"
