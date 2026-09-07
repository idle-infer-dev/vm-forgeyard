from __future__ import annotations

import importlib.resources
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


ALLOWED_CATEGORY_NAMES = {"bug", "feature_request", "documentation_gap", "policy_rejection"}
ALLOWED_PRECONDITION_LEVELS = {"MUST", "SHOULD", "MAY"}
ALLOWED_STATUSES = {"intended", "implemented", "partially_implemented", "planned", "deprecated"}
REQUIRED_WORKFLOW_FIELDS = {
    "schema_version",
    "id",
    "status",
    "summary",
    "classification",
    "actors",
    "auth",
    "preconditions",
    "steps",
    "success_criteria",
    "bug_indicators",
    "feature_request_indicators",
    "documentation_gap_indicators",
    "related",
}


@dataclass(frozen=True)
class ContractValidationResult:
    capabilities_id: str
    workflow_count: int
    workflow_ids: list[str]


class ContractValidationError(ValueError):
    pass


def validate_packaged_contracts(repository_root: Path | None = None) -> ContractValidationResult:
    errors = collect_contract_errors(repository_root=repository_root)
    if errors:
        raise ContractValidationError("\n".join(errors))
    capabilities = _load_contract_yaml("capabilities.v1.yaml")
    workflow_ids = [workflow["id"] for workflow in capabilities["workflows"]]
    return ContractValidationResult(
        capabilities_id=capabilities["id"],
        workflow_count=len(workflow_ids),
        workflow_ids=workflow_ids,
    )


def collect_contract_errors(repository_root: Path | None = None) -> list[str]:
    root = repository_root or _default_repository_root()
    errors: list[str] = []
    try:
        schema = _load_contract_yaml("workflow-contract.schema.v1.yaml")
        capabilities = _load_contract_yaml("capabilities.v1.yaml")
    except Exception as exc:
        return [f"failed to load base contract files: {exc}"]

    errors.extend(_validate_schema(schema))
    errors.extend(_validate_capabilities(capabilities))

    workflow_entries = capabilities.get("workflows") if isinstance(capabilities, dict) else None
    if not isinstance(workflow_entries, list):
        return errors

    indexed_files: set[str] = set()
    indexed_uris: set[str] = set()
    for workflow_entry in workflow_entries:
        if not isinstance(workflow_entry, dict):
            errors.append("capabilities workflow entry must be an object")
            continue
        workflow_file = workflow_entry.get("file")
        workflow_uri = workflow_entry.get("uri")
        if isinstance(workflow_file, str):
            indexed_files.add(workflow_file)
        if isinstance(workflow_uri, str):
            indexed_uris.add(workflow_uri)
        if not isinstance(workflow_file, str):
            continue
        try:
            workflow = _load_contract_yaml(workflow_file)
        except Exception as exc:
            errors.append(f"{workflow_file}: failed to load workflow contract: {exc}")
            continue
        errors.extend(_validate_workflow(workflow_file, workflow_entry, workflow, root))

    packaged_workflow_files = set(_packaged_workflow_files())
    missing_from_index = sorted(packaged_workflow_files - indexed_files)
    extra_in_index = sorted(indexed_files - packaged_workflow_files)
    for workflow_file in missing_from_index:
        errors.append(f"{workflow_file}: packaged workflow is not listed in capabilities.v1.yaml")
    for workflow_file in extra_in_index:
        errors.append(f"{workflow_file}: capabilities.v1.yaml lists a workflow file that is not packaged")

    contract_resource_uris = _contract_resource_uris()
    missing_resources = sorted(indexed_uris - contract_resource_uris)
    for uri in missing_resources:
        errors.append(f"{uri}: workflow is listed in capabilities.v1.yaml but not exposed as an MCP contract resource")

    return errors


def _validate_schema(schema: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(schema, dict):
        return ["workflow-contract.schema.v1.yaml: schema must be an object"]
    required = set(schema.get("required") or [])
    missing_required = sorted(REQUIRED_WORKFLOW_FIELDS - required)
    for field in missing_required:
        errors.append(f"workflow-contract.schema.v1.yaml: schema does not require {field}")
    return errors


def _validate_capabilities(capabilities: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(capabilities, dict):
        return ["capabilities.v1.yaml: capabilities contract must be an object"]
    for field in ("schema_version", "id", "status", "summary", "classification", "workflows", "related"):
        if field not in capabilities:
            errors.append(f"capabilities.v1.yaml: missing required field {field}")
    if capabilities.get("schema_version") != 1:
        errors.append("capabilities.v1.yaml: schema_version must be 1")
    if capabilities.get("status") not in ALLOWED_STATUSES:
        errors.append("capabilities.v1.yaml: status is not an allowed contract status")
    errors.extend(_validate_classification("capabilities.v1.yaml", capabilities.get("classification")))
    workflows = capabilities.get("workflows")
    if not isinstance(workflows, list) or not workflows:
        errors.append("capabilities.v1.yaml: workflows must be a non-empty list")
        return errors
    seen_ids: set[str] = set()
    seen_files: set[str] = set()
    seen_uris: set[str] = set()
    for index, workflow in enumerate(workflows):
        prefix = f"capabilities.v1.yaml: workflows[{index}]"
        if not isinstance(workflow, dict):
            errors.append(f"{prefix} must be an object")
            continue
        for field in ("id", "uri", "file", "status"):
            if not isinstance(workflow.get(field), str) or not workflow[field]:
                errors.append(f"{prefix}.{field} must be a non-empty string")
        if workflow.get("status") not in ALLOWED_STATUSES:
            errors.append(f"{prefix}.status is not an allowed contract status")
        _check_unique(errors, seen_ids, workflow.get("id"), f"{prefix}.id")
        _check_unique(errors, seen_files, workflow.get("file"), f"{prefix}.file")
        _check_unique(errors, seen_uris, workflow.get("uri"), f"{prefix}.uri")
    return errors


def _validate_workflow(path: str, entry: dict[str, Any], workflow: Any, repository_root: Path) -> list[str]:
    errors: list[str] = []
    if not isinstance(workflow, dict):
        return [f"{path}: workflow contract must be an object"]
    missing = sorted(REQUIRED_WORKFLOW_FIELDS - set(workflow))
    extra = sorted(set(workflow) - REQUIRED_WORKFLOW_FIELDS)
    for field in missing:
        errors.append(f"{path}: missing required field {field}")
    for field in extra:
        errors.append(f"{path}: unexpected field {field}")
    if workflow.get("schema_version") != 1:
        errors.append(f"{path}: schema_version must be 1")
    if workflow.get("id") != entry.get("id"):
        errors.append(f"{path}: workflow id must match capabilities entry id")
    if workflow.get("status") != entry.get("status"):
        errors.append(f"{path}: workflow status must match capabilities entry status")
    if workflow.get("status") not in ALLOWED_STATUSES:
        errors.append(f"{path}: status is not an allowed contract status")
    errors.extend(_validate_classification(path, workflow.get("classification")))

    actors = workflow.get("actors")
    if not _is_non_empty_string_list(actors):
        errors.append(f"{path}: actors must be a non-empty string list")
        actor_names: set[str] = set()
    else:
        actor_names = set(actors)

    if not isinstance(workflow.get("auth"), dict):
        errors.append(f"{path}: auth must be an object")
    errors.extend(_validate_preconditions(path, workflow.get("preconditions")))
    errors.extend(_validate_steps(path, workflow.get("steps"), actor_names))
    for field in ("success_criteria", "bug_indicators", "feature_request_indicators", "documentation_gap_indicators"):
        if not _is_non_empty_string_list(workflow.get(field)):
            errors.append(f"{path}: {field} must be a non-empty string list")
    errors.extend(_validate_related(path, workflow.get("related"), repository_root))
    return errors


def _validate_classification(path: str, classification: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(classification, dict):
        return [f"{path}: classification must be an object"]
    for field in ("purpose", "default_rule", "categories"):
        if field not in classification:
            errors.append(f"{path}: classification missing {field}")
    categories = classification.get("categories")
    if not isinstance(categories, list) or not categories:
        errors.append(f"{path}: classification.categories must be a non-empty list")
        return errors
    names = []
    for index, category in enumerate(categories):
        prefix = f"{path}: classification.categories[{index}]"
        if not isinstance(category, dict):
            errors.append(f"{prefix} must be an object")
            continue
        name = category.get("name")
        meaning = category.get("meaning")
        if name not in ALLOWED_CATEGORY_NAMES:
            errors.append(f"{prefix}.name is not an allowed category")
        if not isinstance(meaning, str) or not meaning:
            errors.append(f"{prefix}.meaning must be a non-empty string")
        if isinstance(name, str):
            names.append(name)
    missing_categories = sorted(ALLOWED_CATEGORY_NAMES - set(names))
    for name in missing_categories:
        errors.append(f"{path}: classification.categories missing {name}")
    return errors


def _validate_preconditions(path: str, preconditions: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(preconditions, list) or not preconditions:
        return [f"{path}: preconditions must be a non-empty list"]
    for index, precondition in enumerate(preconditions):
        prefix = f"{path}: preconditions[{index}]"
        if not isinstance(precondition, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if precondition.get("level") not in ALLOWED_PRECONDITION_LEVELS:
            errors.append(f"{prefix}.level is not allowed")
        if not isinstance(precondition.get("text"), str) or not precondition["text"]:
            errors.append(f"{prefix}.text must be a non-empty string")
    return errors


def _validate_steps(path: str, steps: Any, actor_names: set[str]) -> list[str]:
    errors: list[str] = []
    if not isinstance(steps, list) or not steps:
        return [f"{path}: steps must be a non-empty list"]
    seen_ids: set[str] = set()
    for index, step in enumerate(steps):
        prefix = f"{path}: steps[{index}]"
        if not isinstance(step, dict):
            errors.append(f"{prefix} must be an object")
            continue
        for field in ("id", "actor", "action", "expected"):
            if not isinstance(step.get(field), str) or not step[field]:
                errors.append(f"{prefix}.{field} must be a non-empty string")
        _check_unique(errors, seen_ids, step.get("id"), f"{prefix}.id")
        actor = step.get("actor")
        if actor_names and actor not in actor_names:
            errors.append(f"{prefix}.actor must be listed in actors")
    return errors


def _validate_related(path: str, related: Any, repository_root: Path) -> list[str]:
    errors: list[str] = []
    if not isinstance(related, dict):
        return [f"{path}: related must be an object"]
    for field in ("mcp_resources", "mcp_tools", "http_paths", "files"):
        value = related.get(field)
        if value is not None and not _is_string_list(value):
            errors.append(f"{path}: related.{field} must be a string list when present")
    for file_name in related.get("files") or []:
        if not (repository_root / file_name).exists():
            errors.append(f"{path}: related file does not exist: {file_name}")
    return errors


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def _is_non_empty_string_list(value: Any) -> bool:
    return _is_string_list(value) and bool(value)


def _check_unique(errors: list[str], seen: set[str], value: Any, label: str) -> None:
    if not isinstance(value, str):
        return
    if value in seen:
        errors.append(f"{label} duplicates {value}")
    seen.add(value)


def _load_contract_yaml(relative_path: str) -> Any:
    return yaml.safe_load(_read_contract_text(relative_path))


def _read_contract_text(relative_path: str) -> str:
    resource = importlib.resources.files("kvm_control.contracts")
    for part in relative_path.split("/"):
        resource = resource.joinpath(part)
    return resource.read_text(encoding="utf-8")


def _packaged_workflow_files() -> list[str]:
    workflow_root = importlib.resources.files("kvm_control.contracts").joinpath("workflows")
    return [f"workflows/{path.name}" for path in workflow_root.iterdir() if path.name.endswith(".yaml")]


def _contract_resource_uris() -> set[str]:
    from kvm_control.mcp_api import CONTRACT_RESOURCES

    return set(CONTRACT_RESOURCES)


def _default_repository_root() -> Path:
    return Path(__file__).resolve().parents[3]
