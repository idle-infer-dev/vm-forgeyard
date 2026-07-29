from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


PowerState = Literal["stopped", "starting", "running", "paused", "stopping", "failed"]
ReadinessState = Literal["booting", "configuring", "network_ready", "ready", "failed"]
VmStatus = Literal["creating", "stopped", "running", "paused", "reverting", "deleting", "failed"]
OperationStatus = Literal["queued", "running", "completed", "failed", "rejected"]
LayerPresence = Literal["present", "absent", "trashed"]
VmRetention = Literal["ephemeral", "keep_stopped", "archive", "protected", "live"]
RunStatus = Literal["pending", "running", "completed", "failed", "aborted"]
RunEventType = Literal["disk_full", "warning", "info", "api_reject", "vm_crash"]
EstimateSource = Literal["ai", "history", "manual", "api-feedback"]
ImageCacheState = Literal["known", "fetching", "present", "retiring", "failed"]
BaseImageBuildStatus = Literal["planned", "completed"]
TestsuiteArtifactKind = Literal["test_script", "test_bundle", "test_dataset", "other"]
TestsuiteDependencyStatus = Literal["active", "obsolete"]
ValidationStatus = Literal["unverified", "verified", "failed"]
ResultArtifactKind = Literal["run_report", "human_report", "test_log", "db_dump", "state_snapshot", "trace_bundle", "other"]
FirewallEgressRuleMode = Literal["allow_all", "cidr"]
FirewallEgressRuleInputMode = Literal["allow_all", "cidr", "single_ip"]
FirewallRuleMode = Literal["allow_all", "single_ip"]
FirewallTargetZone = Literal["net", "dev", "stage", "misc", "live"]
EndpointWorkaroundKind = Literal["fqdn", "ip"]
EndpointWorkaroundType = Literal["hosts_entry", "dnat"]
AuthRole = Literal["admin", "dev", "staging", "live", "repository"]


class CreateVmRequest(BaseModel):
    namespace: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._+=-]+$")
    template_id: str
    vm_slot: str = Field(pattern=r"^[A-Za-z0-9_+=-]+$")
    network_id: str = Field(default="dev", pattern=r"^[A-Za-z0-9_+=-]+$")
    vcpus: int | None = None
    memory_mb: int | None = None
    estimated_layer3_growth_mb: int | None = None
    layer3_size_mb: int | None = Field(default=None, ge=1)
    lock_resource_id: str | None = None
    autostart: bool = True
    image_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:-]+$")
    retention: VmRetention | None = None
    retention_reason: str | None = None
    purpose: str | None = None
    agent_session_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:/+=-]+$")
    agent_label: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:-]+$")
    handoff: str | None = None
    ssh_public_key: str | None = Field(default=None, max_length=4096)


class ResizeLayer3Request(BaseModel):
    new_size_mb: int = Field(ge=1)


class WaitVmReadyRequest(BaseModel):
    timeout_s: int = Field(default=120, ge=0, le=900)
    poll_interval_s: int = Field(default=5, ge=1, le=60)
    check_ssh: bool = True


class WaitVmReadyResponse(BaseModel):
    vm_id: str
    namespace: str
    ready: bool
    timed_out: bool = False
    elapsed_s: float
    power_state: PowerState
    readiness_state: ReadinessState
    reserved_ip: str
    ssh_target: str
    current_ip: str | None = None
    reason: str | None = None


class SetVmRetentionRequest(BaseModel):
    retention: VmRetention
    reason: str | None = None


class VmActionResponse(BaseModel):
    operation_id: int
    vm_id: str
    namespace: str
    action: str
    status: OperationStatus
    power_state: PowerState
    readiness_state: ReadinessState
    reserved_ip: str
    rejection_category: str | None = None
    rejection_reason: str | None = None
    dry_run: bool = False
    planned_commands: list[list[str]] = Field(default_factory=list)
    executor_results: list[dict] = Field(default_factory=list)
    layer3_disposition: dict | None = None
    retention: VmRetention = "ephemeral"
    retention_reason: str | None = None
    purpose: str | None = None
    agent_session_id: str | None = None
    agent_label: str | None = None
    handoff: str | None = None


class ResizeLayer3Response(BaseModel):
    operation_id: int
    vm_id: str
    namespace: str
    action: str
    status: OperationStatus
    power_state: PowerState
    readiness_state: ReadinessState
    reserved_ip: str
    layer3_path: str
    previous_virtual_size_bytes: int
    new_virtual_size_bytes: int
    dry_run: bool = False
    planned_commands: list[list[str]] = Field(default_factory=list)
    executor_results: list[dict] = Field(default_factory=list)


class PromoteLayer2Response(BaseModel):
    operation_id: int
    vm_id: str
    namespace: str
    action: str
    status: OperationStatus
    power_state: PowerState
    readiness_state: ReadinessState
    source_layer3_path: str
    target_layer2_path: str
    image_id: str | None = None
    dry_run: bool = False
    planned_commands: list[list[str]] = Field(default_factory=list)
    executor_results: list[dict] = Field(default_factory=list)


class PromoteLayer2Request(BaseModel):
    image_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:-]+$")
    description: str | None = None
    visible_name: str | None = None
    keywords: list[str] = Field(default_factory=list)


class PublishImageRequest(BaseModel):
    image_id: str = Field(pattern=r"^[A-Za-z0-9._:-]+$")
    source_vm_id: str
    workflow_name: str = Field(pattern=r"^[A-Za-z0-9._:-]+$")
    workflow_version: str = Field(pattern=r"^[A-Za-z0-9._:-]+$")
    git_ref: str | None = None
    visible_name: str | None = None
    comment: str | None = None
    tags: list[str] = Field(default_factory=list)


class CreateFirewallEgressRuleRequest(BaseModel):
    namespace: str = Field(pattern=r"^[a-zA-Z0-9._-]+$")
    lock_resource_id: str = Field(pattern=r"^[a-zA-Z0-9._:-]+$")
    mode: FirewallEgressRuleInputMode
    target_cidr: str | None = None
    target_ip: str | None = None


class FirewallEgressRuleResponse(BaseModel):
    id: int
    namespace: str
    lock_resource_id: str
    mode: FirewallEgressRuleMode
    target_cidr: str | None = None
    created_at: str
    updated_at: str


class CreateFirewallIngressRuleRequest(BaseModel):
    namespace: str = Field(pattern=r"^[a-zA-Z0-9._-]+$")
    lock_resource_id: str = Field(pattern=r"^[a-zA-Z0-9._:-]+$")
    mode: FirewallRuleMode
    target_ip: str | None = None


class FirewallIngressRuleResponse(BaseModel):
    id: int
    namespace: str
    lock_resource_id: str
    mode: FirewallRuleMode
    target_ip: str | None = None
    created_at: str
    updated_at: str


class CreateFirewallAccessRuleRequest(BaseModel):
    namespace: str = Field(pattern=r"^[a-zA-Z0-9._-]+$")
    lock_resource_id: str = Field(pattern=r"^[a-zA-Z0-9._:-]+$")
    target_zone: FirewallTargetZone
    source_cidr: str


class FirewallAccessRuleResponse(BaseModel):
    id: int
    namespace: str
    lock_resource_id: str
    target_zone: FirewallTargetZone
    source_cidr: str
    created_at: str
    updated_at: str


class CreateEndpointWorkaroundRuleRequest(BaseModel):
    namespace: str = Field(pattern=r"^[a-zA-Z0-9._-]+$")
    lock_resource_id: str = Field(pattern=r"^[a-zA-Z0-9._:-]+$")
    kind: EndpointWorkaroundKind
    value: str = Field(min_length=1, max_length=255)
    workaround_type: EndpointWorkaroundType
    target_ip: str
    apply_on: list[str] = Field(min_length=1)
    maps_to_service: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:-]+$")
    manifest_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:-]+$")
    constraint_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:-]+$")
    notes: str | None = None
    metadata: dict = Field(default_factory=dict)


class EndpointWorkaroundRuleResponse(BaseModel):
    id: int
    namespace: str
    lock_resource_id: str
    kind: EndpointWorkaroundKind
    value: str
    workaround_type: EndpointWorkaroundType
    target_ip: str
    apply_on: list[str] = Field(default_factory=list)
    maps_to_service: str | None = None
    manifest_id: str | None = None
    constraint_id: str | None = None
    notes: str | None = None
    metadata: dict = Field(default_factory=dict)
    created_at: str
    updated_at: str


class ImageActionResponse(BaseModel):
    operation_id: int
    image_id: str
    action: str
    status: OperationStatus
    cache_state: ImageCacheState
    local_path: str
    remote_path: str
    checksum_sha256: str | None = None
    size_bytes: int | None = None
    remote_backend: str | None = None
    remote_verified: bool | None = None
    dry_run: bool = False
    planned_commands: list[list[str]] = Field(default_factory=list)
    executor_results: list[dict] = Field(default_factory=list)


class ImageRecordResponse(BaseModel):
    image_id: str
    namespace: str
    source_vm_id: str
    source_template_id: str
    workflow_name: str
    workflow_version: str
    git_ref: str | None = None
    local_path: str
    remote_path: str
    cache_state: ImageCacheState
    checksum_sha256: str | None = None
    size_bytes: int | None = None
    remote_backend: str | None = None
    metadata: dict = Field(default_factory=dict)
    created_at: str
    updated_at: str
    last_published_at: str | None = None
    last_fetched_at: str | None = None
    last_retired_at: str | None = None


class WebrootArtifactResponse(BaseModel):
    namespace: str
    path: str
    public_path: str
    size_bytes: int
    checksum_sha256: str
    updated_at: str


class WebrootArtifactDeleteResponse(BaseModel):
    namespace: str
    path: str
    public_path: str
    deleted: bool


class AptCachePolicyResponse(BaseModel):
    enabled: bool = False
    proxy_url: str | None = None
    required: bool = False


class BaseImageRecipeResponse(BaseModel):
    id: str
    distro: str
    version: str
    suite: str | None = None
    architecture: Literal["amd64", "arm64", "armhf"]
    method: Literal["debootstrap", "installer", "image_import", "custom"]
    default: bool = True
    development_only: bool = False
    package_manager: str | None = None
    repository_urls: list[str] = Field(default_factory=list)
    apt_cache: AptCachePolicyResponse = Field(default_factory=AptCachePolicyResponse)
    boot_mode: Literal["direct_kernel", "grub", "firmware"]
    disk_layout: Literal["filesystem", "gpt-root-last", "vendor"]
    filesystem: str | None = None
    output_format: Literal["raw", "qcow2"]
    catalog_image_id: str
    postinstall_steps: list[str] = Field(default_factory=list)
    package_manifest_path: str | None = None
    required_role: Literal["admin"] = "admin"
    notes: str | None = None


class Layer2UserAccountResponse(BaseModel):
    username: str
    groups: list[str] = Field(default_factory=list)
    sudo: bool = False
    login: bool = True
    notes: str | None = None


class Layer2ServiceResponse(BaseModel):
    name: str
    package_names: list[str] = Field(default_factory=list)
    enabled_by_default: bool = False
    notes: str | None = None


class Layer2ImageRecipeResponse(BaseModel):
    id: str
    base_image_recipe_id: str
    template_id: str
    catalog_image_id: str
    description: str
    keywords: list[str] = Field(default_factory=list)
    architecture: Literal["amd64", "arm64", "armhf"]
    auto_build_after_base_image: bool = True
    builder_implemented: bool = False
    system_packages: list[str] = Field(default_factory=list)
    python_venv_tools: list[str] = Field(default_factory=list)
    layer2_size_mb: int | None = None
    user_accounts: list[Layer2UserAccountResponse] = Field(default_factory=list)
    services: list[Layer2ServiceResponse] = Field(default_factory=list)
    network_interfaces: int = 1
    default_access: Literal["root", "user-only"] = "root"
    notes: str | None = None


class BuildLayer2ImageRequest(BaseModel):
    force: bool = False
    publish: bool = True
    notes: str | None = None


class Layer2ImageBuildResponse(BaseModel):
    operation_id: int
    recipe_id: str
    status: BaseImageBuildStatus
    required_role: Literal["admin"] = "admin"
    builder_implemented: bool = False
    would_publish: bool = True
    force: bool = False
    catalog_image_id: str
    layer2_path: str
    base_image_path: str
    checksum_sha256: str | None = None
    size_bytes: int | None = None
    architecture: Literal["amd64", "arm64", "armhf"]
    planned_steps: list[str] = Field(default_factory=list)
    idempotent: bool = False
    notes: str | None = None


class BuildBaseImageRequest(BaseModel):
    force: bool = False
    publish: bool = True
    build_default_layer2: bool = True
    image_size_mb: int = Field(default=4096, ge=512)
    notes: str | None = None


class BaseImageBuildPlanResponse(BaseModel):
    operation_id: int
    recipe_id: str
    status: BaseImageBuildStatus
    required_role: Literal["admin"] = "admin"
    builder_implemented: bool = False
    would_publish: bool = True
    force: bool = False
    image_size_mb: int
    catalog_image_id: str
    image_path: str
    metadata_path: str
    kernel_dir: str | None = None
    kernel_path: str | None = None
    initrd_path: str | None = None
    checksum_sha256: str | None = None
    size_bytes: int | None = None
    output_format: Literal["raw", "qcow2"]
    boot_mode: Literal["direct_kernel", "grub", "firmware"]
    disk_layout: Literal["filesystem", "gpt-root-last", "vendor"]
    method: Literal["debootstrap", "installer", "image_import", "custom"]
    architecture: Literal["amd64", "arm64", "armhf"]
    planned_steps: list[str] = Field(default_factory=list)
    layer2_builds: list[Layer2ImageBuildResponse] = Field(default_factory=list)
    notes: str | None = None


class TestsuiteArtifactReference(BaseModel):
    artifact_id: str = Field(pattern=r"^[A-Za-z0-9._:/+=-]+$")
    artifact_uri: str
    kind: TestsuiteArtifactKind
    version: str | None = None
    checksum_sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    signature_uri: str | None = None
    signer_id: str | None = None
    validation_status: ValidationStatus = "unverified"
    notes: str | None = None
    metadata: dict = Field(default_factory=dict)


class CreateTestsuiteDependencyDocumentRequest(BaseModel):
    namespace: str = Field(pattern=r"^[a-zA-Z0-9._-]+$")
    testsuite_id: str = Field(pattern=r"^[A-Za-z0-9._:/+=-]+$")
    testsuite_version: str = Field(pattern=r"^[A-Za-z0-9._:/+=-]+$")
    git_ref: str | None = None
    image_ids: list[str] = Field(default_factory=list)
    artifacts: list[TestsuiteArtifactReference] = Field(default_factory=list)
    status: TestsuiteDependencyStatus = "active"
    notes: str | None = None
    metadata: dict = Field(default_factory=dict)


class TestsuiteDependencyDocumentResponse(BaseModel):
    id: int
    namespace: str
    testsuite_id: str
    testsuite_version: str
    git_ref: str | None = None
    image_ids: list[str]
    artifacts: list[TestsuiteArtifactReference]
    status: TestsuiteDependencyStatus
    notes: str | None = None
    metadata: dict = Field(default_factory=dict)
    created_at: str
    updated_at: str


class ResultUserdataReference(BaseModel):
    artifact_id: str = Field(pattern=r"^[A-Za-z0-9._:/+=-]+$")
    artifact_uri: str
    kind: ResultArtifactKind
    checksum_sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    signature_uri: str | None = None
    signer_id: str | None = None
    validation_status: ValidationStatus = "unverified"
    size_bytes: int | None = Field(default=None, ge=0)
    retention_class: str | None = None
    sensitivity: str | None = None
    format: str | None = None
    notes: str | None = None
    metadata: dict = Field(default_factory=dict)


class RunReportRequest(BaseModel):
    report_id: str = Field(pattern=r"^[A-Za-z0-9._:/+=-]+$")
    report_uri: str
    schema_version: str = Field(pattern=r"^[A-Za-z0-9._:-]+$")
    checksum_sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    signature_uri: str | None = None
    signer_id: str | None = None
    validation_status: ValidationStatus = "unverified"
    result_userdata: list[ResultUserdataReference] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class RunReportResponse(BaseModel):
    run_id: int
    report_id: str
    report_uri: str
    schema_version: str
    checksum_sha256: str | None = None
    signature_uri: str | None = None
    signer_id: str | None = None
    validation_status: ValidationStatus
    result_userdata: list[ResultUserdataReference] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    created_at: str
    updated_at: str


class CreateLockRequest(BaseModel):
    resource_id: str = Field(pattern=r"^[a-zA-Z0-9._:-]+$")
    namespace: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9._-]+$")


class ReleaseLockRequest(BaseModel):
    released_by: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9._-]+$")


class CreateAuthTokenRequest(BaseModel):
    username: str = Field(pattern=r"^(admin|dev|staging|live|git\.[a-zA-Z0-9._-]+)$")
    role: AuthRole | None = None


class AuthTokenCreateResponse(BaseModel):
    token_id: str
    username: str
    role: AuthRole
    namespace: str | None = None
    token: str
    created_at: str


class AuthTokenResponse(BaseModel):
    token_id: str
    username: str
    role: AuthRole
    namespace: str | None = None
    created_at: str
    last_used_at: str | None = None
    revoked_at: str | None = None


class CreateRunRequest(BaseModel):
    namespace: str = Field(pattern=r"^[a-zA-Z0-9._-]+$")
    workflow_name: str = Field(pattern=r"^[a-zA-Z0-9._:-]+$")
    workflow_version: str = Field(pattern=r"^[a-zA-Z0-9._:-]+$")
    git_ref: str | None = None
    vm_ids: list[str] = Field(default_factory=list)
    declared_tests: list[str] = Field(default_factory=list)
    selected_tests: list[str] = Field(default_factory=list)


class RunEstimateRequest(BaseModel):
    estimated_disk_mb: int | None = Field(default=None, ge=0)
    estimated_ram_mb: int | None = Field(default=None, ge=0)
    estimated_duration_s: int | None = Field(default=None, ge=0)
    source: EstimateSource = "manual"
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    notes: str | None = None


class StageStartRequest(BaseModel):
    name: str = Field(pattern=r"^[a-zA-Z0-9._:-]+$")
    order_index: int = Field(default=0, ge=0)


class StageFinishRequest(BaseModel):
    status: Literal["completed", "failed", "aborted"] = "completed"
    notes: str | None = None


class FinishRunRequest(BaseModel):
    status: Literal["completed", "failed", "aborted"] = "completed"
    notes: str | None = None


class RunEventRequest(BaseModel):
    event_type: RunEventType
    message: str
    stage_id: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9._:-]+$")
    details: dict = Field(default_factory=dict)


class IgnoreRunForLearningRequest(BaseModel):
    reason: str
    bug_reference: str | None = None


class RunResponse(BaseModel):
    id: int
    namespace: str
    workflow_name: str
    workflow_version: str
    git_ref: str | None = None
    status: RunStatus
    vm_ids: list[str]
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None


class RunUsageResponse(BaseModel):
    run_id: int
    current_disk_bytes: int
    current_ram_mb: int
    max_disk_bytes: int
    max_ram_mb: int
    sample_count: int
    last_sample_at: str | None = None
