from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None


class HostConfig(BaseModel):
    vm_cpu_set: list[int] = Field(default_factory=lambda: [0, 1, 2, 3])
    max_vms: int = 16
    max_total_vcpus: int = 24
    max_total_memory_mb: int = 32768
    max_layer3_per_layer2: int = 6


class NetworkConfig(BaseModel):
    cidr: str = "10.80.0.0/20"
    gateway: str = "10.80.0.1"
    dhcp_cidr: str = "10.81.0.0/24"
    mac_prefix: str = "52:54:00"
    segments: list["NetworkSegmentConfig"] = Field(
        default_factory=lambda: [
            NetworkSegmentConfig(id="dev", bridge="dev"),
            NetworkSegmentConfig(id="stage", bridge="stage"),
            NetworkSegmentConfig(id="misc", bridge="misc"),
            NetworkSegmentConfig(id="live", bridge="live"),
        ]
    )


class NetworkSegmentConfig(BaseModel):
    id: str
    bridge: str
    address: str | None = None
    dhcp_range_start: str | None = None
    dhcp_range_end: str | None = None


class FirewallConfig(BaseModel):
    default_ingress_sources: list[str] = Field(default_factory=lambda: ["10.0.0.0/8"])


class LeaseConfig(BaseModel):
    namespace_lock_ttl_seconds: int = 2 * 60 * 60


class GuestBootstrapConfig(BaseModel):
    apt_http_proxy: str | None = None


class AptCachePolicyConfig(BaseModel):
    enabled: bool = False
    proxy_url: str | None = None
    required: bool = False


class BaseImageRecipeConfig(BaseModel):
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
    apt_cache: AptCachePolicyConfig = Field(default_factory=AptCachePolicyConfig)
    boot_mode: Literal["direct_kernel", "grub", "firmware"] = "direct_kernel"
    disk_layout: Literal["filesystem", "gpt-root-last", "vendor"] = "filesystem"
    filesystem: str | None = "ext4"
    output_format: Literal["raw", "qcow2"] = "raw"
    catalog_image_id: str
    postinstall_steps: list[str] = Field(default_factory=list)
    package_manifest_path: str | None = None
    required_role: Literal["admin"] = "admin"
    notes: str | None = None


class Layer2UserAccountConfig(BaseModel):
    username: str
    groups: list[str] = Field(default_factory=list)
    sudo: bool = False
    login: bool = True
    notes: str | None = None


class Layer2ServiceConfig(BaseModel):
    name: str
    package_names: list[str] = Field(default_factory=list)
    enabled_by_default: bool = False
    notes: str | None = None


class Layer2ImageRecipeConfig(BaseModel):
    id: str
    base_image_recipe_id: str
    template_id: str
    catalog_image_id: str
    description: str
    keywords: list[str] = Field(default_factory=list)
    architecture: Literal["amd64", "arm64", "armhf"] = "amd64"
    auto_build_after_base_image: bool = True
    builder_implemented: bool = False
    system_packages: list[str] = Field(default_factory=list)
    python_venv_tools: list[str] = Field(default_factory=list)
    layer2_size_mb: int | None = Field(default=None, ge=1)
    user_accounts: list[Layer2UserAccountConfig] = Field(default_factory=list)
    services: list[Layer2ServiceConfig] = Field(default_factory=list)
    network_interfaces: int = 1
    default_access: Literal["root", "user-only"] = "root"
    notes: str | None = None


def default_layer2_image_recipes() -> list[Layer2ImageRecipeConfig]:
    common_agent_tools = [
        "bash-completion",
        "build-essential",
        "ca-certificates",
        "curl",
        "dnsutils",
        "file",
        "git",
        "jq",
        "less",
        "lsof",
        "make",
        "man-db",
        "netcat-openbsd",
        "openssh-client",
        "pkg-config",
        "pipx",
        "mypy",
        "python3",
        "python3-dev",
        "python3-pip",
        "python3-pytest",
        "python3-setuptools",
        "python3-venv",
        "python3-virtualenv",
        "python3-wheel",
        "ripgrep",
        "rsync",
        "shellcheck",
        "strace",
        "sudo",
        "tcpdump",
        "tmux",
        "tree",
        "unzip",
        "vim-tiny",
        "wget",
        "xz-utils",
        "zip",
    ]
    return [
        Layer2ImageRecipeConfig(
            id="agent-sandbox-tools-ubuntu-24.04-noble-amd64",
            base_image_recipe_id="ubuntu-24.04-noble-amd64",
            template_id="ubuntu-24.04",
            catalog_image_id="default.agent-sandbox-tools.ubuntu-24.04-noble-amd64.layer2",
            description=(
                "Default Ubuntu 24.04 user-only agent sandbox layer2 with common CLI/build tools, "
                "multiple non-root agent accounts, and Python virtualenv tooling available system-wide."
            ),
            keywords=["agent", "sandbox", "tools", "ubuntu", "noble", "ripgrep", "build-essential", "python-venv", "user-only"],
            builder_implemented=True,
            system_packages=common_agent_tools,
            python_venv_tools=[],
            user_accounts=[
                Layer2UserAccountConfig(username=f"agent{i}", groups=["users"], sudo=False, notes="Non-root reusable agent login account.")
                for i in range(1, 9)
            ],
            default_access="user-only",
            notes=(
                "Shared default VMs from this layer2 should expose only non-root accounts. Agents that need "
                "package installation should order a private VM from this image and use a privileged workflow there."
            ),
        ),
        Layer2ImageRecipeConfig(
            id="agent-sandbox-tools-devuan-6-excalibur-amd64",
            base_image_recipe_id="devuan-6-excalibur-amd64",
            template_id="devuan-excalibur",
            catalog_image_id="default.agent-sandbox-tools.devuan-6-excalibur-amd64.layer2",
            description=(
                "Default user-only agent sandbox layer2 with common CLI/build tools, multiple non-root "
                "agent accounts, and Python virtualenv tooling available system-wide."
            ),
            keywords=["agent", "sandbox", "tools", "ripgrep", "build-essential", "python-venv", "user-only"],
            builder_implemented=True,
            system_packages=common_agent_tools,
            python_venv_tools=["pip", "setuptools", "wheel", "virtualenv", "pipx", "pytest", "ruff", "mypy"],
            user_accounts=[
                Layer2UserAccountConfig(username=f"agent{i}", groups=["users"], sudo=False, notes="Non-root reusable agent login account.")
                for i in range(1, 9)
            ],
            default_access="user-only",
            notes=(
                "Shared default VMs from this layer2 should expose only non-root accounts. Agents that need "
                "package installation should order a private VM from this image and use a privileged workflow there."
            ),
        ),
        Layer2ImageRecipeConfig(
            id="browser-mobile-test-devuan-6-excalibur-amd64",
            base_image_recipe_id="devuan-6-excalibur-amd64",
            template_id="devuan-excalibur",
            catalog_image_id="default.browser-mobile-test.devuan-6-excalibur-amd64.layer2",
            description=(
                "Explicit-build browser mobile test layer2 with Playwright Python tooling, system browser "
                "packages, fonts, xvfb, and screenshot/video dependencies for responsive web and PWA tests."
            ),
            keywords=[
                "browser",
                "mobile",
                "playwright",
                "chromium",
                "firefox",
                "responsive",
                "pwa",
                "screenshot",
                "video",
                "touch",
            ],
            auto_build_after_base_image=False,
            builder_implemented=True,
            layer2_size_mb=8192,
            system_packages=[
                "ca-certificates",
                "chromium",
                "curl",
                "ffmpeg",
                "firefox-esr",
                "fonts-dejavu",
                "fonts-liberation",
                "fonts-noto",
                "fonts-noto-color-emoji",
                "git",
                "jq",
                "libasound2",
                "libatk-bridge2.0-0",
                "libatk1.0-0",
                "libcairo2",
                "libcups2",
                "libdrm2",
                "libgbm1",
                "libgtk-3-0",
                "libnss3",
                "libpango-1.0-0",
                "libx11-xcb1",
                "libxcomposite1",
                "libxdamage1",
                "libxfixes3",
                "libxkbcommon0",
                "libxrandr2",
                "libxshmfence1",
                "nodejs",
                "npm",
                "python3",
                "python3-pip",
                "python3-pytest",
                "python3-venv",
                "xauth",
                "xvfb",
            ],
            python_venv_tools=["playwright", "pytest", "pytest-playwright"],
            user_accounts=[
                Layer2UserAccountConfig(username="browser", groups=["users"], sudo=False, notes="Default non-root account for browser mobile tests."),
            ],
            default_access="user-only",
            notes=(
                "This image is for browser-level mobile emulation, not Android. Tests should use Playwright "
                "device profiles for viewport, user agent, device scale factor, touch, locale, geolocation, "
                "screenshots, and video. Use explicit browser executable paths when relying on distro "
                "chromium/firefox packages rather than Playwright-downloaded browser bundles."
            ),
        ),
        Layer2ImageRecipeConfig(
            id="network-service-lab-devuan-6-excalibur-amd64",
            base_image_recipe_id="devuan-6-excalibur-amd64",
            template_id="devuan-excalibur",
            catalog_image_id="default.network-service-lab.devuan-6-excalibur-amd64.layer2",
            description=(
                "Generic disabled-by-default network service lab image for DNS, apt repositories, mail catchall, "
                "POP3, rsync, HTTP/HTTPS static storage, DHCP, firewalling, and network impairment tests."
            ),
            keywords=[
                "network",
                "service-lab",
                "dns",
                "apt-repository",
                "mail-catchall",
                "imap",
                "pop3",
                "rsync",
                "http-storage",
                "https-storage",
                "kea",
                "iptables",
                "ipset",
                "shorewall",
                "traffic-shaping",
                "netem",
            ],
            builder_implemented=True,
            system_packages=[
                "apt-utils",
                "bind9",
                "createrepo-c",
                "curl",
                "debhelper",
                "devscripts",
                "dnsutils",
                "dovecot-core",
                "dovecot-imapd",
                "dovecot-pop3d",
                "dpkg-dev",
                "iptables",
                "iproute2",
                "ipset",
                "kea-dhcp4-server",
                "lighttpd",
                "nginx-light",
                "opensmtpd",
                "openssl",
                "python3",
                "python3-venv",
                "reprepro",
                "rsync",
                "shorewall",
                "tcpdump",
            ],
            user_accounts=[
                Layer2UserAccountConfig(username="serviceadmin", groups=["users"], sudo=True, notes="Administrative setup account for enabling lab services."),
                Layer2UserAccountConfig(username="catchall", groups=["users"], sudo=False, notes="Default mailbox account for catchall mail tests."),
            ],
            services=[
                Layer2ServiceConfig(name="dns", package_names=["bind9"], notes="Ready to configure authoritative or recursive DNS."),
                Layer2ServiceConfig(name="apt-repository", package_names=["reprepro", "dpkg-dev", "nginx-light"], notes="Repository serving, not a cache."),
                Layer2ServiceConfig(name="mail-catchall-imap-pop3", package_names=["opensmtpd", "dovecot-imapd", "dovecot-pop3d"], notes="Catchall mailbox by default with IMAP and POP3 access; named mailboxes may be added later."),
                Layer2ServiceConfig(name="rsync", package_names=["rsync"], notes="Open rsync service rooted in writable storage."),
                Layer2ServiceConfig(name="http-https-storage", package_names=["nginx-light", "openssl"], notes="Static delivery of writable rsync shares."),
                Layer2ServiceConfig(name="dhcp", package_names=["kea-dhcp4-server"], notes="Kea DHCP server prepared but disabled."),
                Layer2ServiceConfig(name="traffic-control", package_names=["iproute2", "iptables", "ipset", "shorewall"], notes="tc/netem delay, loss, shaping, and routed firewall tests."),
            ],
            network_interfaces=2,
            default_access="root",
            notes=(
                "All daemons should be installed but disabled by default. The VM should have two NICs on the same "
                "kvm-control network so tests can route through it for in-traffic-shaping-out scenarios."
            ),
        ),
    ]


def default_base_image_recipes() -> list[BaseImageRecipeConfig]:
    return [
        BaseImageRecipeConfig(
            id="ubuntu-24.04-noble-amd64",
            distro="Ubuntu",
            version="24.04 LTS",
            suite="noble",
            architecture="amd64",
            method="debootstrap",
            package_manager="apt",
            repository_urls=["http://archive.ubuntu.com/ubuntu/"],
            boot_mode="direct_kernel",
            disk_layout="filesystem",
            catalog_image_id="ubuntu-24.04-noble-amd64",
            notes="Pinned Ubuntu 24.04 LTS default recipe; builder implementation is pending.",
        ),
        BaseImageRecipeConfig(
            id="devuan-6-excalibur-amd64",
            distro="Devuan",
            version="6",
            suite="excalibur",
            architecture="amd64",
            method="debootstrap",
            package_manager="apt",
            repository_urls=["http://deb.devuan.org/merged/"],
            boot_mode="direct_kernel",
            disk_layout="filesystem",
            catalog_image_id="devuan-6-excalibur-amd64",
            notes="Pinned Devuan Excalibur default recipe; builder implementation is pending.",
        ),
        BaseImageRecipeConfig(
            id="openbsd-7.9-amd64",
            distro="OpenBSD",
            version="7.9",
            architecture="amd64",
            method="installer",
            package_manager="pkg_add",
            repository_urls=["https://cdn.openbsd.org/pub/OpenBSD/7.9/"],
            boot_mode="grub",
            disk_layout="gpt-root-last",
            filesystem=None,
            output_format="raw",
            catalog_image_id="openbsd-7.9-amd64",
            notes="Pinned OpenBSD release recipe; installer/import implementation is pending.",
        ),
    ]


class ImageFactoryConfig(BaseModel):
    recipes: list[BaseImageRecipeConfig] = Field(default_factory=default_base_image_recipes)
    layer2_recipes: list[Layer2ImageRecipeConfig] = Field(default_factory=default_layer2_image_recipes)
    authorized_keys_path: Path = Path("/root/.ssh/authorized_keys")


class StorageConfig(BaseModel):
    base_dir: Path = Path("./var/lib/kvm-control/base")
    layer2_dir: Path = Path("./var/lib/kvm-control/layer2")
    layer3_dir: Path = Path("./var/lib/kvm-control/layer3")
    image_remote_dir: Path = Path("./var/lib/kvm-control/image-remote")
    image_remote_backend: Literal["local", "rsync"] = "local"
    image_remote_rsync_host: str | None = None
    image_remote_rsync_module: str | None = None
    image_remote_rsync_subdir: str = "kvm-control-images"
    image_remote_rsync_timeout_s: int = 30
    trash_dir: Path = Path("./var/lib/kvm-control/trash")
    webroot_dir: Path = Path("./var/lib/kvm-control/webroot")
    state_dir: Path = Path("./var/lib/kvm-control/state")
    requests_dir: Path = Path("./run/kvm-control/requests")
    runtime_dir: Path = Path("./run/kvm-control/runtime")
    audit_log: Path = Path("./var/lib/kvm-control/state/audit.log")
    disk_full_threshold_bytes: int = 64 * 1024 * 1024


class AuthAclConfig(BaseModel):
    users: list[str]
    source_cidrs: list[str] = Field(default_factory=list)
    zones: list[Literal["dev", "stage", "misc", "live"]]


class AuthConfig(BaseModel):
    mode: Literal["enforced", "open"] = "enforced"
    username: str | None = None
    password: str | None = None
    admin_token: str | None = None
    admin_token_hash: str | None = None
    trusted_proxy_cidrs: list[str] = Field(default_factory=list)
    acl: list[AuthAclConfig] = Field(
        default_factory=lambda: [
            AuthAclConfig(users=["admin"], zones=["dev", "stage", "misc", "live"]),
            AuthAclConfig(users=["dev"], zones=["dev"]),
            AuthAclConfig(users=["staging"], zones=["stage"]),
            AuthAclConfig(users=["live"], zones=["live"]),
            AuthAclConfig(users=["git.*"], zones=["dev"]),
        ]
    )

    @property
    def enabled(self) -> bool:
        return bool((self.username and self.password) or self.admin_token or self.admin_token_hash)


class TemplateConfig(BaseModel):
    id: str
    base_image: str
    base_image_format: Literal["qcow2", "raw"] = "qcow2"
    architecture: str = "x86_64"
    boot_mode: Literal["disk", "direct_kernel"] = "disk"
    kernel_path: str | None = None
    initrd_path: str | None = None
    kernel_append: str | None = None
    max_vcpus: int
    max_memory_mb: int
    default_vcpus: int = 2
    default_memory_mb: int = 2048


class AppConfig(BaseModel):
    host: HostConfig = Field(default_factory=HostConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    firewall: FirewallConfig = Field(default_factory=FirewallConfig)
    leases: LeaseConfig = Field(default_factory=LeaseConfig)
    guest_bootstrap: GuestBootstrapConfig = Field(default_factory=GuestBootstrapConfig)
    image_factory: ImageFactoryConfig = Field(default_factory=ImageFactoryConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    templates: list[TemplateConfig] = Field(default_factory=list)
    executor_bin: str = "python3 -m kvm_control.root_vm_exec"
    dry_run: bool = False
    source_path: str | None = None

    @property
    def state_db_path(self) -> Path:
        return self.storage.state_dir / "kvm-control.db"


DEFAULT_CONFIG = AppConfig(
    templates=[
        TemplateConfig(
            id="ubuntu-24.04",
            base_image="ubuntu-24.04-base.qcow2",
            max_vcpus=8,
            max_memory_mb=8192,
            default_vcpus=2,
            default_memory_mb=2048,
        )
    ]
)


def load_config(path: str | Path | None = None) -> AppConfig:
    if path is None:
        config = DEFAULT_CONFIG
    else:
        raw = _load_config_file(Path(path))
        config = _model_validate(AppConfig, raw)
        config.source_path = str(Path(path))
    ensure_directories(config)
    return config


def ensure_directories(config: AppConfig) -> None:
    storage = config.storage
    for path in (
        storage.base_dir,
        storage.layer2_dir,
        storage.layer3_dir,
        storage.image_remote_dir,
        storage.trash_dir,
        storage.webroot_dir,
        storage.state_dir,
        storage.requests_dir,
        storage.runtime_dir,
    ):
        path.mkdir(parents=True, exist_ok=True)


def template_map(config: AppConfig) -> dict[str, TemplateConfig]:
    return {template.id: template for template in config.templates}


def base_image_recipe_map(config: AppConfig) -> dict[str, BaseImageRecipeConfig]:
    return {recipe.id: recipe for recipe in config.image_factory.recipes}


def layer2_image_recipe_map(config: AppConfig) -> dict[str, Layer2ImageRecipeConfig]:
    return {recipe.id: recipe for recipe in config.image_factory.layer2_recipes}


def config_to_dict(config: AppConfig) -> dict[str, Any]:
    if hasattr(config, "model_dump"):
        return config.model_dump(mode="json")
    return json.loads(config.json())


def _load_config_file(path: Path) -> dict[str, Any]:
    text = path.read_text()
    if path.suffix == ".json":
        return json.loads(text)
    if yaml is None:
        raise RuntimeError("YAML config requires PyYAML; use JSON config or install PyYAML")
    return yaml.safe_load(text) or {}


def _model_validate(model: type[BaseModel], payload: dict[str, Any]) -> Any:
    if hasattr(model, "model_validate"):
        return model.model_validate(payload)
    return model.parse_obj(payload)
