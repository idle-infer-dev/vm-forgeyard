from __future__ import annotations

import ipaddress
import json
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from .config import AppConfig, NetworkSegmentConfig
from .status_bus import StatusEventBus


_WILDCARD_IPV4_CIDRS = ("0.0.0.0/1", "128.0.0.0/1")


_SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS templates (
    template_id TEXT PRIMARY KEY,
    base_image TEXT NOT NULL,
    base_image_format TEXT NOT NULL DEFAULT 'qcow2',
    architecture TEXT NOT NULL DEFAULT 'x86_64',
    boot_mode TEXT NOT NULL DEFAULT 'disk',
    kernel_path TEXT,
    initrd_path TEXT,
    kernel_append TEXT,
    max_vcpus INTEGER NOT NULL,
    max_memory_mb INTEGER NOT NULL,
    default_vcpus INTEGER NOT NULL,
    default_memory_mb INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vm_instances (
    vm_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    vm_slot TEXT NOT NULL,
    template_id TEXT NOT NULL,
    network_id TEXT NOT NULL DEFAULT 'dev',
    vcpus INTEGER NOT NULL,
    memory_mb INTEGER NOT NULL,
    estimated_layer3_growth_mb INTEGER,
    reserved_ip TEXT NOT NULL,
    reserved_mac TEXT NOT NULL,
    power_state TEXT NOT NULL,
    readiness_state TEXT NOT NULL,
    status TEXT NOT NULL,
    layer2_path TEXT NOT NULL,
    layer2_presence TEXT NOT NULL,
    layer3_path TEXT NOT NULL,
    layer3_presence TEXT NOT NULL,
    pause_reason TEXT,
    lock_resource_id TEXT,
    source_image_id TEXT,
    retention TEXT NOT NULL DEFAULT 'ephemeral',
    retention_reason TEXT,
    purpose TEXT,
    agent_session_id TEXT,
    agent_label TEXT,
    handoff TEXT,
    ssh_public_key TEXT,
    nested_virtualization INTEGER NOT NULL DEFAULT 0,
    stopped_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(namespace, vm_slot)
);
CREATE TABLE IF NOT EXISTS image_catalog (
    image_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    source_vm_id TEXT NOT NULL,
    source_template_id TEXT NOT NULL,
    workflow_name TEXT NOT NULL,
    workflow_version TEXT NOT NULL,
    git_ref TEXT,
    local_path TEXT NOT NULL,
    remote_path TEXT NOT NULL,
    remote_backend TEXT NOT NULL DEFAULT 'local',
    cache_state TEXT NOT NULL,
    checksum_sha256 TEXT,
    size_bytes INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_published_at TEXT,
    last_fetched_at TEXT,
    last_retired_at TEXT
);
CREATE TABLE IF NOT EXISTS testsuite_dependency_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    namespace TEXT NOT NULL,
    testsuite_id TEXT NOT NULL,
    testsuite_version TEXT NOT NULL,
    git_ref TEXT,
    image_ids_json TEXT NOT NULL DEFAULT '[]',
    artifacts_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
    notes TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(namespace, testsuite_id, testsuite_version)
);
CREATE TABLE IF NOT EXISTS operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vm_id TEXT,
    namespace TEXT,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    rejection_category TEXT,
    rejection_reason TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS status_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    kind TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    status TEXT,
    namespace TEXT,
    vm_id TEXT,
    run_id INTEGER,
    stage_id TEXT,
    operation_id INTEGER,
    resource_id TEXT,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS ip_reservations (
    namespace TEXT NOT NULL,
    vm_slot TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(namespace, vm_slot),
    UNIQUE(ip_address),
    UNIQUE(mac_address)
);
CREATE TABLE IF NOT EXISTS lock_resources (
    resource_id TEXT PRIMARY KEY,
    holder_namespace TEXT,
    capacity INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL DEFAULT 'active',
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS lock_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    status TEXT NOT NULL,
    last_lease_refresh_at TEXT,
    lease_expires_at TEXT,
    lease_expired_at TEXT,
    lease_ttl_seconds INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS firewall_egress_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    namespace TEXT NOT NULL,
    lock_resource_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    target_ip TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS firewall_ingress_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    namespace TEXT NOT NULL,
    lock_resource_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    target_ip TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS firewall_access_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    namespace TEXT NOT NULL,
    lock_resource_id TEXT NOT NULL,
    target_zone TEXT NOT NULL,
    source_cidr TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(namespace, lock_resource_id, target_zone, source_cidr)
);
CREATE TABLE IF NOT EXISTS endpoint_workaround_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    namespace TEXT NOT NULL,
    lock_resource_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    workaround_type TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    apply_on_json TEXT NOT NULL DEFAULT '[]',
    maps_to_service TEXT,
    manifest_id TEXT,
    constraint_id TEXT,
    notes TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS trash_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path TEXT NOT NULL,
    trashed_path TEXT NOT NULL,
    vm_id TEXT,
    namespace TEXT,
    vm_slot TEXT,
    network_id TEXT,
    retention TEXT,
    retention_reason TEXT,
    purpose TEXT,
    agent_session_id TEXT,
    agent_label TEXT,
    handoff TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    namespace TEXT NOT NULL,
    workflow_name TEXT NOT NULL,
    workflow_version TEXT NOT NULL,
    git_ref TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    vm_ids_json TEXT NOT NULL DEFAULT '[]',
    declared_tests_json TEXT NOT NULL DEFAULT '[]',
    selected_tests_json TEXT NOT NULL DEFAULT '[]',
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    finished_at TEXT,
    duration_s REAL,
    paused_duration_s REAL NOT NULL DEFAULT 0,
    effective_duration_s REAL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS run_estimates (
    run_id INTEGER PRIMARY KEY,
    estimated_disk_mb INTEGER,
    estimated_ram_mb INTEGER,
    estimated_duration_s INTEGER,
    source TEXT NOT NULL,
    confidence REAL,
    notes TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS run_stages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    stage_id TEXT NOT NULL,
    name TEXT NOT NULL,
    order_index INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',
    notes TEXT,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    duration_s REAL,
    paused_duration_s REAL NOT NULL DEFAULT 0,
    effective_duration_s REAL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(run_id, stage_id)
);
CREATE TABLE IF NOT EXISTS run_usage_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    sampled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    disk_bytes INTEGER NOT NULL,
    ram_mb INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS run_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    stage_id TEXT,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS run_learning_exclusions (
    run_id INTEGER PRIMARY KEY,
    reason TEXT NOT NULL,
    bug_reference TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS run_reports (
    run_id INTEGER PRIMARY KEY,
    report_id TEXT NOT NULL,
    report_uri TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    checksum_sha256 TEXT,
    signature_uri TEXT,
    signer_id TEXT,
    validation_status TEXT NOT NULL DEFAULT 'unverified',
    result_userdata_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS run_pause_periods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    stage_id TEXT,
    reason TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    duration_s REAL
);
CREATE TABLE IF NOT EXISTS workflow_test_catalog (
    namespace TEXT NOT NULL,
    workflow_name TEXT NOT NULL,
    workflow_version TEXT NOT NULL,
    test_id TEXT NOT NULL,
    last_seen_run_id INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(namespace, workflow_name, workflow_version, test_id)
);
CREATE TABLE IF NOT EXISTS auth_tokens (
    token_id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    namespace TEXT,
    secret_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT,
    revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS repository_self_registration_keys (
    key_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    source_cidrs_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT,
    revoked_at TEXT
);
"""


class Registry:
    def __init__(self, config: AppConfig, status_bus: StatusEventBus | None = None):
        self.config = config
        self.db_path = Path(config.state_db_path)
        self.status_bus = status_bus
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(vm_instances)").fetchall()}
            if "pause_reason" not in columns:
                conn.execute("ALTER TABLE vm_instances ADD COLUMN pause_reason TEXT")
            if "network_id" not in columns:
                conn.execute("ALTER TABLE vm_instances ADD COLUMN network_id TEXT NOT NULL DEFAULT 'dev'")
            if "source_image_id" not in columns:
                conn.execute("ALTER TABLE vm_instances ADD COLUMN source_image_id TEXT")
            if "retention" not in columns:
                conn.execute("ALTER TABLE vm_instances ADD COLUMN retention TEXT NOT NULL DEFAULT 'ephemeral'")
            if "retention_reason" not in columns:
                conn.execute("ALTER TABLE vm_instances ADD COLUMN retention_reason TEXT")
            if "purpose" not in columns:
                conn.execute("ALTER TABLE vm_instances ADD COLUMN purpose TEXT")
            if "agent_session_id" not in columns:
                conn.execute("ALTER TABLE vm_instances ADD COLUMN agent_session_id TEXT")
            if "agent_label" not in columns:
                conn.execute("ALTER TABLE vm_instances ADD COLUMN agent_label TEXT")
            if "handoff" not in columns:
                conn.execute("ALTER TABLE vm_instances ADD COLUMN handoff TEXT")
            if "ssh_public_key" not in columns:
                conn.execute("ALTER TABLE vm_instances ADD COLUMN ssh_public_key TEXT")
            if "nested_virtualization" not in columns:
                conn.execute("ALTER TABLE vm_instances ADD COLUMN nested_virtualization INTEGER NOT NULL DEFAULT 0")
            if "stopped_at" not in columns:
                conn.execute("ALTER TABLE vm_instances ADD COLUMN stopped_at TEXT")
            template_columns = {row["name"] for row in conn.execute("PRAGMA table_info(templates)").fetchall()}
            if "base_image_format" not in template_columns:
                conn.execute("ALTER TABLE templates ADD COLUMN base_image_format TEXT NOT NULL DEFAULT 'qcow2'")
            if "architecture" not in template_columns:
                conn.execute("ALTER TABLE templates ADD COLUMN architecture TEXT NOT NULL DEFAULT 'x86_64'")
            if "boot_mode" not in template_columns:
                conn.execute("ALTER TABLE templates ADD COLUMN boot_mode TEXT NOT NULL DEFAULT 'disk'")
            if "kernel_path" not in template_columns:
                conn.execute("ALTER TABLE templates ADD COLUMN kernel_path TEXT")
            if "initrd_path" not in template_columns:
                conn.execute("ALTER TABLE templates ADD COLUMN initrd_path TEXT")
            if "kernel_append" not in template_columns:
                conn.execute("ALTER TABLE templates ADD COLUMN kernel_append TEXT")
            run_columns = {row["name"] for row in conn.execute("PRAGMA table_info(runs)").fetchall()}
            if "declared_tests_json" not in run_columns:
                conn.execute("ALTER TABLE runs ADD COLUMN declared_tests_json TEXT NOT NULL DEFAULT '[]'")
            if "selected_tests_json" not in run_columns:
                conn.execute("ALTER TABLE runs ADD COLUMN selected_tests_json TEXT NOT NULL DEFAULT '[]'")
            if "duration_s" not in run_columns:
                conn.execute("ALTER TABLE runs ADD COLUMN duration_s REAL")
            if "paused_duration_s" not in run_columns:
                conn.execute("ALTER TABLE runs ADD COLUMN paused_duration_s REAL NOT NULL DEFAULT 0")
            if "effective_duration_s" not in run_columns:
                conn.execute("ALTER TABLE runs ADD COLUMN effective_duration_s REAL")
            stage_columns = {row["name"] for row in conn.execute("PRAGMA table_info(run_stages)").fetchall()}
            if "paused_duration_s" not in stage_columns:
                conn.execute("ALTER TABLE run_stages ADD COLUMN paused_duration_s REAL NOT NULL DEFAULT 0")
            if "effective_duration_s" not in stage_columns:
                conn.execute("ALTER TABLE run_stages ADD COLUMN effective_duration_s REAL")
            lock_request_columns = {row["name"] for row in conn.execute("PRAGMA table_info(lock_requests)").fetchall()}
            if "last_lease_refresh_at" not in lock_request_columns:
                conn.execute("ALTER TABLE lock_requests ADD COLUMN last_lease_refresh_at TEXT")
            if "lease_expires_at" not in lock_request_columns:
                conn.execute("ALTER TABLE lock_requests ADD COLUMN lease_expires_at TEXT")
            if "lease_expired_at" not in lock_request_columns:
                conn.execute("ALTER TABLE lock_requests ADD COLUMN lease_expired_at TEXT")
            if "lease_ttl_seconds" not in lock_request_columns:
                conn.execute("ALTER TABLE lock_requests ADD COLUMN lease_ttl_seconds INTEGER")
            trash_columns = {row["name"] for row in conn.execute("PRAGMA table_info(trash_items)").fetchall()}
            for column in (
                "namespace",
                "vm_slot",
                "network_id",
                "retention",
                "retention_reason",
                "purpose",
                "agent_session_id",
                "agent_label",
                "handoff",
            ):
                if column not in trash_columns:
                    conn.execute(f"ALTER TABLE trash_items ADD COLUMN {column} TEXT")
            if "metadata_json" not in trash_columns:
                conn.execute("ALTER TABLE trash_items ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'")
            image_columns = {row["name"] for row in conn.execute("PRAGMA table_info(image_catalog)").fetchall()}
            if "git_ref" not in image_columns and image_columns:
                conn.execute("ALTER TABLE image_catalog ADD COLUMN git_ref TEXT")
            if "remote_backend" not in image_columns and image_columns:
                conn.execute("ALTER TABLE image_catalog ADD COLUMN remote_backend TEXT NOT NULL DEFAULT 'local'")
            for template in self.config.templates:
                conn.execute(
                    """
                    INSERT INTO templates(
                        template_id, base_image, base_image_format, architecture, boot_mode,
                        kernel_path, initrd_path, kernel_append, max_vcpus, max_memory_mb,
                        default_vcpus, default_memory_mb
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(template_id) DO UPDATE SET
                      base_image = excluded.base_image,
                      base_image_format = excluded.base_image_format,
                      architecture = excluded.architecture,
                      boot_mode = excluded.boot_mode,
                      kernel_path = excluded.kernel_path,
                      initrd_path = excluded.initrd_path,
                      kernel_append = excluded.kernel_append,
                      max_vcpus = excluded.max_vcpus,
                      max_memory_mb = excluded.max_memory_mb,
                      default_vcpus = excluded.default_vcpus,
                      default_memory_mb = excluded.default_memory_mb
                    """,
                    (
                        template.id,
                        template.base_image,
                        template.base_image_format,
                        template.architecture,
                        template.boot_mode,
                        template.kernel_path,
                        template.initrd_path,
                        template.kernel_append,
                        template.max_vcpus,
                        template.max_memory_mb,
                        template.default_vcpus,
                        template.default_memory_mb,
                    ),
                )
            conn.commit()

    @contextmanager
    def tx(self) -> sqlite3.Connection:
        with self._lock:
            conn = self._connect()
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def list_templates(self) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute("SELECT * FROM templates ORDER BY template_id").fetchall()
        return [dict(row) for row in rows]

    def get_template(self, template_id: str) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM templates WHERE template_id = ?", (template_id,)).fetchone()
        return dict(row) if row else None

    def create_auth_token(self, token_id: str, username: str, role: str, namespace: str | None, secret_hash: str) -> dict[str, Any]:
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO auth_tokens(token_id, username, role, namespace, secret_hash)
                VALUES(?, ?, ?, ?, ?)
                """,
                (token_id, username, role, namespace, secret_hash),
            )
            row = conn.execute("SELECT * FROM auth_tokens WHERE token_id = ?", (token_id,)).fetchone()
        return dict(row)

    def replace_revoked_auth_token(
        self,
        token_id: str,
        username: str,
        role: str,
        namespace: str | None,
        secret_hash: str,
    ) -> dict[str, Any]:
        with self.tx() as conn:
            existing = conn.execute("SELECT * FROM auth_tokens WHERE username = ?", (username,)).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO auth_tokens(token_id, username, role, namespace, secret_hash)
                    VALUES(?, ?, ?, ?, ?)
                    """,
                    (token_id, username, role, namespace, secret_hash),
                )
            elif existing["revoked_at"]:
                conn.execute(
                    """
                    UPDATE auth_tokens
                    SET token_id = ?, role = ?, namespace = ?, secret_hash = ?,
                        created_at = CURRENT_TIMESTAMP, last_used_at = NULL, revoked_at = NULL
                    WHERE username = ?
                    """,
                    (token_id, role, namespace, secret_hash, username),
                )
            else:
                raise ValueError("repository is already registered")
            row = conn.execute("SELECT * FROM auth_tokens WHERE username = ?", (username,)).fetchone()
        return dict(row)

    def get_auth_token(self, token_id: str) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM auth_tokens WHERE token_id = ?", (token_id,)).fetchone()
        return dict(row) if row else None

    def get_auth_token_by_username(self, username: str) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM auth_tokens WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def list_auth_tokens(self) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                """
                SELECT token_id, username, role, namespace, created_at, last_used_at, revoked_at
                FROM auth_tokens
                ORDER BY username
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_auth_token_used(self, token_id: str) -> None:
        with self.tx() as conn:
            conn.execute("UPDATE auth_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token_id = ?", (token_id,))

    def revoke_auth_token(self, token_id: str) -> dict[str, Any] | None:
        with self.tx() as conn:
            conn.execute("UPDATE auth_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token_id = ? AND revoked_at IS NULL", (token_id,))
            row = conn.execute(
                """
                SELECT token_id, username, role, namespace, created_at, last_used_at, revoked_at
                FROM auth_tokens
                WHERE token_id = ?
                """,
                (token_id,),
            ).fetchone()
        return dict(row) if row else None

    def create_repository_self_registration_key(
        self,
        key_id: str,
        name: str,
        secret_hash: str,
        source_cidrs: list[str],
    ) -> dict[str, Any]:
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO repository_self_registration_keys(key_id, name, secret_hash, source_cidrs_json)
                VALUES(?, ?, ?, ?)
                """,
                (key_id, name, secret_hash, json.dumps(source_cidrs)),
            )
            row = conn.execute("SELECT * FROM repository_self_registration_keys WHERE key_id = ?", (key_id,)).fetchone()
        return _decode_repository_self_registration_key(row)

    def get_repository_self_registration_key(self, key_id: str) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM repository_self_registration_keys WHERE key_id = ?", (key_id,)).fetchone()
        return _decode_repository_self_registration_key(row) if row else None

    def list_repository_self_registration_keys(self) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                """
                SELECT key_id, name, source_cidrs_json, created_at, last_used_at, revoked_at
                FROM repository_self_registration_keys
                ORDER BY name
                """
            ).fetchall()
        return [_decode_repository_self_registration_key(row) for row in rows]

    def mark_repository_self_registration_key_used(self, key_id: str) -> None:
        with self.tx() as conn:
            conn.execute("UPDATE repository_self_registration_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_id = ?", (key_id,))

    def revoke_repository_self_registration_key(self, key_id: str) -> dict[str, Any] | None:
        with self.tx() as conn:
            conn.execute(
                """
                UPDATE repository_self_registration_keys
                SET revoked_at = CURRENT_TIMESTAMP
                WHERE key_id = ? AND revoked_at IS NULL
                """,
                (key_id,),
            )
            row = conn.execute(
                """
                SELECT key_id, name, source_cidrs_json, created_at, last_used_at, revoked_at
                FROM repository_self_registration_keys
                WHERE key_id = ?
                """,
                (key_id,),
            ).fetchone()
        return _decode_repository_self_registration_key(row) if row else None

    def _segment_for_network(self, network_id: str) -> NetworkSegmentConfig:
        segments = list(self.config.network.segments)
        segment = next((item for item in segments if item.id == network_id), None)
        if segment is None:
            raise ValueError(f"unknown network {network_id}")
        return segment

    def _network_for_segment(self, network_id: str) -> ipaddress.IPv4Network:
        segments = list(self.config.network.segments)
        segment = self._segment_for_network(network_id)
        if segment.address:
            network = ipaddress.ip_interface(segment.address).network
            if network.version != 4:
                raise ValueError(f"only IPv4 network segments are supported: {network_id}")
            return network

        base = ipaddress.ip_network(self.config.network.cidr)
        if base.version != 4:
            raise ValueError("only IPv4 network reservations are supported")
        if base.prefixlen <= 24:
            subnets = list(base.subnets(new_prefix=24))
            index = segments.index(segment) + 1
            if index < len(subnets):
                return subnets[index]
        return base

    def _ip_in_dynamic_dhcp_pool(self, network_id: str, ip_address: str | ipaddress.IPv4Address) -> bool:
        segment = self._segment_for_network(network_id)
        if not segment.dhcp_range_start or not segment.dhcp_range_end:
            return False
        candidate = ipaddress.ip_address(ip_address)
        start = ipaddress.ip_address(segment.dhcp_range_start)
        end = ipaddress.ip_address(segment.dhcp_range_end)
        if candidate.version != 4 or start.version != 4 or end.version != 4:
            return False
        if start > end:
            start, end = end, start
        return start <= candidate <= end

    def _network_hosts(self, network_id: str) -> list[str]:
        net = self._network_for_segment(network_id)
        return [str(host) for host in list(net.hosts())[10:] if not self._ip_in_dynamic_dhcp_pool(network_id, host)]

    def reserve_ip(self, namespace: str, vm_slot: str, network_id: str) -> dict[str, str]:
        reused = False
        with self.tx() as conn:
            row = conn.execute(
                "SELECT ip_address, mac_address FROM ip_reservations WHERE namespace = ? AND vm_slot = ?",
                (namespace, vm_slot),
            ).fetchone()
            reservation_network = self._network_for_segment(network_id)
            if (
                row
                and ipaddress.ip_address(row["ip_address"]) in reservation_network
                and not self._ip_in_dynamic_dhcp_pool(network_id, row["ip_address"])
            ):
                reservation = {"reserved_ip": row["ip_address"], "reserved_mac": row["mac_address"]}
                reused = True
            else:
                if row:
                    conn.execute(
                        "DELETE FROM ip_reservations WHERE namespace = ? AND vm_slot = ?",
                        (namespace, vm_slot),
                    )
                used_ips = {
                    r["ip_address"] for r in conn.execute("SELECT ip_address FROM ip_reservations").fetchall()
                }
                candidate_ip = next(ip for ip in self._network_hosts(network_id) if ip not in used_ips)
                mac = row["mac_address"] if row else self._generate_mac(conn)
                conn.execute(
                    """
                    INSERT INTO ip_reservations(namespace, vm_slot, ip_address, mac_address)
                    VALUES(?, ?, ?, ?)
                    """,
                    (namespace, vm_slot, candidate_ip, mac),
                )
                reservation = {"reserved_ip": candidate_ip, "reserved_mac": mac}
        self.record_status_event(
            kind="ip_reservation",
            level="info",
            status="completed",
            namespace=namespace,
            summary=f"{'reused' if reused else 'reserved'} IP {reservation['reserved_ip']} for {namespace}/{vm_slot}",
            details={"vm_slot": vm_slot, "network_id": network_id, **reservation, "reused": reused},
        )
        return reservation

    def _generate_mac(self, conn: sqlite3.Connection) -> str:
        prefix = self.config.network.mac_prefix.split(":")
        while True:
            tail = [f"{secrets.randbelow(256):02x}" for _ in range(3)]
            mac = ":".join(prefix + tail)
            exists = conn.execute(
                "SELECT 1 FROM ip_reservations WHERE mac_address = ?", (mac,)
            ).fetchone()
            if not exists:
                return mac

    def create_operation(
        self,
        action: str,
        vm_id: str | None,
        namespace: str | None,
        status: str,
        details: dict[str, Any] | None = None,
        rejection_category: str | None = None,
        rejection_reason: str | None = None,
    ) -> int:
        payload = json.dumps(details or {})
        with self.tx() as conn:
            cur = conn.execute(
                """
                INSERT INTO operations(vm_id, namespace, action, status, rejection_category, rejection_reason, details_json)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (vm_id, namespace, action, status, rejection_category, rejection_reason, payload),
            )
            operation_id = int(cur.lastrowid)
        self.record_status_event(
            kind="operation",
            level=_status_level(status, rejection_category, rejection_reason),
            status=status,
            namespace=namespace,
            vm_id=vm_id,
            operation_id=operation_id,
            summary=_operation_summary(action, status, vm_id, rejection_reason),
            details={
                "action": action,
                "rejection_category": rejection_category,
                "rejection_reason": rejection_reason,
                "details": details or {},
            },
        )
        return operation_id

    def update_operation(self, operation_id: int, status: str, **kwargs: Any) -> None:
        columns = ["status = ?", "updated_at = CURRENT_TIMESTAMP"]
        values: list[Any] = [status]
        for key, value in kwargs.items():
            if key == "details":
                key = "details_json"
                value = json.dumps(value)
            columns.append(f"{key} = ?")
            values.append(value)
        values.append(operation_id)
        with self.tx() as conn:
            conn.execute(
                f"UPDATE operations SET {', '.join(columns)} WHERE id = ?",
                values,
            )
        operation = self.get_operation(operation_id)
        if operation is not None:
            self.record_status_event(
                kind="operation",
                level=_status_level(status, operation.get("rejection_category"), operation.get("rejection_reason")),
                status=status,
                namespace=operation.get("namespace"),
                vm_id=operation.get("vm_id"),
                operation_id=operation_id,
                summary=_operation_summary(operation["action"], status, operation.get("vm_id"), operation.get("rejection_reason")),
                details={
                    "action": operation["action"],
                    "rejection_category": operation.get("rejection_category"),
                    "rejection_reason": operation.get("rejection_reason"),
                    "details": operation.get("details", {}),
                },
            )

    def get_operation(self, operation_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM operations WHERE id = ?", (operation_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["details"] = json.loads(result.pop("details_json"))
        return result

    def list_operations(self, statuses: list[str] | None = None, limit: int = 100) -> list[dict[str, Any]]:
        query = "SELECT * FROM operations"
        params: list[Any] = []
        if statuses:
            placeholders = ", ".join("?" for _ in statuses)
            query += f" WHERE status IN ({placeholders})"
            params.extend(statuses)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self.tx() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_operation_row(row) for row in rows]

    def upsert_image(self, image: dict[str, Any]) -> dict[str, Any]:
        payload = dict(image)
        payload.setdefault("remote_backend", "local")
        payload["metadata_json"] = json.dumps(payload.pop("metadata", {}))
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO image_catalog(
                    image_id, namespace, source_vm_id, source_template_id, workflow_name, workflow_version,
                    git_ref, local_path, remote_path, remote_backend, cache_state, checksum_sha256, size_bytes, metadata_json,
                    last_published_at, last_fetched_at, last_retired_at
                ) VALUES(
                    :image_id, :namespace, :source_vm_id, :source_template_id, :workflow_name, :workflow_version,
                    :git_ref, :local_path, :remote_path, :remote_backend, :cache_state, :checksum_sha256, :size_bytes, :metadata_json,
                    :last_published_at, :last_fetched_at, :last_retired_at
                )
                ON CONFLICT(image_id) DO UPDATE SET
                    namespace = excluded.namespace,
                    source_vm_id = excluded.source_vm_id,
                    source_template_id = excluded.source_template_id,
                    workflow_name = excluded.workflow_name,
                    workflow_version = excluded.workflow_version,
                    git_ref = excluded.git_ref,
                    local_path = excluded.local_path,
                    remote_path = excluded.remote_path,
                    remote_backend = excluded.remote_backend,
                    cache_state = excluded.cache_state,
                    checksum_sha256 = excluded.checksum_sha256,
                    size_bytes = excluded.size_bytes,
                    metadata_json = excluded.metadata_json,
                    last_published_at = excluded.last_published_at,
                    last_fetched_at = excluded.last_fetched_at,
                    last_retired_at = excluded.last_retired_at,
                    updated_at = CURRENT_TIMESTAMP
                """,
                payload,
            )
        result = self.get_image(payload["image_id"])
        if result is None:
            raise KeyError(payload["image_id"])
        return result

    def get_image(self, image_id: str) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM image_catalog WHERE image_id = ?", (image_id,)).fetchone()
        return _image_row(row)

    def list_images(self, namespace: str | None = None, query: str | None = None, keyword: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM image_catalog"
        params: tuple[Any, ...] = ()
        if namespace is not None:
            sql += " WHERE namespace = ?"
            params = (namespace,)
        sql += " ORDER BY image_id"
        with self.tx() as conn:
            rows = conn.execute(sql, params).fetchall()
        images = [_image_row(row) for row in rows]
        search = (query or "").strip().casefold()
        wanted_keyword = (keyword or "").strip().casefold()
        if not search and not wanted_keyword:
            return images

        def searchable_text(image: dict[str, Any]) -> str:
            metadata = image.get("metadata") or {}
            parts = [
                image.get("image_id"),
                image.get("namespace"),
                image.get("source_vm_id"),
                image.get("source_template_id"),
                image.get("workflow_name"),
                image.get("workflow_version"),
                image.get("git_ref"),
                metadata.get("visible_name"),
                metadata.get("description"),
                metadata.get("comment"),
            ]
            parts.extend(str(item) for item in metadata.get("keywords") or [])
            parts.extend(str(item) for item in metadata.get("tags") or [])
            return " ".join(str(part) for part in parts if part).casefold()

        def has_keyword(image: dict[str, Any]) -> bool:
            if not wanted_keyword:
                return True
            metadata = image.get("metadata") or {}
            keywords = [str(item).casefold() for item in metadata.get("keywords") or []]
            tags = [str(item).casefold() for item in metadata.get("tags") or []]
            return wanted_keyword in keywords or wanted_keyword in tags

        return [image for image in images if (not search or search in searchable_text(image)) and has_keyword(image)]

    def patch_image(self, image_id: str, **updates: Any) -> dict[str, Any]:
        columns = ["updated_at = CURRENT_TIMESTAMP"]
        values: list[Any] = []
        for key, value in updates.items():
            if key == "metadata":
                key = "metadata_json"
                value = json.dumps(value)
            columns.append(f"{key} = ?")
            values.append(value)
        values.append(image_id)
        with self.tx() as conn:
            conn.execute(f"UPDATE image_catalog SET {', '.join(columns)} WHERE image_id = ?", values)
        image = self.get_image(image_id)
        if image is None:
            raise KeyError(image_id)
        return image

    def delete_image(self, image_id: str) -> None:
        with self.tx() as conn:
            conn.execute("DELETE FROM image_catalog WHERE image_id = ?", (image_id,))

    def image_active_vm_count(self, image_id: str) -> int:
        with self.tx() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM vm_instances
                WHERE source_image_id = ? AND status != 'deleting'
                """,
                (image_id,),
            ).fetchone()
        return int(row["count"])

    def upsert_testsuite_dependency_document(
        self,
        namespace: str,
        testsuite_id: str,
        testsuite_version: str,
        git_ref: str | None,
        image_ids: list[str],
        artifacts: list[dict[str, Any]],
        status: str,
        notes: str | None,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        unique_image_ids = sorted(set(image_ids))
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO testsuite_dependency_documents(
                    namespace, testsuite_id, testsuite_version, git_ref,
                    image_ids_json, artifacts_json, status, notes, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(namespace, testsuite_id, testsuite_version) DO UPDATE SET
                    git_ref = excluded.git_ref,
                    image_ids_json = excluded.image_ids_json,
                    artifacts_json = excluded.artifacts_json,
                    status = excluded.status,
                    notes = excluded.notes,
                    metadata_json = excluded.metadata_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    namespace,
                    testsuite_id,
                    testsuite_version,
                    git_ref,
                    json.dumps(unique_image_ids),
                    json.dumps(artifacts),
                    status,
                    notes,
                    json.dumps(metadata),
                ),
            )
            row = conn.execute(
                """
                SELECT * FROM testsuite_dependency_documents
                WHERE namespace = ? AND testsuite_id = ? AND testsuite_version = ?
                """,
                (namespace, testsuite_id, testsuite_version),
            ).fetchone()
        if row is None:
            raise KeyError(testsuite_id)
        return _testsuite_dependency_document_row(row)

    def list_testsuite_dependency_documents(
        self,
        namespace: str | None = None,
        testsuite_id: str | None = None,
        image_id: str | None = None,
        artifact_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM testsuite_dependency_documents"
        params: list[Any] = []
        clauses: list[str] = []
        if namespace is not None:
            clauses.append("namespace = ?")
            params.append(namespace)
        if testsuite_id is not None:
            clauses.append("testsuite_id = ?")
            params.append(testsuite_id)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY namespace, testsuite_id, testsuite_version, id"
        with self.tx() as conn:
            rows = conn.execute(query, params).fetchall()
        documents = [_testsuite_dependency_document_row(row) for row in rows]
        if image_id is not None:
            documents = [document for document in documents if image_id in document["image_ids"]]
        if artifact_id is not None:
            documents = [
                document
                for document in documents
                if any(artifact.get("artifact_id") == artifact_id for artifact in document["artifacts"])
            ]
        return documents

    def get_testsuite_dependency_document(self, document_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM testsuite_dependency_documents WHERE id = ?", (document_id,)).fetchone()
        return _testsuite_dependency_document_row(row) if row else None

    def delete_testsuite_dependency_document(self, document_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM testsuite_dependency_documents WHERE id = ?", (document_id,)).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM testsuite_dependency_documents WHERE id = ?", (document_id,))
        return _testsuite_dependency_document_row(row)

    def list_vms(self) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute("SELECT * FROM vm_instances ORDER BY namespace, vm_slot").fetchall()
        return [dict(row) for row in rows]

    def get_vm(self, vm_id: str) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM vm_instances WHERE vm_id = ?", (vm_id,)).fetchone()
        return dict(row) if row else None

    def get_vm_by_slot(self, namespace: str, vm_slot: str) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute(
                "SELECT * FROM vm_instances WHERE namespace = ? AND vm_slot = ?",
                (namespace, vm_slot),
            ).fetchone()
        return dict(row) if row else None

    def list_vms_for_namespace(self, namespace: str) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT * FROM vm_instances WHERE namespace = ? ORDER BY vm_slot",
                (namespace,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_vms_for_ids(self, vm_ids: list[str]) -> list[dict[str, Any]]:
        if not vm_ids:
            return []
        placeholders = ", ".join("?" for _ in vm_ids)
        with self.tx() as conn:
            rows = conn.execute(
                f"SELECT * FROM vm_instances WHERE vm_id IN ({placeholders}) ORDER BY vm_id",
                vm_ids,
            ).fetchall()
        return [dict(row) for row in rows]

    def list_stopped_ephemeral_vms(self) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM vm_instances
                WHERE retention = 'ephemeral'
                  AND layer3_presence = 'present'
                  AND (
                    power_state IN ('stopped', 'failed')
                    OR status = 'deleting'
                  )
                ORDER BY namespace, vm_slot
                """,
            ).fetchall()
        return [dict(row) for row in rows]

    def upsert_vm(self, vm: dict[str, Any]) -> dict[str, Any]:
        vm = {
            "retention": "ephemeral",
            "retention_reason": None,
            "purpose": None,
            "agent_session_id": None,
            "agent_label": None,
            "handoff": None,
            "ssh_public_key": None,
            "nested_virtualization": 0,
            "stopped_at": None,
            **vm,
        }
        if vm["stopped_at"] is None and vm.get("power_state") in {"stopped", "failed"}:
            vm["stopped_at"] = datetime.now(UTC).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO vm_instances(
                    vm_id, namespace, vm_slot, template_id, network_id, vcpus, memory_mb, estimated_layer3_growth_mb,
                    reserved_ip, reserved_mac, power_state, readiness_state, status,
                    layer2_path, layer2_presence, layer3_path, layer3_presence, pause_reason, lock_resource_id, source_image_id,
                    retention, retention_reason, purpose, agent_session_id, agent_label, handoff, ssh_public_key, nested_virtualization, stopped_at
                ) VALUES(
                    :vm_id, :namespace, :vm_slot, :template_id, :network_id, :vcpus, :memory_mb, :estimated_layer3_growth_mb,
                    :reserved_ip, :reserved_mac, :power_state, :readiness_state, :status,
                    :layer2_path, :layer2_presence, :layer3_path, :layer3_presence, :pause_reason, :lock_resource_id, :source_image_id,
                    :retention, :retention_reason, :purpose, :agent_session_id, :agent_label, :handoff, :ssh_public_key, :nested_virtualization, :stopped_at
                )
                ON CONFLICT(vm_id) DO UPDATE SET
                    network_id = excluded.network_id,
                    vcpus = excluded.vcpus,
                    memory_mb = excluded.memory_mb,
                    estimated_layer3_growth_mb = excluded.estimated_layer3_growth_mb,
                    reserved_ip = excluded.reserved_ip,
                    reserved_mac = excluded.reserved_mac,
                    power_state = excluded.power_state,
                    readiness_state = excluded.readiness_state,
                    status = excluded.status,
                    layer2_path = excluded.layer2_path,
                    layer2_presence = excluded.layer2_presence,
                    layer3_path = excluded.layer3_path,
                    layer3_presence = excluded.layer3_presence,
                    pause_reason = excluded.pause_reason,
                    lock_resource_id = excluded.lock_resource_id,
                    source_image_id = excluded.source_image_id,
                    retention = excluded.retention,
                    retention_reason = excluded.retention_reason,
                    purpose = excluded.purpose,
                    agent_session_id = excluded.agent_session_id,
                    agent_label = excluded.agent_label,
                    handoff = excluded.handoff,
                    ssh_public_key = excluded.ssh_public_key,
                    nested_virtualization = excluded.nested_virtualization,
                    stopped_at = excluded.stopped_at,
                    updated_at = CURRENT_TIMESTAMP
                """,
                vm,
            )
        return self.get_vm(vm["vm_id"])  # type: ignore[arg-type]

    def patch_vm(self, vm_id: str, **updates: Any) -> dict[str, Any]:
        columns = ["updated_at = CURRENT_TIMESTAMP"]
        values: list[Any] = []
        if "power_state" in updates and "stopped_at" not in updates:
            if updates["power_state"] in {"stopped", "failed"}:
                current = self.get_vm(vm_id)
                if current is None or current.get("power_state") != updates["power_state"] or not current.get("stopped_at"):
                    updates["stopped_at"] = datetime.now(UTC).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")
            elif updates["power_state"] in {"starting", "running", "paused"}:
                updates["stopped_at"] = None
        for key, value in updates.items():
            columns.append(f"{key} = ?")
            values.append(value)
        values.append(vm_id)
        with self.tx() as conn:
            conn.execute(f"UPDATE vm_instances SET {', '.join(columns)} WHERE vm_id = ?", values)
        vm = self.get_vm(vm_id)
        if vm is None:
            raise KeyError(vm_id)
        return vm

    def delete_vm(self, vm_id: str) -> None:
        with self.tx() as conn:
            conn.execute("DELETE FROM vm_instances WHERE vm_id = ?", (vm_id,))

    def record_archived_vm(self, vm: dict[str, Any], trashed_path: str, reason: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {
            "reason": reason,
            **(metadata or {}),
        }
        with self.tx() as conn:
            cur = conn.execute(
                """
                INSERT INTO trash_items(
                    source_path, trashed_path, vm_id, namespace, vm_slot, network_id,
                    retention, retention_reason, purpose, agent_session_id, agent_label, handoff, metadata_json
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vm["layer3_path"],
                    trashed_path,
                    vm["vm_id"],
                    vm["namespace"],
                    vm["vm_slot"],
                    vm["network_id"],
                    vm.get("retention"),
                    vm.get("retention_reason"),
                    vm.get("purpose"),
                    vm.get("agent_session_id"),
                    vm.get("agent_label"),
                    vm.get("handoff"),
                    json.dumps(payload),
                ),
            )
            row = conn.execute("SELECT * FROM trash_items WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        return _trash_item_row(row)

    def list_archived_vms(self, namespace: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM trash_items WHERE vm_id IS NOT NULL"
        params: list[Any] = []
        if namespace is not None:
            query += " AND namespace = ?"
            params.append(namespace)
        query += " ORDER BY created_at DESC, id DESC"
        with self.tx() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_trash_item_row(row) for row in rows]

    def next_vm_id(self, namespace: str, vm_slot: str) -> str:
        return f"{namespace}-{vm_slot}"

    def current_capacity(self) -> dict[str, Any]:
        with self.tx() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_vms,
                    COALESCE(SUM(vcpus), 0) AS total_vcpus,
                    COALESCE(SUM(memory_mb), 0) AS total_memory_mb
                FROM vm_instances
                WHERE power_state IN ('starting', 'running')
                """
            ).fetchone()
        return {
            "max_vms": self.config.host.max_vms,
            "max_total_vcpus": self.config.host.max_total_vcpus,
            "max_total_memory_mb": self.config.host.max_total_memory_mb,
            "test_cpu_set": self.config.host.vm_cpu_set,
            "used_vms": row["total_vms"],
            "used_vcpus": row["total_vcpus"],
            "used_memory_mb": row["total_memory_mb"],
        }

    def ensure_capacity(self, vcpus: int, memory_mb: int) -> tuple[bool, str | None]:
        cap = self.current_capacity()
        if cap["used_vms"] >= cap["max_vms"]:
            return False, "vm_limit_reached"
        if cap["used_vcpus"] + vcpus > cap["max_total_vcpus"]:
            return False, "vcpu_limit_reached"
        if cap["used_memory_mb"] + memory_mb > cap["max_total_memory_mb"]:
            return False, "memory_limit_reached"
        return True, None

    def active_nested_virtualization_count(self, namespace: str) -> int:
        with self.tx() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM vm_instances
                WHERE namespace = ?
                  AND nested_virtualization = 1
                  AND power_state IN ('starting', 'running')
                """,
                (namespace,),
            ).fetchone()
        return int(row["count"])

    def namespace_disk_usage(self, namespace: str) -> dict[str, Any]:
        rows = self.list_vms_for_namespace(namespace)
        layer2_paths = {row["layer2_path"] for row in rows if row["layer2_presence"] == "present"}
        layer3_paths = [row["layer3_path"] for row in rows if row["layer3_presence"] == "present"]
        return {
            "namespace": namespace,
            "layer2_bytes": sum(_safe_size(Path(path)) for path in layer2_paths),
            "layer3_bytes": sum(_safe_size(Path(path)) for path in layer3_paths),
            "layer2_images": len(layer2_paths),
            "layer3_images": len(layer3_paths),
        }

    def namespace_ips(self, namespace: str) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                """
                SELECT vm_slot, ip_address, mac_address
                FROM ip_reservations WHERE namespace = ?
                ORDER BY vm_slot
                """,
                (namespace,),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_ip_reservation(self, namespace: str, vm_slot: str) -> None:
        with self.tx() as conn:
            conn.execute(
                "DELETE FROM ip_reservations WHERE namespace = ? AND vm_slot = ?",
                (namespace, vm_slot),
            )

    def active_layer3_count(self, namespace: str, template_id: str) -> int:
        layer2_name = f"{namespace}--{template_id}.qcow2"
        expected_path = str(self.config.storage.layer2_dir / layer2_name)
        with self.tx() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM vm_instances
                WHERE layer2_path = ? AND layer3_presence = 'present'
                """,
                (expected_path,),
            ).fetchone()
        return int(row["count"])

    def ensure_lock_request(self, resource_id: str, namespace: str, ttl_seconds: int | None = None) -> dict[str, Any]:
        if resource_id == f"namespace:{namespace}":
            ttl_seconds = ttl_seconds or self.config.leases.namespace_lock_ttl_seconds
        else:
            ttl_seconds = None
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO lock_resources(resource_id) VALUES(?) ON CONFLICT(resource_id) DO NOTHING",
                (resource_id,),
            )
            row = conn.execute(
                """
                SELECT * FROM lock_requests
                WHERE resource_id = ? AND namespace = ? AND status IN ('queued', 'granted')
                ORDER BY id LIMIT 1
                """,
                (resource_id, namespace),
            ).fetchone()
            if row:
                return dict(row)
            cur = conn.execute(
                """
                INSERT INTO lock_requests(
                    resource_id, namespace, status, last_lease_refresh_at, lease_expires_at, lease_ttl_seconds
                )
                VALUES(
                    ?, ?, 'queued',
                    CASE WHEN ? IS NULL THEN NULL ELSE CURRENT_TIMESTAMP END,
                    CASE WHEN ? IS NULL THEN NULL ELSE datetime(CURRENT_TIMESTAMP, '+' || ? || ' seconds') END,
                    ?
                )
                """,
                (resource_id, namespace, ttl_seconds, ttl_seconds, ttl_seconds, ttl_seconds),
            )
            request_id = int(cur.lastrowid)
            promoted = self._promote_lock_holder(conn, resource_id)
            row = conn.execute("SELECT * FROM lock_requests WHERE id = ?", (request_id,)).fetchone()
        record = dict(row)
        if promoted is not None and promoted["id"] != record["id"]:
            self.record_status_event(
                kind="lock",
                level="info",
                status="granted",
                namespace=promoted["namespace"],
                resource_id=resource_id,
                summary=f"lock {resource_id} granted for {promoted['namespace']}",
                details={"request_id": promoted["id"], "resource_id": resource_id, "namespace": promoted["namespace"]},
            )
        self.record_status_event(
            kind="lock",
            level="info" if record["status"] == "granted" else "warning",
            status=record["status"],
            namespace=namespace,
            resource_id=resource_id,
            summary=f"lock {resource_id} {record['status']} for {namespace}",
            details={"request_id": record["id"], "resource_id": resource_id, "namespace": namespace},
        )
        return record

    def refresh_lock_lease(self, request_id: int, namespace: str, ttl_seconds: int | None = None) -> dict[str, Any]:
        ttl_seconds = ttl_seconds or self.config.leases.namespace_lock_ttl_seconds
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM lock_requests WHERE id = ?", (request_id,)).fetchone()
            if row is None:
                raise KeyError(request_id)
            if row["namespace"] != namespace:
                raise PermissionError("namespace_mismatch")
            if row["resource_id"] != f"namespace:{namespace}":
                raise PermissionError("not_namespace_lock")
            if row["status"] not in {"queued", "granted"}:
                raise PermissionError("lock_not_active")
            conn.execute(
                """
                UPDATE lock_requests
                SET last_lease_refresh_at = CURRENT_TIMESTAMP,
                    lease_expires_at = datetime(CURRENT_TIMESTAMP, '+' || ? || ' seconds'),
                    lease_expired_at = NULL,
                    lease_ttl_seconds = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (ttl_seconds, ttl_seconds, request_id),
            )
            updated = conn.execute("SELECT * FROM lock_requests WHERE id = ?", (request_id,)).fetchone()
        record = dict(updated)
        self.record_status_event(
            kind="lease",
            level="info",
            status="refreshed",
            namespace=namespace,
            resource_id=record["resource_id"],
            summary=f"lease refreshed for namespace lock {record['resource_id']}",
            details={
                "request_id": request_id,
                "resource_id": record["resource_id"],
                "namespace": namespace,
                "lease_expires_at": record["lease_expires_at"],
                "lease_ttl_seconds": ttl_seconds,
            },
        )
        return record

    def list_expired_namespace_lock_leases(self) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM lock_requests
                WHERE status = 'granted'
                  AND resource_id = 'namespace:' || namespace
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= CURRENT_TIMESTAMP
                  AND lease_expired_at IS NULL
                ORDER BY lease_expires_at, id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_lock_lease_expired(self, request_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            conn.execute(
                """
                UPDATE lock_requests
                SET lease_expired_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND lease_expired_at IS NULL
                """,
                (request_id,),
            )
            row = conn.execute("SELECT * FROM lock_requests WHERE id = ?", (request_id,)).fetchone()
        return dict(row) if row else None

    def _promote_lock_holder(self, conn: sqlite3.Connection, resource_id: str) -> dict[str, Any] | None:
        resource = conn.execute(
            "SELECT * FROM lock_resources WHERE resource_id = ?",
            (resource_id,),
        ).fetchone()
        if resource is None or resource["holder_namespace"]:
            return None
        next_row = conn.execute(
            """
            SELECT * FROM lock_requests
            WHERE resource_id = ? AND status = 'queued'
            ORDER BY id LIMIT 1
            """,
            (resource_id,),
        ).fetchone()
        if next_row is None:
            return None
        conn.execute(
            "UPDATE lock_requests SET status = 'granted', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (next_row["id"],),
        )
        conn.execute(
            "UPDATE lock_resources SET holder_namespace = ?, updated_at = CURRENT_TIMESTAMP WHERE resource_id = ?",
            (next_row["namespace"], resource_id),
        )
        return dict(next_row)

    def get_lock_request(self, request_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM lock_requests WHERE id = ?", (request_id,)).fetchone()
        return dict(row) if row else None

    def list_lock_resources(self) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute("SELECT * FROM lock_resources ORDER BY resource_id").fetchall()
        return [dict(row) for row in rows]

    def list_lock_status(self) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                """
                SELECT
                    lr.resource_id,
                    lr.holder_namespace,
                    COALESCE(SUM(CASE WHEN lq.status = 'queued' THEN 1 ELSE 0 END), 0) AS queued_count,
                    COALESCE(SUM(CASE WHEN lq.status = 'granted' THEN 1 ELSE 0 END), 0) AS granted_count
                FROM lock_resources lr
                LEFT JOIN lock_requests lq ON lq.resource_id = lr.resource_id
                GROUP BY lr.resource_id, lr.holder_namespace
                ORDER BY lr.resource_id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def lock_queue(self, resource_id: str) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                """
                SELECT * FROM lock_requests WHERE resource_id = ? AND status IN ('queued', 'granted')
                ORDER BY id
                """,
                (resource_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def release_lock(self, request_id: int, released_by: str) -> dict[str, Any]:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM lock_requests WHERE id = ?", (request_id,)).fetchone()
            if row is None:
                raise KeyError(request_id)
            if row["namespace"] != released_by:
                raise PermissionError("namespace_mismatch")
            conn.execute(
                "UPDATE lock_requests SET status = 'released', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (request_id,),
            )
            conn.execute(
                """
                UPDATE lock_resources
                SET holder_namespace = NULL, updated_at = CURRENT_TIMESTAMP
                WHERE resource_id = ? AND holder_namespace = ?
                """,
                (row["resource_id"], released_by),
            )
            promoted = self._promote_lock_holder(conn, row["resource_id"])
            updated = conn.execute("SELECT * FROM lock_requests WHERE id = ?", (request_id,)).fetchone()
        record = dict(updated)
        if promoted is not None:
            self.record_status_event(
                kind="lock",
                level="info",
                status="granted",
                namespace=promoted["namespace"],
                resource_id=row["resource_id"],
                summary=f"lock {row['resource_id']} granted for {promoted['namespace']}",
                details={"request_id": promoted["id"], "resource_id": row["resource_id"], "namespace": promoted["namespace"]},
            )
        self.record_status_event(
            kind="lock",
            level="info",
            status="released",
            namespace=released_by,
            resource_id=row["resource_id"],
            summary=f"lock {row['resource_id']} released by {released_by}",
            details={"request_id": request_id, "resource_id": row["resource_id"], "namespace": released_by},
        )
        return record

    def create_firewall_egress_rule(self, namespace: str, lock_resource_id: str, mode: str, target_cidr: str | None) -> dict[str, Any]:
        with self.tx() as conn:
            cur = conn.execute(
                """
                INSERT INTO firewall_egress_rules(namespace, lock_resource_id, mode, target_ip)
                VALUES(?, ?, ?, ?)
                """,
                (namespace, lock_resource_id, mode, target_cidr),
            )
            row = conn.execute("SELECT * FROM firewall_egress_rules WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        return dict(row) if row else {}

    def create_firewall_ingress_rule(self, namespace: str, lock_resource_id: str, mode: str, target_ip: str | None) -> dict[str, Any]:
        with self.tx() as conn:
            cur = conn.execute(
                """
                INSERT INTO firewall_ingress_rules(namespace, lock_resource_id, mode, target_ip)
                VALUES(?, ?, ?, ?)
                """,
                (namespace, lock_resource_id, mode, target_ip),
            )
            row = conn.execute("SELECT * FROM firewall_ingress_rules WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        return dict(row) if row else {}

    def list_firewall_egress_rules(self, namespace: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM firewall_egress_rules"
        params: tuple[Any, ...] = ()
        if namespace is not None:
            query += " WHERE namespace = ?"
            params = (namespace,)
        query += " ORDER BY id"
        with self.tx() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def list_firewall_ingress_rules(self, namespace: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM firewall_ingress_rules"
        params: tuple[Any, ...] = ()
        if namespace is not None:
            query += " WHERE namespace = ?"
            params = (namespace,)
        query += " ORDER BY id"
        with self.tx() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_firewall_egress_rule(self, rule_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM firewall_egress_rules WHERE id = ?", (rule_id,)).fetchone()
        return dict(row) if row else None

    def get_firewall_ingress_rule(self, rule_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM firewall_ingress_rules WHERE id = ?", (rule_id,)).fetchone()
        return dict(row) if row else None

    def delete_firewall_egress_rule(self, rule_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM firewall_egress_rules WHERE id = ?", (rule_id,)).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM firewall_egress_rules WHERE id = ?", (rule_id,))
        return dict(row)

    def delete_firewall_ingress_rule(self, rule_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM firewall_ingress_rules WHERE id = ?", (rule_id,)).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM firewall_ingress_rules WHERE id = ?", (rule_id,))
        return dict(row)

    def delete_firewall_egress_rules_for_lock(self, namespace: str, lock_resource_id: str) -> int:
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT id FROM firewall_egress_rules WHERE namespace = ? AND lock_resource_id = ?",
                (namespace, lock_resource_id),
            ).fetchall()
            conn.execute(
                "DELETE FROM firewall_egress_rules WHERE namespace = ? AND lock_resource_id = ?",
                (namespace, lock_resource_id),
            )
        return len(rows)

    def delete_firewall_ingress_rules_for_lock(self, namespace: str, lock_resource_id: str) -> int:
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT id FROM firewall_ingress_rules WHERE namespace = ? AND lock_resource_id = ?",
                (namespace, lock_resource_id),
            ).fetchall()
            conn.execute(
                "DELETE FROM firewall_ingress_rules WHERE namespace = ? AND lock_resource_id = ?",
                (namespace, lock_resource_id),
            )
        return len(rows)

    def effective_firewall_egress_entries(self) -> list[str]:
        entries: set[str] = set()
        for rule in self.list_firewall_egress_rules():
            if rule["mode"] == "allow_all":
                entries.update(_WILDCARD_IPV4_CIDRS)
            elif rule["target_ip"]:
                entries.add(rule["target_ip"])
        return sorted(entries)

    def effective_firewall_ingress_entries(self) -> list[str]:
        entries: set[str] = set()
        for rule in self.list_firewall_ingress_rules():
            if rule["mode"] == "allow_all":
                entries.update(_WILDCARD_IPV4_CIDRS)
            elif rule["target_ip"]:
                entries.add(rule["target_ip"])
        return sorted(entries)

    def create_firewall_access_rule(
        self,
        namespace: str,
        lock_resource_id: str,
        target_zone: str,
        source_cidr: str,
    ) -> dict[str, Any]:
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO firewall_access_rules(namespace, lock_resource_id, target_zone, source_cidr)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(namespace, lock_resource_id, target_zone, source_cidr)
                DO UPDATE SET updated_at = CURRENT_TIMESTAMP
                """,
                (namespace, lock_resource_id, target_zone, source_cidr),
            )
            row = conn.execute(
                """
                SELECT * FROM firewall_access_rules
                WHERE namespace = ? AND lock_resource_id = ? AND target_zone = ? AND source_cidr = ?
                """,
                (namespace, lock_resource_id, target_zone, source_cidr),
            ).fetchone()
        return dict(row) if row else {}

    def list_firewall_access_rules(self, namespace: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM firewall_access_rules"
        params: tuple[Any, ...] = ()
        if namespace is not None:
            query += " WHERE namespace = ?"
            params = (namespace,)
        query += " ORDER BY id"
        with self.tx() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def delete_firewall_access_rule(self, rule_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM firewall_access_rules WHERE id = ?", (rule_id,)).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM firewall_access_rules WHERE id = ?", (rule_id,))
        return dict(row)

    def delete_firewall_access_rules_for_lock(self, namespace: str, lock_resource_id: str) -> int:
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT id FROM firewall_access_rules WHERE namespace = ? AND lock_resource_id = ?",
                (namespace, lock_resource_id),
            ).fetchall()
            conn.execute(
                "DELETE FROM firewall_access_rules WHERE namespace = ? AND lock_resource_id = ?",
                (namespace, lock_resource_id),
            )
        return len(rows)

    def effective_firewall_access_entries(self) -> dict[str, list[str]]:
        entries_by_zone: dict[str, set[str]] = {"net": set(), "dev": set(), "stage": set(), "misc": set(), "live": set()}
        for rule in self.list_firewall_access_rules():
            entries_by_zone.setdefault(rule["target_zone"], set()).add(rule["source_cidr"])
        return {zone: sorted(entries) for zone, entries in entries_by_zone.items()}

    def create_endpoint_workaround_rule(
        self,
        namespace: str,
        lock_resource_id: str,
        kind: str,
        value: str,
        workaround_type: str,
        target_ip: str,
        apply_on: list[str],
        maps_to_service: str | None = None,
        manifest_id: str | None = None,
        constraint_id: str | None = None,
        notes: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self.tx() as conn:
            cur = conn.execute(
                """
                INSERT INTO endpoint_workaround_rules(
                    namespace, lock_resource_id, kind, value, workaround_type, target_ip,
                    apply_on_json, maps_to_service, manifest_id, constraint_id, notes, metadata_json
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    namespace,
                    lock_resource_id,
                    kind,
                    value,
                    workaround_type,
                    target_ip,
                    json.dumps(apply_on),
                    maps_to_service,
                    manifest_id,
                    constraint_id,
                    notes,
                    json.dumps(metadata or {}),
                ),
            )
            row = conn.execute("SELECT * FROM endpoint_workaround_rules WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        return self._decode_endpoint_workaround_rule(row) if row else {}

    def list_endpoint_workaround_rules(self, namespace: str | None = None, lock_resource_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM endpoint_workaround_rules"
        clauses: list[str] = []
        params: list[Any] = []
        if namespace is not None:
            clauses.append("namespace = ?")
            params.append(namespace)
        if lock_resource_id is not None:
            clauses.append("lock_resource_id = ?")
            params.append(lock_resource_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id"
        with self.tx() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [self._decode_endpoint_workaround_rule(row) for row in rows]

    def get_endpoint_workaround_rule(self, rule_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM endpoint_workaround_rules WHERE id = ?", (rule_id,)).fetchone()
        return self._decode_endpoint_workaround_rule(row) if row else None

    def delete_endpoint_workaround_rule(self, rule_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM endpoint_workaround_rules WHERE id = ?", (rule_id,)).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM endpoint_workaround_rules WHERE id = ?", (rule_id,))
        return self._decode_endpoint_workaround_rule(row)

    def delete_endpoint_workaround_rules_for_lock(self, namespace: str, lock_resource_id: str) -> int:
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT id FROM endpoint_workaround_rules WHERE namespace = ? AND lock_resource_id = ?",
                (namespace, lock_resource_id),
            ).fetchall()
            conn.execute(
                "DELETE FROM endpoint_workaround_rules WHERE namespace = ? AND lock_resource_id = ?",
                (namespace, lock_resource_id),
            )
        return len(rows)

    def _decode_endpoint_workaround_rule(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["apply_on"] = json.loads(item.pop("apply_on_json") or "[]")
        item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        return item

    def create_run(
        self,
        namespace: str,
        workflow_name: str,
        workflow_version: str,
        git_ref: str | None,
        vm_ids: list[str],
        declared_tests: list[str],
        selected_tests: list[str],
    ) -> dict[str, Any]:
        payload = json.dumps(vm_ids)
        declared_payload = json.dumps(sorted(set(declared_tests)))
        selected_payload = json.dumps(selected_tests)
        with self.tx() as conn:
            cur = conn.execute(
                """
                INSERT INTO runs(namespace, workflow_name, workflow_version, git_ref, status, vm_ids_json, declared_tests_json, selected_tests_json)
                VALUES(?, ?, ?, ?, 'running', ?, ?, ?)
                """,
                (namespace, workflow_name, workflow_version, git_ref, payload, declared_payload, selected_payload),
            )
            run_id = int(cur.lastrowid)
            conn.execute(
                "UPDATE runs SET started_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (run_id,),
            )
            self._reconcile_workflow_test_catalog(conn, namespace, workflow_name, workflow_version, run_id, sorted(set(declared_tests)))
        run = self.get_run(run_id)
        if run is None:
            raise KeyError(run_id)
        self.record_status_event(
            kind="run",
            level="info",
            status=run["status"],
            namespace=namespace,
            run_id=run_id,
            summary=f"run {run_id} started for {namespace}",
            details={
                "workflow_name": workflow_name,
                "workflow_version": workflow_version,
                "git_ref": git_ref,
                "vm_ids": vm_ids,
            },
        )
        return run

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return _run_row(row)

    def list_runs(self, namespace: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM runs"
        params: tuple[Any, ...] = ()
        if namespace:
            query += " WHERE namespace = ?"
            params = (namespace,)
        query += " ORDER BY id DESC"
        with self.tx() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_run_row(row) for row in rows]

    def update_run_estimate(
        self,
        run_id: int,
        estimated_disk_mb: int | None,
        estimated_ram_mb: int | None,
        estimated_duration_s: int | None,
        source: str,
        confidence: float | None,
        notes: str | None,
    ) -> dict[str, Any]:
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO run_estimates(run_id, estimated_disk_mb, estimated_ram_mb, estimated_duration_s, source, confidence, notes)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    estimated_disk_mb = excluded.estimated_disk_mb,
                    estimated_ram_mb = excluded.estimated_ram_mb,
                    estimated_duration_s = excluded.estimated_duration_s,
                    source = excluded.source,
                    confidence = excluded.confidence,
                    notes = excluded.notes,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (run_id, estimated_disk_mb, estimated_ram_mb, estimated_duration_s, source, confidence, notes),
            )
        return self.get_run_estimate(run_id)

    def get_run_estimate(self, run_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM run_estimates WHERE run_id = ?", (run_id,)).fetchone()
        return dict(row) if row else None

    def upsert_run_report(
        self,
        run_id: int,
        report_id: str,
        report_uri: str,
        schema_version: str,
        checksum_sha256: str | None,
        signature_uri: str | None,
        signer_id: str | None,
        validation_status: str,
        result_userdata: list[dict[str, Any]],
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO run_reports(
                    run_id, report_id, report_uri, schema_version, checksum_sha256,
                    signature_uri, signer_id, validation_status, result_userdata_json, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    report_id = excluded.report_id,
                    report_uri = excluded.report_uri,
                    schema_version = excluded.schema_version,
                    checksum_sha256 = excluded.checksum_sha256,
                    signature_uri = excluded.signature_uri,
                    signer_id = excluded.signer_id,
                    validation_status = excluded.validation_status,
                    result_userdata_json = excluded.result_userdata_json,
                    metadata_json = excluded.metadata_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    run_id,
                    report_id,
                    report_uri,
                    schema_version,
                    checksum_sha256,
                    signature_uri,
                    signer_id,
                    validation_status,
                    json.dumps(result_userdata),
                    json.dumps(metadata),
                ),
            )
            row = conn.execute("SELECT * FROM run_reports WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(run_id)
        run = self.get_run(run_id)
        self.record_status_event(
            kind="run_report",
            level="info" if validation_status == "verified" else "warning",
            status=validation_status,
            namespace=run["namespace"] if run else None,
            run_id=run_id,
            summary=f"report {report_id} recorded for run {run_id}",
            details={
                "report_id": report_id,
                "report_uri": report_uri,
                "schema_version": schema_version,
                "validation_status": validation_status,
                "result_userdata_count": len(result_userdata),
            },
        )
        return _run_report_row(row)

    def get_run_report(self, run_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM run_reports WHERE run_id = ?", (run_id,)).fetchone()
        return _run_report_row(row) if row else None

    def list_run_reports(
        self,
        namespace: str | None = None,
        workflow_name: str | None = None,
        workflow_version: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT rr.*
            FROM run_reports rr
            JOIN runs r ON r.id = rr.run_id
        """
        clauses: list[str] = []
        params: list[Any] = []
        if namespace is not None:
            clauses.append("r.namespace = ?")
            params.append(namespace)
        if workflow_name is not None:
            clauses.append("r.workflow_name = ?")
            params.append(workflow_name)
        if workflow_version is not None:
            clauses.append("r.workflow_version = ?")
            params.append(workflow_version)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY rr.run_id DESC"
        with self.tx() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_run_report_row(row) for row in rows]

    def testsuite_dependency_graph(
        self,
        namespace: str | None = None,
        testsuite_id: str | None = None,
        image_id: str | None = None,
        artifact_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        documents = self.list_testsuite_dependency_documents(
            namespace=namespace,
            testsuite_id=testsuite_id,
            image_id=image_id,
            artifact_id=artifact_id,
            status=status,
        )
        image_ids = sorted({doc_image_id for document in documents for doc_image_id in document["image_ids"]})
        images = [image for image in (self.get_image(doc_image_id) for doc_image_id in image_ids) if image is not None]
        reports_by_key: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        for document in documents:
            key = (document["namespace"], document["testsuite_id"], document["testsuite_version"])
            reports_by_key.setdefault(key, self.list_run_reports(
                namespace=document["namespace"],
                workflow_name=document["testsuite_id"],
                workflow_version=document["testsuite_version"],
            ))
        return {
            "documents": [
                {
                    **document,
                    "images": [image for image in images if image["image_id"] in document["image_ids"]],
                    "run_reports": reports_by_key.get((document["namespace"], document["testsuite_id"], document["testsuite_version"]), []),
                }
                for document in documents
            ],
            "images": images,
            "run_reports": [
                report
                for reports in reports_by_key.values()
                for report in reports
            ],
        }

    def start_run_stage(self, run_id: int, stage_id: str, name: str, order_index: int) -> dict[str, Any]:
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO run_stages(run_id, stage_id, name, order_index, status)
                VALUES(?, ?, ?, ?, 'running')
                ON CONFLICT(run_id, stage_id) DO UPDATE SET
                    name = excluded.name,
                    order_index = excluded.order_index,
                    status = 'running',
                    notes = NULL,
                    finished_at = NULL,
                    duration_s = NULL,
                    paused_duration_s = 0,
                    effective_duration_s = NULL,
                    started_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (run_id, stage_id, name, order_index),
            )
        stage = self.get_run_stage(run_id, stage_id)
        run = self.get_run(run_id)
        if stage is not None:
            self.record_status_event(
                kind="run_stage",
                level="info",
                status=stage["status"],
                namespace=run["namespace"] if run else None,
                run_id=run_id,
                stage_id=stage_id,
                summary=f"stage {stage_id} started for run {run_id}",
                details={"name": name, "order_index": order_index},
            )
        return stage

    def finish_run_stage(self, run_id: int, stage_id: str, status: str, notes: str | None) -> dict[str, Any]:
        stage = self.get_run_stage(run_id, stage_id)
        if stage is None:
            raise KeyError(stage_id)
        paused_duration = round(self._paused_seconds_between(run_id, stage["started_at"], None, stage_id=stage_id), 3)
        with self.tx() as conn:
            conn.execute(
                """
                UPDATE run_stages
                SET
                    status = ?,
                    notes = ?,
                    finished_at = CURRENT_TIMESTAMP,
                    duration_s = ROUND((julianday(CURRENT_TIMESTAMP) - julianday(started_at)) * 86400.0, 3),
                    paused_duration_s = ?,
                    effective_duration_s = ROUND(((julianday(CURRENT_TIMESTAMP) - julianday(started_at)) * 86400.0) - ?, 3),
                    updated_at = CURRENT_TIMESTAMP
                WHERE run_id = ? AND stage_id = ?
                """,
                (status, notes, paused_duration, paused_duration, run_id, stage_id),
            )
        stage = self.get_run_stage(run_id, stage_id)
        if stage is None:
            raise KeyError(stage_id)
        run = self.get_run(run_id)
        self.record_status_event(
            kind="run_stage",
            level=_status_level(status),
            status=status,
            namespace=run["namespace"] if run else None,
            run_id=run_id,
            stage_id=stage_id,
            summary=f"stage {stage_id} {status} for run {run_id}",
            details={"notes": notes},
        )
        return stage

    def get_run_stage(self, run_id: int, stage_id: str) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute(
                "SELECT * FROM run_stages WHERE run_id = ? AND stage_id = ?",
                (run_id, stage_id),
            ).fetchone()
        return dict(row) if row else None

    def list_run_stages(self, run_id: int) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT * FROM run_stages WHERE run_id = ? ORDER BY order_index, id",
                (run_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_active_run_stage(self, run_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute(
                """
                SELECT * FROM run_stages
                WHERE run_id = ? AND status = 'running' AND finished_at IS NULL
                ORDER BY order_index DESC, id DESC
                LIMIT 1
                """,
                (run_id,),
            ).fetchone()
        return dict(row) if row else None

    def create_run_event(
        self,
        run_id: int,
        event_type: str,
        message: str,
        stage_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = json.dumps(details or {})
        with self.tx() as conn:
            cur = conn.execute(
                """
                INSERT INTO run_events(run_id, stage_id, event_type, message, details_json)
                VALUES(?, ?, ?, ?, ?)
                """,
                (run_id, stage_id, event_type, message, payload),
            )
            row = conn.execute("SELECT * FROM run_events WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        event = _event_row(row)
        run = self.get_run(run_id)
        if event is not None:
            self.record_status_event(
                kind="run_event",
                level=_event_level(event_type),
                status=event_type,
                namespace=run["namespace"] if run else None,
                run_id=run_id,
                stage_id=stage_id,
                summary=message,
                details=event["details"],
            )
        return event

    def list_run_events(self, run_id: int) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT * FROM run_events WHERE run_id = ? ORDER BY id",
                (run_id,),
            ).fetchall()
        return [_event_row(row) for row in rows]

    def record_run_usage_sample(self, run_id: int, disk_bytes: int, ram_mb: int) -> dict[str, Any]:
        with self.tx() as conn:
            cur = conn.execute(
                """
                INSERT INTO run_usage_samples(run_id, disk_bytes, ram_mb)
                VALUES(?, ?, ?)
                """,
                (run_id, disk_bytes, ram_mb),
            )
            row = conn.execute(
                "SELECT * FROM run_usage_samples WHERE id = ?",
                (int(cur.lastrowid),),
            ).fetchone()
        return dict(row) if row else {}

    def get_run_usage(self, run_id: int) -> dict[str, Any]:
        with self.tx() as conn:
            latest = conn.execute(
                """
                SELECT disk_bytes, ram_mb, sampled_at
                FROM run_usage_samples
                WHERE run_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (run_id,),
            ).fetchone()
            summary = conn.execute(
                """
                SELECT
                    COALESCE(MAX(disk_bytes), 0) AS max_disk_bytes,
                    COALESCE(MAX(ram_mb), 0) AS max_ram_mb,
                    COUNT(*) AS sample_count
                FROM run_usage_samples
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
        return {
            "run_id": run_id,
            "current_disk_bytes": latest["disk_bytes"] if latest else 0,
            "current_ram_mb": latest["ram_mb"] if latest else 0,
            "max_disk_bytes": summary["max_disk_bytes"],
            "max_ram_mb": summary["max_ram_mb"],
            "sample_count": summary["sample_count"],
            "last_sample_at": latest["sampled_at"] if latest else None,
        }

    def finish_run(self, run_id: int, status: str, notes: str | None) -> dict[str, Any]:
        run = self.get_run(run_id)
        if run is None:
            raise KeyError(run_id)
        with self.tx() as conn:
            open_reasons = conn.execute(
                "SELECT DISTINCT reason FROM run_pause_periods WHERE run_id = ? AND finished_at IS NULL",
                (run_id,),
            ).fetchall()
        for row in open_reasons:
            self.finish_run_pause(run_id, row["reason"])
        run = self.get_run(run_id)
        if run is None:
            raise KeyError(run_id)
        paused_duration = round(self._paused_seconds_between(run_id, run["started_at"], None), 3)
        with self.tx() as conn:
            conn.execute(
                """
                UPDATE runs
                SET
                    status = ?,
                    notes = ?,
                    finished_at = CURRENT_TIMESTAMP,
                    duration_s = ROUND((julianday(CURRENT_TIMESTAMP) - julianday(started_at)) * 86400.0, 3),
                    paused_duration_s = ?,
                    effective_duration_s = ROUND(((julianday(CURRENT_TIMESTAMP) - julianday(started_at)) * 86400.0) - ?, 3),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (status, notes, paused_duration, paused_duration, run_id),
            )
        run = self.get_run(run_id)
        if run is None:
            raise KeyError(run_id)
        self.record_status_event(
            kind="run",
            level=_status_level(status),
            status=status,
            namespace=run["namespace"],
            run_id=run_id,
            summary=f"run {run_id} {status}",
            details={"notes": notes},
        )
        return run

    def active_runs(self) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                """
                SELECT * FROM runs
                WHERE status IN ('pending', 'running')
                ORDER BY id
                """
            ).fetchall()
        return [_run_row(row) for row in rows]

    def mark_run_learning_excluded(self, run_id: int, reason: str, bug_reference: str | None) -> dict[str, Any]:
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO run_learning_exclusions(run_id, reason, bug_reference)
                VALUES(?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    reason = excluded.reason,
                    bug_reference = excluded.bug_reference
                """,
                (run_id, reason, bug_reference),
            )
        return self.get_run_learning_exclusion(run_id)

    def get_run_learning_exclusion(self, run_id: int) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute(
                "SELECT * FROM run_learning_exclusions WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_run_summary(self, run_id: int) -> dict[str, Any]:
        run = self.get_run(run_id)
        if run is None:
            raise KeyError(run_id)
        return {
            "run": run,
            "estimate": self.get_run_estimate(run_id),
            "usage": self.get_run_usage(run_id),
            "stages": self.list_run_stages(run_id),
            "events": self.list_run_events(run_id),
            "pause_periods": self.get_run_pause_periods(run_id),
            "learning_exclusion": self.get_run_learning_exclusion(run_id),
        }

    def record_status_event(
        self,
        *,
        kind: str,
        summary: str,
        level: str = "info",
        status: str | None = None,
        namespace: str | None = None,
        vm_id: str | None = None,
        run_id: int | None = None,
        stage_id: str | None = None,
        operation_id: int | None = None,
        resource_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = json.dumps(details or {})
        with self.tx() as conn:
            cur = conn.execute(
                """
                INSERT INTO status_events(
                    kind, level, status, namespace, vm_id, run_id, stage_id, operation_id, resource_id, summary, details_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (kind, level, status, namespace, vm_id, run_id, stage_id, operation_id, resource_id, summary, payload),
            )
            row = conn.execute("SELECT * FROM status_events WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        event = _status_event_row(row)
        if event is not None and self.status_bus is not None:
            self.status_bus.publish(event)
        return event or {}

    def list_status_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT * FROM status_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_status_event_row(row) for row in rows]

    def start_run_pause(self, run_id: int, reason: str, stage_id: str | None = None) -> dict[str, Any]:
        with self.tx() as conn:
            existing = conn.execute(
                """
                SELECT * FROM run_pause_periods
                WHERE run_id = ? AND reason = ? AND finished_at IS NULL
                ORDER BY id DESC LIMIT 1
                """,
                (run_id, reason),
            ).fetchone()
            if existing:
                return dict(existing)
            cur = conn.execute(
                """
                INSERT INTO run_pause_periods(run_id, stage_id, reason)
                VALUES(?, ?, ?)
                """,
                (run_id, stage_id, reason),
            )
            row = conn.execute("SELECT * FROM run_pause_periods WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        return dict(row) if row else {}

    def finish_run_pause(self, run_id: int, reason: str) -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute(
                """
                SELECT * FROM run_pause_periods
                WHERE run_id = ? AND reason = ? AND finished_at IS NULL
                ORDER BY id DESC LIMIT 1
                """,
                (run_id, reason),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                """
                UPDATE run_pause_periods
                SET
                    finished_at = CURRENT_TIMESTAMP,
                    duration_s = ROUND((julianday(CURRENT_TIMESTAMP) - julianday(started_at)) * 86400.0, 3)
                WHERE id = ?
                """,
                (row["id"],),
            )
            updated = conn.execute("SELECT * FROM run_pause_periods WHERE id = ?", (row["id"],)).fetchone()
        return dict(updated) if updated else None

    def get_run_pause_periods(self, run_id: int) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT * FROM run_pause_periods WHERE run_id = ? ORDER BY id",
                (run_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def _paused_seconds_between(
        self,
        run_id: int,
        started_at: str | None,
        finished_at: str | None,
        stage_id: str | None = None,
    ) -> float:
        if not started_at:
            return 0.0
        with self.tx() as conn:
            rows = conn.execute(
                """
                SELECT * FROM run_pause_periods
                WHERE run_id = ?
                  AND reason = 'disk_full'
                  AND (stage_id = ? OR (? IS NULL))
                ORDER BY id
                """,
                (run_id, stage_id, stage_id),
            ).fetchall()
        return round(sum(_overlap_seconds(started_at, finished_at, row["started_at"], row["finished_at"]) for row in rows), 3)

    def _reconcile_workflow_test_catalog(
        self,
        conn: sqlite3.Connection,
        namespace: str,
        workflow_name: str,
        workflow_version: str,
        run_id: int,
        declared_tests: list[str],
    ) -> None:
        current = {
            row["test_id"]
            for row in conn.execute(
                """
                SELECT test_id FROM workflow_test_catalog
                WHERE namespace = ? AND workflow_name = ? AND workflow_version = ?
                """,
                (namespace, workflow_name, workflow_version),
            ).fetchall()
        }
        declared = set(declared_tests)
        for test_id in declared:
            conn.execute(
                """
                INSERT INTO workflow_test_catalog(namespace, workflow_name, workflow_version, test_id, last_seen_run_id, active)
                VALUES(?, ?, ?, ?, ?, 1)
                ON CONFLICT(namespace, workflow_name, workflow_version, test_id) DO UPDATE SET
                    last_seen_run_id = excluded.last_seen_run_id,
                    active = 1,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (namespace, workflow_name, workflow_version, test_id, run_id),
            )
        retired = current - declared
        if retired:
            placeholders = ", ".join("?" for _ in retired)
            params: list[Any] = [namespace, workflow_name, workflow_version, *retired]
            conn.execute(
                f"""
                UPDATE workflow_test_catalog
                SET active = 0, updated_at = CURRENT_TIMESTAMP
                WHERE namespace = ? AND workflow_name = ? AND workflow_version = ?
                  AND test_id IN ({placeholders})
                """,
                params,
            )
            history_run_ids = [
                row["id"]
                for row in conn.execute(
                    """
                    SELECT id FROM runs
                    WHERE namespace = ? AND workflow_name = ? AND workflow_version = ?
                    """,
                    (namespace, workflow_name, workflow_version),
                ).fetchall()
            ]
            if history_run_ids:
                run_placeholders = ", ".join("?" for _ in history_run_ids)
                delete_params: list[Any] = [*history_run_ids, *retired]
                retired_placeholders = ", ".join("?" for _ in retired)
                conn.execute(
                    f"DELETE FROM run_stages WHERE run_id IN ({run_placeholders}) AND stage_id IN ({retired_placeholders})",
                    delete_params,
                )
                conn.execute(
                    f"DELETE FROM run_events WHERE run_id IN ({run_placeholders}) AND stage_id IN ({retired_placeholders})",
                    delete_params,
                )


def _image_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    result["metadata"] = json.loads(result.pop("metadata_json", "{}"))
    return result


def _testsuite_dependency_document_row(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["image_ids"] = json.loads(result.pop("image_ids_json", "[]"))
    result["artifacts"] = json.loads(result.pop("artifacts_json", "[]"))
    result["metadata"] = json.loads(result.pop("metadata_json", "{}"))
    return result


def _run_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    result["vm_ids"] = json.loads(result.pop("vm_ids_json"))
    result["declared_tests"] = json.loads(result.pop("declared_tests_json", "[]"))
    result["selected_tests"] = json.loads(result.pop("selected_tests_json", "[]"))
    return result


def _run_report_row(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["result_userdata"] = json.loads(result.pop("result_userdata_json", "[]"))
    result["metadata"] = json.loads(result.pop("metadata_json", "{}"))
    return result


def _event_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    result["details"] = json.loads(result.pop("details_json"))
    return result


def _operation_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    result["details"] = json.loads(result.pop("details_json", "{}"))
    return result


def _status_event_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    result["details"] = json.loads(result.pop("details_json", "{}"))
    return result


def _decode_repository_self_registration_key(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        raise KeyError("repository self-registration key not found")
    result = dict(row)
    result["source_cidrs"] = json.loads(result.pop("source_cidrs_json", "[]"))
    return result


def _trash_item_row(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        raise KeyError("trash item not found")
    result = dict(row)
    result["metadata"] = json.loads(result.pop("metadata_json", "{}"))
    return result


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def _overlap_seconds(
    left_start: str,
    left_end: str | None,
    right_start: str,
    right_end: str | None,
) -> float:
    start = max(_parse_ts(left_start), _parse_ts(right_start))
    end = min(_parse_ts(left_end), _parse_ts(right_end))
    seconds = (end - start).total_seconds()
    return seconds if seconds > 0 else 0.0


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)


def _status_level(status: str, rejection_category: str | None = None, rejection_reason: str | None = None) -> str:
    if status in {"failed"}:
        return "error"
    if status in {"rejected"} or rejection_category or rejection_reason:
        return "warning"
    return "info"


def _event_level(event_type: str) -> str:
    if event_type in {"warning", "api_reject", "disk_full"}:
        return "warning"
    if event_type in {"vm_crash"}:
        return "error"
    return "info"


def _operation_summary(action: str, status: str, vm_id: str | None, rejection_reason: str | None) -> str:
    target = f" for {vm_id}" if vm_id else ""
    summary = f"{action}{target} {status}"
    if rejection_reason:
        return f"{summary}: {rejection_reason}"
    return summary
