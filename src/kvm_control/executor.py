from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

from .config import AppConfig
from .db import Registry


class ExecutorClient:
    def __init__(self, config: AppConfig, registry: Registry):
        self.config = config
        self.registry = registry

    def run(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        request_id = payload.get("operation_id", "adhoc")
        request_path = self.config.storage.requests_dir / f"{request_id}-{action}.json"
        request_path.write_text(json.dumps({"action": action, "payload": payload}, indent=2))
        command = shlex.split(self.config.executor_bin) + ["--request-file", str(request_path)]
        if self.config.dry_run:
            command.append("--dry-run")
        if self.config.source_path:
            command += ["--config", self.config.source_path]
        details = {
            "action": action,
            "request_file": str(request_path),
            "dry_run": self.config.dry_run,
            "command": command,
        }
        self.registry.record_status_event(
            kind="executor",
            level="info",
            status="running",
            namespace=payload.get("namespace"),
            vm_id=payload.get("vm_id"),
            run_id=payload.get("run_id"),
            stage_id=payload.get("stage_id"),
            operation_id=_coerce_int(payload.get("operation_id")),
            summary=f"executor {action} started",
            details=details,
        )
        env = dict(os.environ)
        src_path = str(Path(__file__).resolve().parents[2])
        env["PYTHONPATH"] = src_path if not env.get("PYTHONPATH") else f"{src_path}:{env['PYTHONPATH']}"
        completed = subprocess.run(command, capture_output=True, text=True, check=False, env=env)
        if completed.returncode != 0:
            error = completed.stderr.strip() or completed.stdout.strip() or f"{action} failed"
            self.registry.record_status_event(
                kind="executor",
                level="error",
                status="failed",
                namespace=payload.get("namespace"),
                vm_id=payload.get("vm_id"),
                run_id=payload.get("run_id"),
                stage_id=payload.get("stage_id"),
                operation_id=_coerce_int(payload.get("operation_id")),
                summary=f"executor {action} failed",
                details={**details, "error": error},
            )
            raise RuntimeError(error)
        result = json.loads(completed.stdout or "{}")
        planned_commands = result.get("planned_commands") or []
        self.registry.record_status_event(
            kind="executor",
            level="info",
            status="completed",
            namespace=payload.get("namespace"),
            vm_id=payload.get("vm_id"),
            run_id=payload.get("run_id"),
            stage_id=payload.get("stage_id"),
            operation_id=_coerce_int(payload.get("operation_id")),
            summary=f"executor {action} completed",
            details={
                **details,
                "planned_command_count": len(planned_commands),
                "first_command": planned_commands[0] if planned_commands else None,
                "result_keys": sorted(result.keys()),
            },
        )
        return result


def _coerce_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
