#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_CONTROL_URL = "http://127.0.0.1:8000"
DEFAULT_KEY_FILE = Path.home() / ".kvm-control-self-register.key"


def first_secret_line(path: Path) -> str | None:
    if not path.exists():
        return None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            return line
    return None


def repository_root(start: Path) -> Path:
    current = start.resolve()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return current


def ensure_gitignored(root: Path) -> None:
    ignore_path = root / ".gitignore"
    lines = ignore_path.read_text(encoding="utf-8").splitlines() if ignore_path.exists() else []
    if "repo.auth.token" in {line.strip() for line in lines}:
        return
    with ignore_path.open("a", encoding="utf-8") as handle:
        if lines and lines[-1]:
            handle.write("\n")
        handle.write("repo.auth.token\n")


def register(control_url: str, key: str, repository: str, agent_session_id: str | None) -> dict[str, Any]:
    payload = {"repository": repository, "agent_session_id": agent_session_id}
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{control_url.rstrip('/')}/v1/auth/repository-self-registration",
        data=data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"registration failed with HTTP {exc.code}: {detail}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Self-register this repository for kvm-control MCP/API access.")
    parser.add_argument("--control-url", default=DEFAULT_CONTROL_URL)
    parser.add_argument("--key-file", default=str(DEFAULT_KEY_FILE))
    parser.add_argument("--repository", help="Repository name without the git. prefix; defaults to the git root directory name.")
    parser.add_argument("--root", default=".", help="Repository path; defaults to the current directory.")
    parser.add_argument("--agent-session-id", default=os.environ.get("CODEX_SESSION_ID"))
    args = parser.parse_args()

    root = repository_root(Path(args.root))
    token_path = root / "repo.auth.token"
    if token_path.exists():
        raise RuntimeError(f"{token_path} already exists; refusing to overwrite an existing repository token")

    key = first_secret_line(Path(args.key_file).expanduser())
    if not key:
        raise RuntimeError(f"repository self-registration key is missing from {args.key_file}")

    repository = args.repository or root.name
    if repository.startswith("git."):
        raise RuntimeError("repository must be provided without the git. prefix")

    result = register(args.control_url, key, repository, args.agent_session_id)
    token = result["token"]

    ensure_gitignored(root)
    token_path.write_text(
        "# kvm-control MCP/API bearer token for this repository.\n"
        f"{token}\n",
        encoding="utf-8",
    )
    token_path.chmod(0o600)
    print(json.dumps({"ok": True, "repository": repository, "token_id": result["token_id"], "token_file": str(token_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
