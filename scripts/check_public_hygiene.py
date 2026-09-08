#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


SKIP_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "run",
    "var",
}

SKIP_FILES = {"HANDOFF.md"}

TEXT_SUFFIXES = {
    "",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".text",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class SensitivePattern:
    name: str
    pattern: re.Pattern[str]


PATTERNS = [
    SensitivePattern("private 10.7.x address", re.compile(r"\b10\." + r"7\.\d{1,3}\.\d{1,3}(?::\d+)?\b")),
    SensitivePattern("private KVM host name", re.compile(r"\b" + "kvm" + r"0\b")),
    SensitivePattern("local developer path", re.compile(r"/home/" + r"sven\b")),
    SensitivePattern("known private token fragment", re.compile("TR" + "m49")),
    SensitivePattern("admin token file reference", re.compile(r"\badmin" + r"-token\b")),
    SensitivePattern("repo auth token literal", re.compile(r"repo\.auth\.token:")),
    SensitivePattern(
        "literal bearer token",
        re.compile(
            r"Authorization:\s*Bearer\s+"
            r"(?!<token>|<repository-token>|<self-registration-key>|admin-secret\b|not-a-real-token\b|inbound-token\b)"
            r"[A-Za-z0-9._~+/=-]{16,}"
        ),
    ),
]


def _is_text_path(path: Path) -> bool:
    return path.suffix in TEXT_SUFFIXES


def _iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if relative.name in SKIP_FILES:
            continue
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if _is_text_path(path):
            yield path, relative


def check_public_hygiene(root: Path) -> list[str]:
    findings: list[str] = []
    for path, relative in _iter_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for sensitive in PATTERNS:
                if sensitive.pattern.search(line):
                    findings.append(f"{relative}:{line_number}: {sensitive.name}: {line.strip()}")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a public vm-forgeyard tree for private deployment leakage.")
    parser.add_argument("root", nargs="?", default=".", help="Public repository root to scan")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    findings = check_public_hygiene(root)
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        print(f"public hygiene check failed with {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print("public hygiene check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
