"""Discovery + shared walkers for MCP configuration files.

MCP server configs live in JSON (``.mcp.json``, ``claude_desktop_config.json``,
``mcp.json``) and YAML/TOML variants. A config is interesting if it maps
server names to server definitions — under ``mcpServers`` (Claude Desktop /
Cursor / most clients) or as a bare ``{"server-name": {...}}`` mapping.

This module finds candidate files, parses them, and yields the server
definition dicts to the individual check modules.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from ..findings import Finding

# Filenames that are almost always MCP config, matched exactly.
_EXACT_NAMES = {
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
    "claude_code_config.json",
    "mcp_config.json",
    "servers.json",
}

# Directory names / filename fragments that suggest MCP content.
_NAME_HINTS = ("mcp", "claude", "cursor")

_SKIP_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules", ".mypy_cache",
    ".pytest_cache", "dist", "build", ".tox", ".eggs",
}

# Files to skip by suffix (binary / generated).
_SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip",
                  ".pyc", ".woff", ".woff2", ".bin", ".exe", ".db", ".sqlite"}


def find_config_files(root: Path) -> list[Path]:
    """Return candidate MCP config files under *root*."""
    out: list[Path] = []
    if root.is_file():
        return [root]
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.suffix.lower() in _SKIP_SUFFIXES:
            continue
        if path.name in _EXACT_NAMES or any(h in path.name.lower() for h in _NAME_HINTS):
            out.append(path)
    return out


def load_config(path: Path) -> tuple[dict | list | None, Finding | None]:
    """Parse a config file. Returns (data, error_finding)."""
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        return None, Finding(
            rule="config_unreadable",
            severity="error",
            file=str(path),
            message=f"Could not read {path.name}.",
            detail=repr(exc),
            category="configs",
        )
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            return json.loads(text), None
        except Exception as exc:
            return None, Finding(
                rule="config_unreadable",
                severity="error",
                file=str(path),
                message=f"Could not parse {path.name} as JSON.",
                detail=repr(exc),
                category="configs",
            )
    if suffix in (".yml", ".yaml"):
        return _parse_yaml(text, path)
    if suffix == ".toml":
        try:
            return tomllib.loads(text), None
        except Exception as exc:
            return None, Finding(
                rule="config_unreadable",
                severity="error",
                file=str(path),
                message=f"Could not parse {path.name} as TOML.",
                detail=repr(exc),
                category="configs",
            )
    return None, None  # unsupported type — silently ignored


# ---------------------------------------------------------------------------
# Minimal YAML subset parser (stdlib only): enough for MCP server maps
# (nested mappings and lists of scalars). Anything more complex is reported
# as unreadable rather than silently misparsed.
# ---------------------------------------------------------------------------

def _parse_yaml(text: str, path: Path):
    try:
        from ..yaml_lite import parse as yaml_parse
    except Exception as exc:  # pragma: no cover
        return None, Finding(
            rule="config_unreadable",
            severity="error",
            file=str(path),
            message="YAML parser unavailable.",
            detail=repr(exc),
            category="configs",
        )
    try:
        return yaml_parse(text), None
    except Exception as exc:
        return None, Finding(
            rule="config_unreadable",
            severity="error",
            file=str(path),
            message=f"Could not parse {path.name} as YAML.",
            detail=repr(exc),
            category="configs",
        )


def iter_servers(data: dict | list | None) -> list[tuple[str, dict]]:
    """Yield (server_name, server_dict) from a parsed config.

    Handles the standard ``{"mcpServers": {...}}`` wrapper and a bare
    top-level mapping of server name -> definition.
    """
    if not isinstance(data, dict):
        return []
    servers: list[tuple[str, dict]] = []
    candidates: dict = {}
    if isinstance(data.get("mcpServers"), dict):
        candidates = data["mcpServers"]
    elif isinstance(data.get("servers"), dict):
        candidates = data["servers"]
    else:
        # Bare mapping: only treat as servers if every value is a dict
        # that looks like a server definition (has command/url/args/env).
        if all(isinstance(v, dict) for v in data.values()) and data:
            keys = set(data.keys())
            if keys & {"command", "url", "args", "env", "transport"}:
                candidates = data
            else:
                # Ambiguous bare mapping: values are dicts but none has a
                # server-defining key at top level. Still treat nested
                # dicts that look like servers within one level.
                for name, val in data.items():
                    if isinstance(val, dict) and (
                        {"command", "url", "args", "env", "transport"} & set(val.keys())
                    ):
                        servers.append((name, val))
    for name, val in candidates.items():
        if isinstance(val, dict):
            servers.append((str(name), val))
    return servers


def scan(root: Path) -> list[Finding]:
    """Shared discovery: parse every candidate file, emit unreadable errors."""
    findings: list[Finding] = []
    for path in find_config_files(root):
        data, err = load_config(path)
        if err is not None:
            findings.append(err)
            continue
        # Non-server data is fine — the check modules decide.
    return findings
