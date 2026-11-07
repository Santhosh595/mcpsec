"""Hardcoded-secret detection in MCP configs.

Scans every string value under each server's ``env`` / ``args`` / ``headers``
(or any key) for recognizable credential shapes and long opaque tokens
under credential-sounding key names. Env references (``${VAR}``, ``$VAR``)
and placeholders (``your-api-key-here``) are exempt — a config that points
at the environment is the correct pattern.
"""

from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from ..rules import secret_in_value
from .configs import find_config_files, load_config, iter_servers

# Where secrets hide in MCP server definitions.
_SECRET_CONTAINERS = ("env", "args", "headers", "config")


def _walk_values(node, trail: str = ""):
    """Yield (dotted_path, string_value) for every string in a structure."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_values(v, f"{trail}.{k}" if trail else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_values(v, f"{trail}[{i}]")
    elif isinstance(node, str):
        yield trail, node


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in find_config_files(root):
        data, err = load_config(path)
        if err is not None:
            findings.append(err)
            continue
        for server, cfg in iter_servers(data):
            for dotted, value in _walk_values(cfg):
                # Only care about containers where credentials live. Other
                # strings (command paths, descriptions) are noisy.
                if not any(
                    dotted == c or dotted.startswith(c + ".") or dotted.startswith(c + "[")
                    for c in _SECRET_CONTAINERS
                ):
                    continue
                last_key = dotted.rsplit(".", 1)[-1].split("[", 1)[0]
                hit = secret_in_value(last_key, value)
                if hit is None:
                    continue
                rule_id, detail = hit
                findings.append(Finding(
                    rule=f"server_{server}_{rule_id}",
                    severity="high",
                    file=str(path),
                    message=f"Hardcoded credential in server '{server}' ({dotted}).",
                    detail=detail,
                    category="secrets",
                ))
    return findings
