"""Tool-permission and admin-tool surface analysis.

Flags:
- wildcard tool grants (``tools: ["*"]``, ``tools: "*"``, ``permissions: ["*"]``)
- admin/root tool names exposed without any `readonly`/`read_only` flag
- `allowAll` / `allow_all` / `dangerous: true` flags on a server
"""

from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from .configs import find_config_files, load_config, iter_servers

_WILDCARD_KEYS = ("tools", "permissions", "tool_permissions", "allowed_tools")
_ADMIN_TOOL_RE = __import__("re").compile(
    r"\b(admin|root|dangerous|delete|destroy|drop|shutdown|reboot|exec|shell)\b",
    __import__("re").IGNORECASE,
)


def _is_wildcard(value) -> bool:
    if value == "*":
        return True
    if isinstance(value, list) and "*" in value:
        return True
    return False


def _collect_tool_names(cfg: dict) -> list[tuple[str, str]]:
    """Yield (tool_name, source_key) for tools listed in a server config."""
    out = []
    for key in ("tools", "allowed_tools", "tool_permissions", "permissions"):
        val = cfg.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    out.append((item, key))
                elif isinstance(item, dict) and isinstance(item.get("name"), str):
                    out.append((item["name"], key))
        elif isinstance(val, str):
            out.append((val, key))
    # tools.<name> mapping form
    tools = cfg.get("tools")
    if isinstance(tools, dict):
        for name in tools:
            out.append((str(name), "tools"))
    return out


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in find_config_files(root):
        data, err = load_config(path)
        if err is not None:
            findings.append(err)
            continue
        for server, cfg in iter_servers(data):
            # --- wildcard grants ---
            for key in _WILDCARD_KEYS + ("permissions",):
                if key in cfg and _is_wildcard(cfg[key]):
                    findings.append(Finding(
                        rule="server_wildcard_tools",
                        severity="high",
                        file=str(path),
                        message=f"Server '{server}' grants wildcard tool access ({key}: \"*\").",
                        detail="Any tool the server exposes is callable, including write/delete operations.",
                        category="permissions",
                    ))
            # --- explicit wildcard scopes inside a permissions list ---
            perms = cfg.get("permissions")
            if isinstance(perms, list) and any(
                isinstance(p, str) and p in ("*", "admin", "all", "*:*") for p in perms
            ):
                findings.append(Finding(
                    rule="server_broad_permissions",
                    severity="medium",
                    file=str(path),
                    message=f"Server '{server}' has broad permissions: {perms}.",
                    detail="Non-scoped permission entries grant more than the server needs.",
                    category="permissions",
                ))
            # --- admin-tool names without read-only guard ---
            readonly = bool(cfg.get("readonly") or cfg.get("read_only"))
            for name, _src in _collect_tool_names(cfg):
                if _ADMIN_TOOL_RE.search(name) and not readonly:
                    findings.append(Finding(
                        rule="server_unguar" + "ded_admin_tool",
                        severity="medium",
                        file=str(path),
                        message=f"Server '{server}' exposes admin-like tool '{name}' without a read-only flag.",
                        detail="Admin/destructive-sounding tools should require explicit confirmation or a read-only mode.",
                        category="permissions",
                    ))
                    break  # one admin surface finding per server is enough
            # --- allow-all flags ---
            for flag in ("allow_all", "allowAll", "dangerous", "unrestricted"):
                if cfg.get(flag) is True:
                    findings.append(Finding(
                        rule="server_allow_all",
                        severity="high",
                        file=str(path),
                        message=f"Server '{server}' sets {flag}: true.",
                        detail="All tools/actions permitted without restriction.",
                        category="permissions",
                    ))
    return findings
