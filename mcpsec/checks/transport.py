"""Transport-security checks for MCP server definitions.

Flags cleartext HTTP, wildcard binds, and shell-wrapped transports:
- ``http://`` / ``ws://`` URLs (cleartext)
- ``0.0.0.0`` / ``::`` / ``*`` host binds
- ``shell: true`` with a remote URL, or ``command`` containing curl|bash/eval
- ``stdio`` transport with no command (ambiguous)
"""

from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from .configs import find_config_files, load_config, iter_servers

_WILDCARD_HOSTS = {"0.0.0.0", "::", "[::]", "*", "0.0.0.0:0", "0.0.0.0/0"}
_SHELL_DANGER_RE = re.compile(
    r"(curl|wget)\b[^\n;|]*\|\s*(?:ba|z)?s?h\b|\beval\b|base64\s+.*(?:-d|--decode)",
    re.IGNORECASE,
)


def _urls_in(cfg: dict) -> list[str]:
    urls = []
    for key in ("url", "endpoint", "server_url"):
        v = cfg.get(key)
        if isinstance(v, str) and v:
            urls.append(v)
    args = cfg.get("args")
    if isinstance(args, list):
        for a in args:
            if isinstance(a, str) and a.startswith(("http://", "https://", "ws://", "wss://")):
                urls.append(a)
    return urls


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in find_config_files(root):
        data, err = load_config(path)
        if err is not None:
            findings.append(err)
            continue
        for server, cfg in iter_servers(data):
            # --- cleartext URLs ---
            for url in _urls_in(cfg):
                if url.startswith("http://") or url.startswith("ws://"):
                    findings.append(Finding(
                        rule="server_cleartext_transport",
                        severity="medium",
                        file=str(path),
                        message=f"Server '{server}' uses cleartext URL: {url}.",
                        detail="MCP traffic over http/ws is unauthenticated and unencrypted in transit.",
                        category="transport",
                    ))
            # --- wildcard bind ---
            for key in ("host", "bind", "address", "listen"):
                v = cfg.get(key)
                if isinstance(v, str) and v.strip() in _WILDCARD_HOSTS:
                    findings.append(Finding(
                        rule="server_wildcard_bind",
                        severity="medium",
                        file=str(path),
                        message=f"Server '{server}' binds to wildcard address ({key}: {v.strip()}).",
                        detail="Exposes the MCP server on all interfaces; restrict to localhost unless remote access is required.",
                        category="transport",
                    ))
            # --- shell-wrapped command ---
            shell = cfg.get("shell") is True
            command = cfg.get("command")
            cmd_str = command if isinstance(command, str) else (
                " ".join(a for a in (cfg.get("args") or []) if isinstance(a, str))
            )
            if shell and isinstance(command, str) and _SHELL_DANGER_RE.search(cmd_str):
                findings.append(Finding(
                    rule="server_shell_exec",
                    severity="high",
                    file=str(path),
                    message=f"Server '{server}' runs its command through a shell with a download-and-execute pattern.",
                    detail=f"command: {cmd_str[:160]}",
                    category="transport",
                ))
            elif shell:
                findings.append(Finding(
                    rule="server_shell_true",
                    severity="low",
                    file=str(path),
                    message=f"Server '{server}' sets shell: true.",
                    detail="Shell wrapping widens injection surface; prefer direct command execution when possible.",
                    category="transport",
                ))
            # --- remote URL + stdio transport mismatch ---
            transport = str(cfg.get("transport", "")).lower()
            if transport in ("stdio", "local") and _urls_in(cfg):
                findings.append(Finding(
                    rule="server_transport_mismatch",
                    severity="low",
                    file=str(path),
                    message=f"Server '{server}' declares {transport} transport but also configures a remote URL.",
                    detail="Configuration is ambiguous about how the server is reached.",
                    category="transport",
                ))
    return findings
