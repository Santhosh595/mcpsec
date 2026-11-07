"""Command-line entry point for mcpsec.

Static, read-only audit of MCP server configurations: hardcoded secrets,
wildcard tool permissions, admin-tool exposure, and transport security.
Stdlib only. Exit code is the worst severity seen (see findings.py):
 0 = clean (or info/low only), 2 = medium, 3 = high, 5 = a check errored.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checks import (
    scan_secrets,
    scan_permissions,
    scan_transport,
)
from .findings import SEVERITY_RANK, by_severity, exit_code, to_json

_SCANNERS = (
    ("Hardcoded secrets", scan_secrets),
    ("Tool permissions / admin tools", scan_permissions),
    ("Transport security", scan_transport),
)


def _render_table(findings) -> str:
    """ASCII severity-ranked report. Compact, greppable, CI-friendly."""
    if not findings:
        return "  No findings - clean.\n"
    lines = [
        f"  {'SEV':<8} {'CATEGORY':<18} FILE",
        f"  {'---':<8} {'--------':<18} ----",
    ]
    for f in by_severity(findings):
        lines.append(
            f"  {f.severity:<8} {f.category:<18} {f.file}"
        )
        lines.append(f"           {f.message}")
        if f.detail:
            lines.append(f"           {f.detail}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcpsec",
        description=(
            "Static security audit for MCP server configurations: hardcoded "
            "secrets, wildcard tool permissions, unauthenticated admin "
            "tools, and permissive transport settings."
        ),
        epilog=(
            "Examples:\n"
            "  mcpsec scan .                      # audit the current directory\n"
            "  mcpsec scan ~/.config/mcp.json     # audit one config file\n"
            "  mcpsec scan . --json               # machine-readable output\n"
            "  mcpsec scan . --min-severity high  # only high+ findings"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "command",
        choices=["scan"],
        help="Scan MCP server configurations for security issues.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="config file or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of the ASCII table",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mcpsec {__version__}",
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help=(
            "minimum severity to report (default: low). "
            "Findings below this threshold are ignored. "
            "Exit code is still driven by the worst severity seen."
        ),
    )
    args = parser.parse_args(argv)

    root = Path(args.path).expanduser()
    if not root.exists():
        print(f"mcpsec: not found: {root}", file=sys.stderr)
        return 2

    findings: list = []
    for label, scanner in _SCANNERS:
        try:
            findings.extend(scanner(root))
        except Exception as exc:  # a scanner must never take the CLI down
            from .findings import Finding
            findings.append(
                Finding(
                    rule=f"{scanner.__module__}_crashed",
                    severity="error",
                    file=str(root),
                    message=f"Scanner '{label}' crashed.",
                    detail=repr(exc),
                    category="internal",
                )
            )

    # Filter findings based on --min-severity
    min_rank = SEVERITY_RANK[args.min_severity]
    filtered_findings = [f for f in findings if SEVERITY_RANK[f.severity] >= min_rank]

    if args.json:
        print(to_json(filtered_findings))
    else:
        print(_render_table(filtered_findings))

    return exit_code(findings)


if __name__ == "__main__":
    sys.exit(main())
