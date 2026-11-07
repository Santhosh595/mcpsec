"""CLI contract: exit codes, --json, --min-severity, scan subcommand."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from conftest import install

HERE = Path(__file__).resolve().parent


def _run_cli(args):
    env = dict(os.environ)
    src = str(HERE.parent)
    env["PYTHONPATH"] = src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    proc = subprocess.run(
        [sys.executable, "-m", "mcpsec", "scan", *args],
        capture_output=True,
        text=True,
        env=env,
    )
    return proc


class TestCli:
    def test_clean_exit_zero(self, config_root):
        install(config_root, "mcp.json", "mcp_config_clean.json")
        proc = _run_cli([str(config_root), "--json", "--min-severity", "low"])
        assert proc.returncode == 0, proc.stdout + proc.stderr
        data = json.loads(proc.stdout)
        assert data["count"] == 0

    def test_danger_exit_nonzero(self, config_root):
        install(config_root, "mcp.json", "mcp_config_danger.json")
        proc = _run_cli([str(config_root), "--json"])
        assert proc.returncode >= 2, proc.stdout
        data = json.loads(proc.stdout)
        assert data["count"] > 0
        assert data["summary"]["high"] >= 1

    def test_min_severity_filters(self, config_root):
        install(config_root, "mcp.json", "mcp_config_danger.json")
        proc_high = _run_cli([str(config_root), "--json", "--min-severity", "high"])
        proc_low = _run_cli([str(config_root), "--json", "--min-severity", "low"])
        data_high = json.loads(proc_high.stdout)
        data_low = json.loads(proc_low.stdout)
        assert data_high["count"] <= data_low["count"]
        assert all(f["severity"] == "high" for f in data_high["findings"])

    def test_exit_code_driven_by_worst_not_filter(self, config_root):
        # Severity filter only affects the report; exit code is still based
        # on the worst severity seen in the full set.
        install(config_root, "mcp.json", "mcp_config_danger.json")
        proc = _run_cli([str(config_root), "--min-severity", "critical"])
        assert proc.returncode >= 2

    def test_missing_path_errors(self):
        proc = _run_cli(["/nonexistent/path/xyz"])
        assert proc.returncode == 2

    def test_malformed_is_error_exit(self, config_root):
        install(config_root, "mcp.json", "mcp_config_malformed.json")
        proc = _run_cli([str(config_root), "--json"])
        assert proc.returncode == 5  # error rank
