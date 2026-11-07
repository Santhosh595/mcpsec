"""Transport check: cleartext, wildcard binds, shell wrapping."""

from __future__ import annotations

from mcpsec.checks.transport import scan as scan_transport

from conftest import install


class TestTransportScan:
    def test_danger_config_flagged(self, config_root):
        install(config_root, "mcp_config.json", "mcp_config_danger.json")
        findings = scan_transport(config_root)
        rules = {f.rule for f in findings}
        assert "server_cleartext_transport" in rules
        assert "server_wildcard_bind" in rules
        assert "server_shell_exec" in rules or "server_shell_true" in rules
        assert "server_transport_mismatch" in rules

    def test_clean_config_clean(self, config_root):
        install(config_root, "mcp_config.json", "mcp_config_clean.json")
        assert scan_transport(config_root) == []

    def test_yaml_config_flagged(self, config_root):
        install(config_root, "mcp.yml", "mcp_config_yaml.yml")
        findings = scan_transport(config_root)
        rules = {f.rule for f in findings}
        assert "server_cleartext_transport" in rules
        assert "server_wildcard_bind" in rules
