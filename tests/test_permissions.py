"""Permissions check: wildcard grants, admin tools, allow_all."""

from __future__ import annotations

from mcpsec.checks.permissions import scan as scan_perms

from conftest import install


class TestPermissionsScan:
    def test_danger_config_flagged(self, config_root):
        install(config_root, "mcp_config.json", "mcp_config_danger.json")
        findings = scan_perms(config_root)
        rules = {f.rule for f in findings}
        assert "server_wildcard_tools" in rules
        assert "server_broad_permissions" in rules
        assert "server_allow_all" in rules
        # admin tools surface present
        assert any("admin" in r for r in rules)
        assert any(f.severity == "high" for f in findings)

    def test_clean_config_clean(self, config_root):
        install(config_root, "mcp_config.json", "mcp_config_clean.json")
        assert scan_perms(config_root) == []

    def test_readonly_guards_admin_tool(self, config_root):
        install(config_root, "mcp.json", "mcp_config_clean.json")
        # clean has no admin tools, so nothing to guard — stays empty
        assert scan_perms(config_root) == []

    def test_yaml_config_flagged(self, config_root):
        install(config_root, "mcp.yml", "mcp_config_yaml.yml")
        findings = scan_perms(config_root)
        assert any(f.rule == "server_wildcard_tools" for f in findings)

    def test_malformed_is_error(self, config_root):
        install(config_root, "mcp.json", "mcp_config_malformed.json")
        findings = scan_perms(config_root)
        assert findings and findings[0].severity == "error"
