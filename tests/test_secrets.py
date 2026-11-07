"""Secrets check: hardcoded credentials in env/args/headers."""

from __future__ import annotations

from pathlib import Path

from mcpsec.checks.secrets import scan as scan_secrets
from mcpsec.rules import secret_in_value

from conftest import install


class TestSecretInValue:
    def test_recognizable_shapes_fire(self):
        for name, val in [
            ("OPENAI_API_KEY", "sk-proj-abcdefghijklmnop1234567890"),
            ("GITHUB_TOKEN", "ghp_1234567890abcdefghijklmnopqrstuv"),
            ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
            ("SOME_JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3FeqG (jwt)"),
        ]:
            assert secret_in_value(name, val) is not None, (name, val)

    def test_long_opaque_under_secret_name(self):
        assert secret_in_value("CUSTOM_TOKEN", "aB3dEfGhIjKlMnOpQrStUvWx1") is not None

    def test_env_refs_exempt(self):
        assert secret_in_value("OPENAI_API_KEY", "${OPENAI_API_KEY}") is None
        assert secret_in_value("GITHUB_TOKEN", "$GITHUB_TOKEN") is None

    def test_placeholders_exempt(self):
        assert secret_in_value("API_KEY", "your-api-key-here") is None
        assert secret_in_value("PASSWORD", "changeme") is None

    def test_public_values_no_flag(self):
        assert secret_in_value("LOG_LEVEL", "info") is None
        assert secret_in_value("BASE_URL", "https://api.example.com/v1") is None

    def test_short_secret_name_no_flag(self):
        # Under a secret-sounding key but too short to be a real credential.
        assert secret_in_value("TOKEN", "abc123") is None


class TestScanSecrets:
    def test_danger_config_flagged(self, config_root):
        install(config_root, "mcp_config.json", "mcp_config_danger.json")
        findings = scan_secrets(config_root)
        assert findings
        assert all(f.severity == "high" for f in findings)
        rules = {f.rule for f in findings}
        assert any("sk-" in r or "hardcoded" in r for r in rules)

    def test_clean_config_clean(self, config_root):
        install(config_root, "mcp_config.json", "mcp_config_clean.json")
        assert scan_secrets(config_root) == []

    def test_yaml_config_flagged(self, config_root):
        install(config_root, "mcp.yml", "mcp_config_yaml.yml")
        findings = scan_secrets(config_root)
        assert findings

    def test_malformed_is_error(self, config_root):
        install(config_root, "mcp.json", "mcp_config_malformed.json")
        findings = scan_secrets(config_root)
        assert findings and findings[0].severity == "error"
        assert findings[0].rule == "config_unreadable"
