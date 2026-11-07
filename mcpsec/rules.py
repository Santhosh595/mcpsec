"""Danger patterns for MCP server configurations.

Everything here is heuristic: a match on a config value does not prove
malice, it flags a configuration worth a human look. The goal is to
catch the common MCP misconfigurations — hardcoded secrets baked into
``env``/``args``, wildcard tool permissions, unauthenticated admin
servers, and cleartext transport.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Secrets: keys whose names imply a credential, and values that look like
# real tokens / API keys.
# ---------------------------------------------------------------------------

_SECRET_NAME_RE = re.compile(
    r"(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd|"
    r"credential|private[_-]?key|client[_-]?secret|session[_-]?key|"
    r"refresh[_-]?token|bearer|token|key)",
    re.IGNORECASE,
)

# Recognizable token shapes (high confidence).
_TOKEN_SHAPE_RES = [
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github_finegrained_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    ("aws_secret_key", re.compile(r"\b[A-Za-z0-9/+=]{40}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack_webhook", re.compile(r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+\b")),
    ("jwt_token", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    )),
    ("pem_private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----", re.DOTALL)),
    ("generic_bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}\b", re.IGNORECASE)),
]

# Placeholders / obvious non-secrets that must never flag.
_PLACEHOLDER_VALUES = frozenset({
    "", "changeme", "change-me", "example", "placeholder", "your-api-key",
    "your-api-key-here", "<api-key>", "none", "null", "dummy", "test",
    "xxx", "xxxx", "todo", "redacted", "env", "secure", "hidden",
    "your-token-here", "your-secret-here", "your-key-here", "your-password",
})

_ENV_REF_RE = re.compile(r"^(?:\$\{[^}]+}|\$[A-Z_][A-Z0-9_]*|%[A-Z_][A-Z0-9_]*%)$")
_URL_REF_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)


def _is_placeholder(value: str) -> bool:
    return value.strip().lower() in _PLACEHOLDER_VALUES or bool(_ENV_REF_RE.match(value.strip()))


def secret_in_value(name: str, value: str) -> tuple[str, str] | None:
    """Return (rule_id, detail) if (name, value) looks like a hardcoded secret.

    Two independent signals, either alone is enough:
    1. the value has a recognizable token shape (OPENAI/GITHUB/AWS/JWT/PEM…)
    2. the key name implies a credential *and* the value is a long opaque
       string that doesn't look like a placeholder or an env reference.
    """
    if not isinstance(value, str) or _is_placeholder(value):
        return None
    stripped = value.strip()
    for rule_id, pat in _TOKEN_SHAPE_RES:
        if pat.search(stripped):
            return (f"hardcoded_{rule_id}", f"Value under '{name}' matches the {rule_id} shape.")
    # Generic long-opaque under a secret-sounding key. 20+ chars, mixed
    # alphanumerics, no spaces => suspicious; ordinary URLs / paths excluded.
    if _SECRET_NAME_RE.search(name):
        if (
            len(stripped) >= 20
            and not _URL_REF_RE.search(stripped)
            and not re.search(r"\s", stripped)
            and re.search(r"[A-Za-z]", stripped)
            and re.search(r"[0-9]", stripped)
            and not stripped.startswith(("/", "./", "~/", "-", "--"))
        ):
            return (
                "hardcoded_secret",
                f"Value under '{name}' looks like a hardcoded credential "
                f"({len(stripped)} chars, opaque, mixed alphanumeric).",
            )
    # PEM blocks anywhere in a value.
    if "-----BEGIN" in stripped and "PRIVATE KEY-----" in stripped:
        return ("hardcoded_pem_private_key", f"Value under '{name}' contains a PEM private key block.")
    return None
