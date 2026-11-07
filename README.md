# MCP Security Audit CLI

**mcpsec** is a static scanner for MCP (Multi-Tool Configuration Protocol) configurations. It detects hardcoded secrets, over-broad tool permissions, unauthenticated admin tools, and permissive transport settings. Designed for CI/CD pipelines and local audits, it provides severity-ranked output, exit codes, and JSON reports.

## Features

- **Hardcoded Secrets Detection**: Identifies API keys, tokens, and credentials in MCP configs (OpenAI, GitHub, AWS, Anthropic, Slack, JWT, PEM shapes + long opaque tokens under secret-sounding names). Env references (`${VAR}`, `$VAR`) and placeholders are exempt.
- **Permission Analysis**: Flags tools with excessive or unsafe permissions (wildcard `tools: ["*"]`, broad `permissions` lists, `allow_all: true`).
- **Admin Tool Safety**: Detects admin/destructive-sounding tools (`delete_*`, `exec_*`, `shutdown_*`) exposed without a read-only flag.
- **Transport Security**: Checks for cleartext (`http://`/`ws://`) URLs, wildcard binds (`0.0.0.0`), and shell-wrapped commands.

## Installation

```bash
# Clone the repository
git clone https://github.com/Santhosh595/mcpsec.git
cd mcpsec

# Install dependencies (stdlib-only)
python3 -m pip install -e .
```

## Usage

```bash
# Scan a directory for MCP configs
mcpsec scan /path/to/configs

# Scan a single config file
mcpsec scan ~/.config/mcp.json

# Output results in JSON format
mcpsec scan /path/to/configs --json

# Filter by severity (low, medium, high, critical)
mcpsec scan /path/to/configs --min-severity high
```

## Exit Codes

Exit code is the worst severity seen in the full set (severity filtering only affects the report):

- `0`: No findings, or only low/info noise (non-blocking for CI)
- `2`: Medium-severity findings
- `3`: High-severity findings
- `4`: Critical findings / `5`: a check errored or config unreadable
- `2` (usage): path not found / bad arguments

## Project layout

```
mcpsec/
├── mcpsec/
│   ├── cli.py            # argparse entry point
│   ├── findings.py       # Finding dataclass, severity ranks, JSON output
│   ├── rules.py          # secret shapes + placeholder/env-ref exemptions
│   ├── yaml_lite.py      # minimal YAML subset parser (stdlib only)
│   └── checks/
│       ├── configs.py    # config discovery, parsing, server iteration
│       ├── secrets.py    # hardcoded-credential detection
│       ├── permissions.py # wildcard grants, admin tools, allow_all
│       └── transport.py  # cleartext, wildcard binds, shell wrapping
├── tests/
│   ├── fixtures/         # danger / clean / yaml / malformed configs
│   ├── test_secrets.py
│   ├── test_permissions.py
│   ├── test_transport.py
│   └── test_cli.py
├── pyproject.toml
└── LICENSE               # MIT
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
