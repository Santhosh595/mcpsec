# MCP Security Audit CLI

## Overview

**mcpsec** is a static scanner for MCP (Multi-Tool Configuration Protocol) configurations. It detects hardcoded secrets, over-broad tool permissions, unauthenticated admin tools, and permissive transport settings. Designed for CI/CD pipelines and local audits, it provides severity-ranked output, exit codes, and JSON reports.

## Features

- **Hardcoded Secrets Detection**: Identifies API keys, tokens, and credentials in MCP configs.
- **Permission Analysis**: Flags tools with excessive or unsafe permissions.
- **Transport Security**: Checks for unencrypted or weakly encrypted communication settings.
- **Admin Tool Safety**: Detects unauthenticated or overly permissive admin tool configurations.

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

# Output results in JSON format
mcpsec scan /path/to/configs --json

# Filter by severity (low, medium, high)
mmcpsec scan /path/to/configs --min-severity high
```

## Exit Codes

- `0`: No issues found.
- `1`: Low-severity issues detected.
- `2`: Medium-severity issues detected.
- `3`: High-severity issues detected.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
