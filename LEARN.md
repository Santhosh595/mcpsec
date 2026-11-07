# Learn — mcpsec

## What it is

Security scanner for MCP (Model Context Protocol) server configs. Reads a config, checks three things: embedded secrets, over-permissive tools, insecure transports. Python + pytest, CI green.

**Read this first, then go file-by-file in the repo.**

## 5-minute quickstart

```bash
git clone https://github.com/Santhosh595/mcpsec && cd mcpsec
pip install -r requirements.txt
python -m mcpsec --help        # check README for exact CLI
pytest -q
```

## Concepts — the "why" behind each file

| If you see this in the code | What it means | Viva answer |
|---|---|---|
| MCP config JSON parsing | Servers declare tools/resources/transports | The config IS the attack surface |
| Regex for secrets (`sk-`, `AKIA`, `xoxb-`...) | Secret detection | Keys in config = leaked keys. Pattern = fast, false positives possible |
| Tool allow-list vs allow-all | Least privilege | A server with 40 tools where 3 are used is 37 extra risks |
| Transport: `stdio` vs `http`/`sse` | How the agent talks to the server | HTTP exposes network surface; stdio is local-only |
| JSON schema validation | Structure checking | Malformed config shouldn't crash the scanner |
| pytest fixtures with sample configs | Test design | Good config + bad config per check |

## Common pitfalls

1. **Secrets in repo history** — a scanner flagging secrets is ironic if the repo leaks its own. Check git history.
2. **Allow-all by default** — if your scanner's example config allows all tools, that's the first fix.
3. **Trusting tool descriptions** — a tool's `description` field is data the model reads. Poisoned description = prompt injection.
4. **HTTP without auth** — an MCP HTTP server with no token is an open door.
5. **Regex-only secrets** — entropy + pattern combined beats pattern alone; say the trade-off.

## Hands-on, in this order

1. Run the scanner on the repo's sample config. List every finding.
2. Add a fake secret (`sk-test123`) to a config copy — does it flag? Which pattern?
3. Flip a tool list from explicit to `"*"` — what changes?
4. Switch a transport from `stdio` to `http` — what new warnings?
5. Read the MCP security spec: https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
6. Compare with https://github.com/trufflesecurity/trufflehog (run it on a test dir — see what a mature scanner does)

## Viva questions (with the trap)

1. **"What is MCP?"** Answer: protocol for AI agents to call tools/resources; transports stdio (local) and HTTP/SSE (network).
2. **"Why allow-list tools?"** Answer: least privilege; each tool is an attack surface.
3. **"How does a poisoned tool description attack?"** Answer: model reads descriptions as instructions; malicious text steers behavior (indirect prompt injection).
4. **"Where do secrets leak?"** Answer: config files, `.env` committed to git, logs.
5. **"stdio vs HTTP?"** Answer: stdio = process-local, no network; HTTP = remote, needs auth + TLS.

## 3 things to say if stuck

- "The scanner checks config, not live servers — static analysis, regex + schema."
- "Least privilege is the core principle — allow-list, never allow-all."
- "Tool descriptions are untrusted input; that's the injection vector."

Good luck. MCP security is a 2026 hot topic — this repo is your interview edge.
