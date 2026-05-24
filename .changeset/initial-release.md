---
"@reaatech/tool-use-firewall-core": minor
"@reaatech/tool-use-firewall-config": minor
"@reaatech/tool-use-firewall-policies": minor
"@reaatech/tool-use-firewall-approvals": minor
"@reaatech/tool-use-firewall-audit": minor
"@reaatech/tool-use-firewall-server": minor
---

Initial public release of tool-use-firewall — a policy enforcement layer that sits between AI agents and MCP servers. Intercepts every `tools/call` to apply rate limiting, argument validation (SQL/shell injection, custom regex), cost budgets, read-only enforcement, anomaly detection, secret scanning, and human-in-the-loop approval chains, with structured audit logging and redaction.

This release also adds:

- **JSON-RPC batch support** — batched requests (top-level arrays) are now intercepted per-element instead of being rejected.
- **`--validate <policy.yaml>`** — a CLI subcommand (and `validatePolicyFile` API in `@reaatech/tool-use-firewall-config`) that checks a policy against the schema and verifies every regex is ReDoS-safe, exiting non-zero on failure. Suitable as a CI gate.
- HTTP-transport error responses are now returned in the response body instead of being written to stdout.
- **Audit file output now rotates.** `file` and `sidecar` outputs share one rotating local-file writer (`rotation: daily | size`, `max_files`, `max_size_bytes`, `compress`) writing newline-delimited JSON events. `sidecar` outputs can additionally forward events over HTTP to a log aggregator/SIEM (`endpoint` + optional `api_key_env` Bearer auth) — previously the `endpoint`/`api_key_env` fields were ignored and no rotation was performed. Delivery is best-effort and non-blocking. A `sidecar` requires an `endpoint` and/or a `path`; a `file` requires a `path`. A new `RotatingFileSink` is exported for standalone use.
