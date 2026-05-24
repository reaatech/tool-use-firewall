# @reaatech/tool-use-firewall-audit

[![npm version](https://img.shields.io/npm/v/@reaatech/tool-use-firewall-audit.svg)](https://www.npmjs.com/package/@reaatech/tool-use-firewall-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/reaatech/tool-use-firewall/ci.yml?branch=main&label=CI)](https://github.com/reaatech/tool-use-firewall/actions/workflows/ci.yml)

> **Status:** Pre-1.0 — APIs may change in minor versions. Pin to a specific version in production.

Audit logging with automatic sensitive data redaction for tool-use-firewall. Records every policy decision with configurable verbosity levels, file output, and custom redaction patterns.

## Installation

```bash
npm install @reaatech/tool-use-firewall-audit
# or
pnpm add @reaatech/tool-use-firewall-audit
```

## Feature Overview

- **Decision logging** — Records `ALLOW`, `BLOCK`, and `APPROVAL_REQUIRED` decisions with full context
- **Configurable levels** — `none` (disabled), `summary` (minimal fields), `full` (complete request/response)
- **Sensitive data redaction** — API keys, bearer tokens, emails, and custom patterns automatically redacted
- **Rotating local files** — `file` and `sidecar` outputs share one rotating writer: rotate `daily` or by `size` (`max_size_bytes`), retain `max_files`, and optionally `compress` rotated files to `.gz` (stdout is forbidden — it corrupts MCP streams)
- **Sidecar / SIEM output** — Additionally forward each event over HTTP to a log aggregator (optional Bearer auth); best-effort delivery that never blocks or breaks the proxy
- **Silent mode** — Suppresses output during testing via `NODE_ENV=test` or explicit `silent` option

## Quick Start

```typescript
import { AuditLogger, type AuditEvent } from "@reaatech/tool-use-firewall-audit";

const logger = new AuditLogger({
  config: {
    level: "full",
    output: [
      // Rotating local file: rotate daily, keep 14 files, gzip the old ones.
      { type: "file", path: "/var/log/audit.log", rotation: "daily", max_files: 14, compress: true },
      // Forward to a SIEM/log aggregator over HTTP (optional Bearer auth), and
      // also keep a rotating local copy. `path` is optional for sidecars.
      {
        type: "sidecar",
        endpoint: "https://siem.example/ingest",
        api_key_env: "SIEM_TOKEN",
        path: "/var/log/audit-sidecar.log",
        rotation: "size",
        max_size_bytes: 10485760,
      },
    ],
    redaction: { enabled: true },
  },
});

await logger.log({
  type: "REQUEST_ALLOWED",
  sessionId: "sess_123",
  toolName: "db_query",
  decision: "ALLOW",
  latency: 42,
});
```

## Exports

| Export | Description |
|--------|-------------|
| `AuditLogger` | Main logger class: `log(event)` with configurable levels and redaction; `close()` flushes file sinks on shutdown |
| `AuditEvent` | `{ type, sessionId, toolName?, arguments?, response?, decision, blockedBy?, approvalId?, latency, metadata? }` |
| `AuditDecision` | Union: `'ALLOW'` \| `'BLOCK'` \| `'APPROVAL_REQUIRED'` |
| `AuditLoggerOptions` | `{ config?: AuditConfig, silent?: boolean }` |
| `RotatingFileSink` / `FileSinkOptions` | Standalone rotating newline-delimited JSON file writer (daily/size rotation, retention, gzip) |

## License

[MIT](LICENSE)
