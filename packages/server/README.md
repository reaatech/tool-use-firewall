# @reaatech/tool-use-firewall-server

[![npm version](https://img.shields.io/npm/v/@reaatech/tool-use-firewall-server.svg)](https://www.npmjs.com/package/@reaatech/tool-use-firewall-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/reaatech/tool-use-firewall/ci.yml?branch=main&label=CI)](https://github.com/reaatech/tool-use-firewall/actions/workflows/ci.yml)

> **Status:** Pre-1.0 — APIs may change in minor versions. Pin to a specific version in production.

MCP proxy server, CLI entry point, and interceptor pipeline for tool-use-firewall. Spawns an upstream MCP server as a child process, intercepts JSON-RPC `tools/call` messages, runs them through the policy pipeline, and forwards allowed requests.

## Installation

```bash
npm install @reaatech/tool-use-firewall-server
# or
pnpm add @reaatech/tool-use-firewall-server
```

## Feature Overview

- **MCP proxy server** — Full JSON-RPC 2.0 proxy that spawns upstream MCP via stdio
- **Interceptor pipeline** — Pluggable middleware chain: rate limiter → cost tracker → argument validator → policy engine → read-only check → approval workflow → audit logger
- **CLI entry point** — `tool-use-firewall` command with `--config`, `--upstream`, `--upstream-args`, and `--approval-port` options
- **Unified exports** — Re-exports all public APIs from `core`, `config`, `policies`, `approvals`, and `audit` for a single import
- **Graceful shutdown** — SIGTERM/SIGINT handling with upstream process lifecycle management
- **Message size limits** — 10MB max message size, 128-char max session ID, 10000 max pending responses

## Quick Start

```bash
# CLI usage
tool-use-firewall \
  --config ./policies/default.yaml \
  --upstream node ./my-mcp-server.js

# With approval API
export APPROVAL_API_TOKEN="$(openssl rand -hex 32)"
tool-use-firewall \
  --config ./policies/default.yaml \
  --upstream node ./my-mcp-server.js \
  --approval-port 8080
```

```typescript
import { MCPProxyServer } from "@reaatech/tool-use-firewall-server";

const server = new MCPProxyServer({
  policyPath: "./policies/default.yaml",
  upstreamCommand: "node",
  upstreamArgs: ["./my-mcp-server.js"],
});

await server.start();

// Graceful shutdown
process.on("SIGINT", async () => {
  await server.stop();
  process.exit(0);
});
```

## Exports

| Export | Source | Description |
|--------|--------|-------------|
| `MCPProxyServer` | server | Main proxy server class |
| `InterceptorPipeline` | server | Middleware orchestration pipeline |
| `FirewallError`, etc. | core | All error classes |
| `Logger` | core | Structured logger |
| `redact`, `safeRegExp`, `globToRegex` | core | Utilities |
| `loadPolicyConfig`, `PolicyConfig`, `RuleCondition`, `ExceptionCondition` | config | Policy loading and types |
| `PolicyEngine`, `RateLimiter`, etc. | policies | Policy components |
| `ApprovalWorkflow`, `createApprovalApi` | approvals | Approval system |
| `AuditLogger` | audit | Audit logging |

## License

[MIT](LICENSE)
