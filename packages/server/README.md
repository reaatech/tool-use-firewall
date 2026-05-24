# @reaatech/tool-use-firewall-server

[![npm version](https://img.shields.io/npm/v/@reaatech/tool-use-firewall-server.svg)](https://www.npmjs.com/package/@reaatech/tool-use-firewall-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/reaatech/tool-use-firewall/ci.yml?branch=main&label=CI)](https://github.com/reaatech/tool-use-firewall/actions/workflows/ci.yml)

> **Status:** Pre-1.0 — APIs may change in minor versions. Pin to a specific version in production.

MCP proxy server, CLI entry point, and interceptor pipeline for tool-use-firewall. Spawns one or more upstream MCP servers as child processes, intercepts JSON-RPC `tools/call` messages (including those inside batch requests), runs them through the policy pipeline, and forwards allowed requests. This is the package most users install — it ships the `tool-use-firewall` binary and pulls in the rest of the `@reaatech/tool-use-firewall-*` packages.

## Installation

```bash
npm install @reaatech/tool-use-firewall-server
# or
pnpm add @reaatech/tool-use-firewall-server
```

## Feature Overview

- **MCP proxy server** — Full JSON-RPC 2.0 proxy over stdio or HTTP, with batch-request support
- **Interceptor pipeline** — Pluggable middleware chain: rate limiter → cost tracker → secret scanner → argument validator → schema validator → policy engine → read-only check → anomaly detector → approval workflow → audit logger (each stage registered only when enabled in the policy)
- **Multi-upstream routing** — Spawn several upstream MCP servers and route tools to them by glob pattern
- **Policy hot-reload** — Picks up edits to the policy file without a restart
- **CLI entry point** — `tool-use-firewall` command with `--config`, `--upstream`, `--upstream-args`, `--approval-port`, `--http-port`, `--dry-run`, `--init`, and `--validate` options
- **Optional Prometheus metrics** — `/metrics` endpoint for requests, blocks, approvals, and latency
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

# Scaffold a starter policy from the upstream's tools/list
tool-use-firewall --init --upstream node ./my-mcp-server.js

# Validate a policy (schema + ReDoS) — exits non-zero on failure, good for CI
tool-use-firewall --validate ./policy.yaml
```

### CLI flags

| Flag | Description |
| ---- | ----------- |
| `--config, -c <path>` | Policy YAML file (required to run the proxy) |
| `--upstream, -u <command>` | Command to spawn the upstream MCP server (required to run the proxy) |
| `--upstream-args <string>` | Space-separated upstream args for scripted environments |
| `--approval-port <port>` | Port for the approval HTTP API |
| `--http-port <port>` | Port for the HTTP transport |
| `--dry-run` | Shadow mode: log what would be blocked without enforcing |
| `--init` | Scaffold a `policy.generated.yaml` from the upstream's `tools/list` |
| `--validate <path>` | Validate a policy and exit (no proxy) |
| `--help, -h` / `--version, -v` | Show help / version |

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
