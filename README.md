# 🔥 tool-use-firewall

Policy enforcement layer between AI agents and MCP servers.

[![CI](https://github.com/reaatech/tool-use-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/reaatech/tool-use-firewall/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)](https://github.com/reaatech/tool-use-firewall)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

`tool-use-firewall` is a security-critical proxy that sits between AI agents and [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers. It intercepts tool calls, enforces security policies, and provides human-in-the-loop approvals for dangerous operations.

### Key Features

- **Policy Engine** — Block, allow, or require approval based on tool name, arguments, and custom rules
- **Rate Limiting** — Global, per-tool, and per-session token buckets with bounded memory
- **Argument Validation** — Regex, shell-safety, and SQL-injection checks
- **Read-Only Mode** — Block write operations with break-glass bypass tokens
- **Cost Tracking** — Enforce session budgets for expensive tool calls
- **Audit Logging** — Redacted, structured logs to stderr or files (never stdout)
- **Approval Workflows** — Multi-level human approval chains with timeout handling
- **Safe Regex** — ReDoS protection for all user-configured patterns

## Quick Start

### Prerequisites

- Node.js ≥ 20
- pnpm ≥ 9

### Installation

```bash
pnpm install tool-use-firewall
```

### Usage

```bash
npx tool-use-firewall \
  --config ./policies/default.yaml \
  --upstream node ./your-mcp-server.js
```

With approval API enabled (auth is required — the API binds to `127.0.0.1` by
default):

```bash
export APPROVAL_API_TOKEN="$(openssl rand -hex 32)"
npx tool-use-firewall \
  --config ./policies/default.yaml \
  --upstream node ./your-mcp-server.js \
  --approval-port 8080
```

Add this to the policy YAML to enable the approval API:

```yaml
approval_api:
  token_env: APPROVAL_API_TOKEN
  bind_host: 127.0.0.1   # optional, defaults to 127.0.0.1
```

If `--approval-port` is set without a corresponding `approval_api.token_env`,
the proxy refuses to start rather than expose an unauthenticated API.

Pass arguments to your upstream MCP server after a literal `--`:

```bash
npx tool-use-firewall \
  --config ./policies/default.yaml \
  --upstream node -- ./your-mcp-server.js --port 9000
```

### Policy Configuration

Create a `policies/default.yaml`:

```yaml
version: '1.0'
settings:
  default_action: block
  read_only: false

rate_limits:
  global:
    requests_per_minute: 120
    burst_capacity: 20
  per_tool:
    database_execute:
      requests_per_minute: 10
      burst_capacity: 3

validation:
  rules:
    - id: no_shell_injection
      type: shell_safe
      tools: ['execute_command']
      argument: 'cmd'

rules:
  - id: block_drop_table
    type: block
    tools: ['database_execute']
    conditions:
      - argument: query
        pattern: 'DROP\\s+TABLE'
        flags: 'i'
    priority: 100
    description: 'Prevent DROP TABLE operations'

approvals:
  default_timeout_ms: 300000
  max_pending_approvals: 1000
  required_for:
    - tools: ['file_write', 'database_execute']
      approvers: ['security-team']
      min_approvals: 1
```

## Architecture

```
AI Agent → tool-use-firewall → Upstream MCP Server
              │
              ├─ Policy Engine (block/allow/approve)
              ├─ Rate Limiter (token buckets)
              ├─ Argument Validator (regex/SQL/shell)
              ├─ Read-Only Check
              ├─ Cost Tracker
              └─ Audit Logger (redacted)
```

The proxy uses stdio JSON-RPC to communicate with both the agent and the upstream MCP server. The approval API runs as a separate HTTP server.

## Security

See [SECURITY.md](SECURITY.md) for our security policy and vulnerability reporting process.

- **Bounded Storage** — All stateful components implement TTL/capacity-based eviction. Unbounded `Map` usage is treated as a vulnerability.
- **ReDoS Protection** — All regex patterns from config are validated before compilation.
- **Timing-Safe Comparisons** — Bearer tokens and bypass tokens use `crypto.timingSafeEqual`.
- **Sensitive Data Redaction** — Audit logs and API responses automatically redact passwords, API keys, emails, and bearer tokens.
- **Input Validation** — JSON-RPC messages, approval API bodies, and CLI arguments are all schema-validated.

## Development

```bash
# Install dependencies
pnpm install

# Build
pnpm build

# Run tests
pnpm test

# Run tests with coverage
pnpm test:coverage

# Lint
pnpm lint

# Type check
pnpm typecheck
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — Technical design and resource management patterns
- [DEV_PLAN.md](DEV_PLAN.md) — Roadmap and current phase
- [CONTRIBUTING.md](CONTRIBUTING.md) — Contribution guidelines and commit conventions
- [AGENTS.md](AGENTS.md) — Guidelines for AI agents working on this codebase

## License

MIT © [reaatech](https://github.com/reaatech)
