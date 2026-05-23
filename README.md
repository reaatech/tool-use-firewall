# tool-use-firewall

[![CI](https://github.com/reaatech/tool-use-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/reaatech/tool-use-firewall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue)](https://www.typescriptlang.org/)
[![pnpm](https://img.shields.io/badge/pnpm-10.22-orange)](https://pnpm.io/)
[![Vitest](https://img.shields.io/badge/test-vitest-green)](https://vitest.dev/)

> **Policy enforcement layer between AI agents and MCP servers** — intercept, validate, and secure every tool call before it reaches the upstream.

---

## Why tool-use-firewall?

AI agents are powerful, but they can also be dangerous. A single errant `DROP TABLE` or `rm -rf /` can destroy hours of work. This project sits between your AI agent and your MCP servers, acting as a **security guard** for every tool invocation — rate limiting, argument validation, cost tracking, read-only enforcement, and human-in-the-loop approval chains.

If you're deploying AI agents that talk to databases, filesystems, or any MCP server, this is your safety net.

---

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   AI Agent      │────▶│   tool-use-firewall  │────▶│  Upstream MCP   │
│   (Claude,      │     │   (Interceptor       │     │  Server         │
│   GPT, etc.)    │◀────│    Pipeline)          │◀────│  (Database,     │
└─────────────────┘     └──────────────────────┘     │   Filesystem,   │
                                                      │   Network, etc.) │
                                                      └─────────────────┘
```

The interceptor pipeline enforces policies in strict order:

```
Request → Rate Limiter → Cost Tracker → Argument Validator → Policy Engine → Read-Only Check → Approval Workflow → Audit Logger → Upstream
```

Data flow details and state management: [ARCHITECTURE.md](./ARCHITECTURE.md)

---

## Features

### Policy Engine
- **Rule evaluation** — Block, allow, or require approval by tool name, argument values, and custom conditions
- **Priority-based matching** — Rules evaluated in priority order; first match wins
- **Glob pattern matching** — `db.*` matches `db.execute`, `db.query`, etc.

### Rate Limiting
- **Token bucket algorithm** — Global, per-tool, and per-session limits
- **Bounded memory** — TTL-based eviction prevents memory exhaustion
- **Burst capacity** — Configurable burst allowance for traffic spikes

### Argument Validation
- **SQL injection detection** — Pattern matching against known dangerous patterns
- **Shell injection prevention** — Blocks metacharacters like `;`, `&&`, `` ` ``, `$()`
- **Custom regex patterns** — User-defined validation per tool/argument
- **ReDoS protection** — All regex patterns validated for safety before compilation

### Read-Only Mode
- **Global toggle** — Block all write operations when enabled
- **Per-tool exceptions** — Allow-list for read-only safe tools
- **Break-glass tokens** — Timing-safe bypass for emergencies

### Cost Tracking
- **Per-session budgets** — Enforce cost limits for expensive tool calls
- **Tool-level pricing** — Assign costs per invocation
- **Configurable action** — Block or warn when budget exceeded

### Approval Workflows
- **Multi-level chains** — Require approval from multiple groups
- **Timeout handling** — Expired approvals automatically denied
- **Multiple interfaces** — HTTP API, CLI prompts, webhook notifications
- **Rate-limited API** — Per-IP token bucket on the approval HTTP endpoint

### Audit Logging
- **Structured JSON** — Every decision recorded with full context
- **Sensitive data redaction** — API keys, tokens, emails automatically redacted
- **Level control** — `none`, `summary`, or `full` verbosity
- **File output** — Optional file logging with rotation support

---

## Installation

### Local development

```bash
git clone https://github.com/reaatech/tool-use-firewall.git
cd tool-use-firewall
pnpm install
pnpm build
pnpm test
```

### Usage

```bash
pnpm dev -- --config ./policies/default.yaml --upstream node ./examples/basic-proxy/upstream-server.js
```

Or with the approval API:

```bash
export APPROVAL_API_TOKEN="$(openssl rand -hex 32)"
pnpm dev -- \
  --config ./policies/default.yaml \
  --upstream node ./examples/basic-proxy/upstream-server.js \
  --approval-port 8080
```

---

## Packages

| Package | Description | Dependencies |
| ------- | ----------- | ------------ |
| [`core`](./packages/core) | Types, error classes, logger, redactor, safe-regex | (none) |
| [`config`](./packages/config) | Policy YAML schema (Zod) and loader | `core`, `yaml`, `zod` |
| [`policies`](./packages/policies) | Policy engine, rate limiter, cost tracker, validators | `core`, `config` |
| [`approvals`](./packages/approvals) | Approval workflow, HTTP API, CLI/webhook approvers | `core`, `config`, `policies`, `express`, `zod` |
| [`audit`](./packages/audit) | Audit logging with redaction | `core`, `config` |
| [`server`](./packages/server) | MCP proxy server, CLI, interceptor pipeline | `core`, `config`, `policies`, `approvals`, `audit` |

---

## Policy Configuration

See [`policies/`](./policies/) for example YAML files:

| Policy | Description |
| ------ | ----------- |
| [`default.yaml`](./policies/default.yaml) | Sensible defaults — rate limits, SQL safety, shell safety |
| [`database-safe.yaml`](./policies/database-safe.yaml) | Database-focused policy with strict SQL validation |
| [`read-only.yaml`](./policies/read-only.yaml) | Read-only mode with bypass token support |

---

## Documentation

| Document | Content |
| -------- | ------- |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System design, pipeline flow, resource management |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | Development setup, conventional commits, PR process |
| [AGENTS.md](./AGENTS.md) | Coding conventions and guidance for AI agents |
| [SECURITY.md](./SECURITY.md) | Security policy and vulnerability reporting |

---

## Tech Stack

| Layer | Technology |
| ----- | ---------- |
| Language | TypeScript 5.8 (strict mode) |
| Runtime | Node.js ≥ 20 |
| Package manager | pnpm 10 (workspaces) |
| Build | tsup + Turborepo |
| Lint & format | Biome |
| Testing | Vitest |
| Validation | Zod |
| Schema | YAML |

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full workflow:

1. Fork the repo, create a feature branch
2. Write code with tests (`vitest`), lint with `biome`
3. Run `pnpm lint && pnpm test` before committing
4. Use [Conventional Commits](https://www.conventionalcommits.org/)
5. Open a PR

---

## License

[MIT](./LICENSE) © [Rick Somers](https://reaatech.com)
