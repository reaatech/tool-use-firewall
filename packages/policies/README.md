# @reaatech/tool-use-firewall-policies

[![npm version](https://img.shields.io/npm/v/@reaatech/tool-use-firewall-policies.svg)](https://www.npmjs.com/package/@reaatech/tool-use-firewall-policies)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/reaatech/tool-use-firewall/ci.yml?branch=main&label=CI)](https://github.com/reaatech/tool-use-firewall/actions/workflows/ci.yml)

> **Status:** Pre-1.0 — APIs may change in minor versions. Pin to a specific version in production.

Policy engine, rate limiter, cost tracker, argument validators, SQL validator, and read-only enforcement for tool-use-firewall. All components implement the `Middleware` interface for pluggable use in the interceptor pipeline.

## Installation

```bash
npm install @reaatech/tool-use-firewall-policies
# or
pnpm add @reaatech/tool-use-firewall-policies
```

## Feature Overview

- **Policy engine** — Priority-based rule evaluation with glob pattern matching for tool names
- **Token bucket rate limiter** — Global, per-tool, and per-session limits with TTL-based memory eviction
- **Session cost tracker** — Per-session budget enforcement with tool-level pricing and warn/block actions
- **SQL validator** — Blocked patterns, injection detection, WHERE clause enforcement, read-only mode
- **Argument validator** — Regex, shell-safety, and SQL-safety validators with custom rules from config
- **Read-only check** — Global toggle with per-tool exceptions and timing-safe bypass tokens
- **All implement `Middleware`** — Drop into any `InterceptorPipeline`

## Quick Start

```typescript
import { PolicyEngine, RateLimiter, TokenBucket } from "@reaatech/tool-use-firewall-policies";
import { createRequestContext } from "@reaatech/tool-use-firewall-core";

// Rate limiting
const limiter = new RateLimiter({
  global: { requests_per_minute: 60, burst_capacity: 10 },
});

const ctx = createRequestContext({
  requestId: "1", sessionId: "s1", method: "tools/call", toolName: "db_query",
});

// Returns { action: "CONTINUE" } or throws RateLimitError
const result = await limiter.execute(ctx);

// Policy evaluation
const engine = new PolicyEngine({
  rules: [{ id: "r1", type: "block", tools: ["dangerous_tool"], priority: 10 }],
  settings: { default_action: "allow", audit_level: "full", read_only: false },
  version: "1.0",
});

const evalResult = await engine.evaluate(ctx);
// → { action: "ALLOW" | "BLOCK" | "APPROVAL_REQUIRED", rule?, reason? }
```

## Exports

| Export | Description |
|--------|-------------|
| `PolicyEngine` | Rule evaluation engine: evaluates config rules against request context |
| `EvaluationResult` | `{ action, rule?, reason? }` |
| `RateLimiter` | Middleware: global, per-tool, per-session token bucket rate limiting |
| `TokenBucket` | Core token bucket algorithm (used internally, also exported for custom use) |
| `CostTracker` | Middleware: session budget enforcement with tool-level costs |
| `ArgumentValidator` | Middleware: schema and regex validation of tool arguments |
| `SQLValidator` | Comprehensive SQL query validation (blocked patterns, injection, WHERE) |
| `SQLValidationResult` / `SQLValidationConfig` | SQL validator types |
| `ReadOnlyCheck` | Middleware: blocks write operations when read-only mode is enabled |
| `ValidatorFn` / `ValidationResult` | Argument validator function types |

## License

[MIT](LICENSE)
