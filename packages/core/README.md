# @reaatech/tool-use-firewall-core

[![npm version](https://img.shields.io/npm/v/@reaatech/tool-use-firewall-core.svg)](https://www.npmjs.com/package/@reaatech/tool-use-firewall-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/reaatech/tool-use-firewall/ci.yml?branch=main&label=CI)](https://github.com/reaatech/tool-use-firewall/actions/workflows/ci.yml)

> **Status:** Pre-1.0 — APIs may change in minor versions. Pin to a specific version in production.

Core types, error classes, structured logger, sensitive data redactor, and ReDoS-safe regex utilities for tool-use-firewall. This is the foundational package used by every other `@reaatech/tool-use-firewall-*` package.

## Installation

```bash
npm install @reaatech/tool-use-firewall-core
# or
pnpm add @reaatech/tool-use-firewall-core
```

## Feature Overview

- **Request context types** — `RequestContext`, `Middleware`, `MiddlewareResult`, `InterceptorResponse` for building the interceptor pipeline
- **Typed error hierarchy** — `FirewallError`, `RateLimitError`, `ValidationError`, `PolicyViolationError`, `BudgetExceededError`, `ApprovalRequiredError` — all with error codes
- **Structured logger** — JSON logging to stderr (never stdout) to avoid corrupting MCP JSON-RPC streams
- **Sensitive data redactor** — Pattern-based redaction of API keys, bearer tokens, emails, and custom patterns
- **ReDoS-safe regex** — `safeRegExp()` and `isSafeRegex()` with nested quantifier detection, depth limits, and length caps
- **Glob-to-regex conversion** — `globToRegex()` for tool name pattern matching
- **Zero runtime dependencies** — lightweight and tree-shakeable

## Quick Start

```typescript
import { FirewallError, Logger, redact, safeRegExp } from "@reaatech/tool-use-firewall-core";

// Throw typed errors
throw new FirewallError({ code: "POLICY_VIOLATION", message: "Blocked by policy" });

// Structured logging (writes to stderr)
const log = new Logger("MyService");
log.info("Request processed", { toolName: "db_query", latency: 42 });

// Redact sensitive data
const safe = redact({ api_key: "sk-1234", query: "SELECT 1" });
// → { api_key: "[REDACTED]", query: "SELECT 1" }

// Safe regex compilation
const re = safeRegExp("^SELECT\\s+.*$", "i");
```

## Exports

### Types

| Export | Description |
|--------|-------------|
| `RequestContext` | Immutable request metadata flowing through the pipeline: `requestId`, `sessionId`, `method`, `toolName`, `arguments`, `metadata` |
| `createRequestContext` | Factory for constructing a `RequestContext` with `receivedAt` timestamp and empty `metadata` map |
| `Middleware` | Interface: `execute(context: RequestContext): Promise<MiddlewareResult>` |
| `MiddlewareAction` | Union: `'CONTINUE'` \| `'BLOCK'` \| `'APPROVAL_REQUIRED'` |
| `MiddlewareResult` | `{ action, reason?, metadata? }` |
| `InterceptorResponse` | `{ allowed, action, reason?, metadata? }` |

### Error Classes

| Class | Code | Description |
|-------|------|-------------|
| `FirewallError` | (custom) | Base error with `code`, `message`, `requestId`, `details`, `toJSON()` |
| `PolicyViolationError` | `POLICY_VIOLATION` | Blocked by a policy rule |
| `RateLimitError` | `RATE_LIMIT_EXCEEDED` | Rate limit hit, includes `retryAfterMs` |
| `ValidationError` | `VALIDATION_ERROR` | Argument validation failed |
| `BudgetExceededError` | `BUDGET_EXCEEDED` | Session cost budget exceeded |
| `ApprovalRequiredError` | `APPROVAL_REQUIRED` | Human approval required, includes `approvalId` |

### Utilities

| Export | Description |
|--------|-------------|
| `Logger` | JSON structured logger, writes to stderr (never stdout) |
| `redact` | Deep-redact values using pattern matching |
| `DEFAULT_REDACTION_PATTERNS` | Built-in patterns: API keys, bearer tokens, emails |
| `safeRegExp(pattern, flags?)` | Compile a regex safely, throws `UnsafeRegexError` on ReDoS patterns |
| `isSafeRegex(pattern)` | Boolean check for ReDoS safety |
| `globToRegex(pattern)` | Convert `*`-wildcard glob to anchored regex |

## Related Packages

- [`@reaatech/tool-use-firewall-config`](https://www.npmjs.com/package/@reaatech/tool-use-firewall-config) — Policy schema and YAML loader
- [`@reaatech/tool-use-firewall-policies`](https://www.npmjs.com/package/@reaatech/tool-use-firewall-policies) — Policy engine and validators

## License

[MIT](LICENSE)
