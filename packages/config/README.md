# @reaatech/tool-use-firewall-config

[![npm version](https://img.shields.io/npm/v/@reaatech/tool-use-firewall-config.svg)](https://www.npmjs.com/package/@reaatech/tool-use-firewall-config)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/reaatech/tool-use-firewall/ci.yml?branch=main&label=CI)](https://github.com/reaatech/tool-use-firewall/actions/workflows/ci.yml)

> **Status:** Pre-1.0 — APIs may change in minor versions. Pin to a specific version in production.

Zod-based policy schema definitions and YAML policy file loader for tool-use-firewall. Validates policy configurations at startup and provides typed interfaces for the policy engine.

## Installation

```bash
npm install @reaatech/tool-use-firewall-config
# or
pnpm add @reaatech/tool-use-firewall-config
```

## Feature Overview

- **Zod validation** — Full policy config schema with nested rate limit, cost, validation, approval, audit, upstream, metrics, secret-scan, and anomaly subschemas
- **YAML loading** — `loadPolicyConfig(path)` reads and validates a YAML policy file, throws typed `ValidationError` on parse failures
- **Policy linting** — `validatePolicyFile(path)` checks a policy against the schema *and* verifies every regex is ReDoS-safe, returning structured errors/warnings (powers the `--validate` CLI flag)
- **Default values** — Sensible defaults for settings, timeouts, budget actions, and audit levels
- **TypeScript types** — All config shapes exported as `z.infer` types for compile-time safety
- **Dual ESM/CJS output**

## Quick Start

```typescript
import { loadPolicyConfig, type PolicyConfig } from "@reaatech/tool-use-firewall-config";

const config: PolicyConfig = loadPolicyConfig("./policies/default.yaml");
console.log(config.settings?.default_action); // "block"
```

Lint a policy without booting the proxy (e.g. in CI):

```typescript
import { validatePolicyFile } from "@reaatech/tool-use-firewall-config";

const result = validatePolicyFile("./policy.yaml");
if (!result.valid) {
  console.error(result.errors.join("\n"));
  process.exit(1);
}
```

## Exports

| Export | Description |
|--------|-------------|
| `loadPolicyConfig(path)` | Read and validate a YAML policy file |
| `validatePolicyFile(path)` / `PolicyValidationResult` | Lint a policy (schema + ReDoS) without throwing; returns `{ valid, errors, warnings }` |
| `policyConfigSchema` | Root Zod schema for the full policy YAML |
| `ruleSchema` / `Rule` | Allow/block/approval rule with conditions and priority |
| `ruleConditionSchema` / `RuleCondition` | Argument-based condition with pattern/equals/contains/gt/lt |
| `exceptionConditionSchema` / `ExceptionCondition` | Read-only exception condition (argument + regex pattern) |
| `rateLimitConfigSchema` / `RateLimitConfig` | Global, per-tool, and per-session rate limits |
| `costConfigSchema` / `CostConfig` | Session budgets and per-tool costs |
| `validationRuleSchema` / `ValidationRule` | Regex, shell-safe, and SQL-safe validation rules |
| `approvalConfigSchema` / `ApprovalConfig` | Multi-level approval configuration |
| `auditConfigSchema` / `AuditConfig` | Audit level, output targets, and redaction config |

## License

[MIT](LICENSE)
