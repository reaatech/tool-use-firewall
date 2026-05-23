# AGENTS.md — tool-use-firewall

> Agent-focused guidance for contributing to this codebase.

## Project Structure

This is a **pnpm workspace monorepo** managed with Turborepo.

```
packages/
  core/       — Types, errors, logger, redactor, safe-regex
  config/     — Policy schema (Zod) + YAML loader
  policies/   — Policy engine, rate limiter, cost tracker, validators
  approvals/  — Approval workflow, HTTP API, CLI/webhook approvers
  audit/      — Audit logging with redaction
  server/     — MCP proxy server, CLI, interceptor pipeline
e2e/          — End-to-end tests
examples/     — Runnable example servers
policies/     — YAML policy files
skills/       — Specialized agent skills
```

## Build System

- **Package manager:** pnpm (required)
- **Build tool:** tsup (per-package) + Turborepo (orchestration)
- **Format/Lint:** Biome (not Prettier/ESLint)
- **Test:** Vitest
- **TypeScript:** Strict mode, ESM + CJS dual output

### Common Commands

```bash
# Install all dependencies
pnpm install

# Build everything
pnpm build

# Run all tests
pnpm test

# Lint & format
pnpm lint
pnpm lint:fix

# Type-check without emit
pnpm typecheck
```

## Core Principles

### 1. Security First
- Every line of code must be security-conscious
- Never bypass validation or policy checks
- Assume all inputs are potentially malicious
- Follow the principle of least privilege

### 2. Quality Standards
- Maintain ≥90% test coverage
- Use strict TypeScript (`strict: true`)
- No `any` types — Biome is configured to error on `any`. Use `unknown` + narrowing instead.
- All public APIs must have JSDoc documentation

### 3. Performance Awareness
- Target <10ms latency for policy evaluation
- Minimize memory footprint
- Profile before optimizing

### Memory Management
All stateful components (rate limiters, approval queues, cost trackers, caches) must implement bounded storage with TTL or capacity-based eviction. Unbounded `Map` usage is a security vulnerability (DoS via memory exhaustion). See [ARCHITECTURE.md](./ARCHITECTURE.md) Resource Management section for patterns.

## Coding Conventions

1. **Runtime validation:** Use Zod for all external-facing data. Never trust raw JSON.
2. **Logging:** Use the `Logger` class from `packages/core`. Never `console.log` in library code.
3. **Error handling:** Use typed `FirewallError` subclasses from `packages/core`. Include error codes.
4. **Types:** Prefer `type` over `interface` for data shapes. Keep `interface` for class contracts.
5. **No `any`:** Biome is configured to error on `any`. Use `unknown` + narrowing instead.
6. **Exports:** Always provide ESM + CJS dual output with `types` condition first in `exports`.

## Adding a New Package

1. Create `packages/<name>/` with `package.json`, `tsconfig.json`, `tsup.config.ts`, `vitest.config.ts`, `src/index.ts`
2. Use `@reaatech/tool-use-firewall-core` for shared types. Do not duplicate schemas.
3. Add to `pnpm-workspace.yaml` if not under `packages/*`
4. Run `pnpm install` from the package directory

## Testing

- Unit tests live next to source files: `src/foo.test.ts`
- E2E tests live in `e2e/`
- Always run `pnpm test` before committing

## Available Skills

Skills in `skills/` provide specialized instructions:

| Skill | Description |
|-------|-------------|
| `policy-engine` | Implement and configure policy rules |
| `rate-limiter` | Configure and manage rate limiting |
| `sql-validator` | SQL injection prevention and validation |
| `audit-logger` | Configure audit logging and compliance |
| `approval-workflow` | Set up human-in-the-loop approvals |
| `testing` | Write and run tests |
| `security-review` | Security-focused code review |

## Resources

- [MCP SDK Documentation](https://github.com/modelcontextprotocol/sdk)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
