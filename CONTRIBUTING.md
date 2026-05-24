# Contributing to tool-use-firewall

## Development Setup

```bash
# Install pnpm if you don't have it
npm install -g pnpm

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Lint and format
pnpm lint
pnpm lint:fix
```

## Monorepo Structure

This repo uses pnpm workspaces with Turborepo for task orchestration.

```
packages/
  core/       — Types, errors, logger, redactor, safe-regex
  config/     — Policy schema (Zod) + YAML loader
  policies/   — Policy engine, rate limiter, cost tracker, validators, secret scanner, anomaly detector
  approvals/  — Approval workflow, HTTP API, CLI/webhook/Slack/Discord approvers
  audit/      — Audit logging with redaction
  server/     — MCP proxy server, CLI, interceptor pipeline
```

## Conventional Commits

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `refactor:` code change that neither fixes a bug nor adds a feature
- `test:` adding or correcting tests
- `chore:` build process or auxiliary tool changes

## Pull Request Process

1. Fork the repo and create a feature branch
2. Make your changes with tests
3. Ensure `pnpm lint` and `pnpm test` pass
4. Update relevant documentation
5. Open a PR with a clear description

## Releasing

Maintainers use Changesets to manage releases:

```bash
pnpm changeset
pnpm version-packages
pnpm release
```
