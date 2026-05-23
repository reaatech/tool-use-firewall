# @reaatech/tool-use-firewall-approvals

[![npm version](https://img.shields.io/npm/v/@reaatech/tool-use-firewall-approvals.svg)](https://www.npmjs.com/package/@reaatech/tool-use-firewall-approvals)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/reaatech/tool-use-firewall/ci.yml?branch=main&label=CI)](https://github.com/reaatech/tool-use-firewall/actions/workflows/ci.yml)

> **Status:** Pre-1.0 — APIs may change in minor versions. Pin to a specific version in production.

Human-in-the-loop approval workflows for tool-use-firewall. Supports multi-level approval chains with timeout handling, an HTTP approval API, CLI prompts, and webhook notifications.

## Installation

```bash
npm install @reaatech/tool-use-firewall-approvals
# or
pnpm add @reaatech/tool-use-firewall-approvals
```

## Feature Overview

- **Approval workflow engine** — Manages pending approvals with status tracking and timeout expiry
- **Multi-level chains** — Require approval from multiple groups with configurable minimum approvals
- **HTTP API** — Express-based REST API for listing, approving, and denying requests (Bearer token auth)
- **Rate-limited API** — Per-IP token bucket on the approval HTTP endpoint
- **CLI approver** — Console-based approval prompts (writes to stderr, never stdout)
- **Webhook approver** — Sends approval requests via HTTP POST with configurable API keys
- **Bounded storage** — FIFO eviction when pending queue exceeds capacity

## Quick Start

```typescript
import { ApprovalWorkflow, createApprovalApi } from "@reaatech/tool-use-firewall-approvals";
import { createRequestContext } from "@reaatech/tool-use-firewall-core";

const workflow = new ApprovalWorkflow({
  default_timeout_ms: 300000,
  max_pending_approvals: 1000,
  required_for: [{ tools: ["dangerous_tool"], approvers: ["admin"], min_approvals: 1 }],
});

// Create the Express approval API
const app = createApprovalApi(workflow, "your-api-key");
app.listen(8080);

// Request approval — returns an approval ID (does not throw)
const ctx = createRequestContext({
  requestId: "1", sessionId: "s1", method: "tools/call", toolName: "dangerous_tool",
});
const approvalId = await workflow.requestApproval(ctx);
console.log(approvalId); // "appr_<uuid>"
```

## Exports

| Export | Description |
|--------|-------------|
| `ApprovalWorkflow` | Core workflow engine: `requestApproval`, `approve`, `deny`, `getStatus`, `listPending` |
| `createApprovalApi` | Express app factory: routes at `/api/v1/approvals/*` with Bearer auth |
| `CLIApprover` | Console-based `ApproverGroup` for local approval prompts |
| `WebhookApprover` | HTTP-based `ApproverGroup` for external approval systems |
| `ApprovalRequest` | `{ id, context, status, createdAt, expiresAt, requiredApprovers, approvals, denials, minApprovals }` |
| `ApprovalResult` | `{ success, status?, pendingApprovers?, reason? }` |
| `ApproverGroup` | Interface: `notify(request: ApprovalRequest): Promise<void>` |

## License

[MIT](LICENSE)
