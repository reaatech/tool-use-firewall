# Enterprise Example

End-to-end setup with policy rules, multi-level approvals, per-tool rate limits,
session cost budgets, file-based audit logging, and a break-glass bypass token.

## Run

From the repo root:

```bash
pnpm build

# Required when --approval-port is set:
export APPROVAL_API_TOKEN="$(openssl rand -hex 32)"

# Optional emergency bypass for read-only mode:
export FIREWALL_BYPASS_TOKEN="$(openssl rand -hex 32)"

node dist/cli.js \
  --config ./examples/enterprise/enterprise-policy.yaml \
  --upstream node ./examples/enterprise/enterprise-mcp-server.js \
  --approval-port 8080
```

The approval API binds to `127.0.0.1:8080` and requires the bearer token from
`APPROVAL_API_TOKEN`. To list pending approvals:

```bash
curl -H "Authorization: Bearer $APPROVAL_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/approvals/pending
```

The enterprise policy demonstrates:

- Multi-level approval chains (`deploy_release` requires 2 approvals from
  separate groups).
- Per-tool rate limits.
- Session cost budgets with per-tool weights.
- File-based audit logging (writes to `./enterprise-audit.log`).
- Bypass token for break-glass overrides of read-only mode.

`enterprise-mcp-server.js` is a mock — it returns canned responses and never
performs real side effects.
