# Basic Proxy Example

The smallest possible setup: a mock upstream MCP server with two tools (`echo`,
`add`) protected by the default policy.

## Run

From the repo root:

```bash
pnpm build
node dist/cli.js \
  --config ./policies/default.yaml \
  --upstream node ./examples/basic-proxy/upstream-server.js
```

The proxy reads JSON-RPC on stdin and writes responses on stdout. Try it by
piping a request in:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
  node dist/cli.js \
    --config ./policies/default.yaml \
    --upstream node ./examples/basic-proxy/upstream-server.js
```

The default policy blocks unknown tool calls and rate-limits everything.
