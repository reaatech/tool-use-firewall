# Database Safety Example

Protect a database-backed MCP server from DROP TABLE, TRUNCATE, and unscoped
DELETE statements.

## Run

From the repo root:

```bash
pnpm build
node dist/cli.js \
  --config ./policies/database-safe.yaml \
  --upstream node ./examples/database-safety/db-mcp-server.js
```

Try it:

```bash
# Allowed:
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"database_execute","arguments":{"query":"SELECT * FROM users"}}}' | \
  node dist/cli.js --config ./policies/database-safe.yaml --upstream node ./examples/database-safety/db-mcp-server.js

# Blocked (DROP TABLE):
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"database_execute","arguments":{"query":"DROP TABLE users"}}}' | \
  node dist/cli.js --config ./policies/database-safe.yaml --upstream node ./examples/database-safety/db-mcp-server.js
```

`db-mcp-server.js` is a mock — it never touches a real database.
