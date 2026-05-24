# tool-use-firewall

> Policy enforcement layer between AI agents and MCP servers — intercept, validate, and secure every tool call before it reaches the upstream.

This is the unscoped convenience package. It ships the `tool-use-firewall`
binary and re-exports the full programmatic API. Under the hood it is a thin
alias for [`@reaatech/tool-use-firewall-server`](https://www.npmjs.com/package/@reaatech/tool-use-firewall-server).

## Install

```bash
# Run without installing
npx tool-use-firewall --config ./policy.yaml --upstream node ./my-mcp-server.js

# Or install the CLI globally
npm install -g tool-use-firewall
tool-use-firewall --config ./policy.yaml --upstream node ./my-mcp-server.js
```

> Requires Node.js ≥ 20.

## Programmatic use

```ts
import { MCPProxyServer } from 'tool-use-firewall';
```

If you want a narrower dependency surface, import directly from the scoped
`@reaatech/tool-use-firewall-*` packages instead.

See the [project README](https://github.com/reaatech/tool-use-firewall#readme)
for full documentation.
