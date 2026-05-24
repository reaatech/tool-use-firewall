// Unscoped convenience entry point. Re-exports the full public API from the
// server package so `import { MCPProxyServer } from 'tool-use-firewall'` works.
// The scoped @reaatech/tool-use-firewall-* packages remain the canonical
// imports for consumers who want a narrower dependency surface.
export * from '@reaatech/tool-use-firewall-server';
