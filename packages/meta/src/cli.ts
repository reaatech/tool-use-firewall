#!/usr/bin/env node
// Thin launcher for the `tool-use-firewall` binary. The real implementation
// lives in @reaatech/tool-use-firewall-server; we invoke its `main` so this
// package is just an unscoped alias (and reserves the bare name on npm).
import { main } from '@reaatech/tool-use-firewall-server/cli';

main().catch((error: unknown) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
