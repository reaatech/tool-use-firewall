#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MCPProxyServer } from './server.js';

const FIREWALL_FLAGS = new Set([
  '--config',
  '-c',
  '--upstream',
  '-u',
  '--approval-port',
  '--help',
  '-h',
  '--version',
  '-v',
]);

function readVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkgPath = resolve(here, '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as { version?: string };
    return pkg.version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

function showHelp(): void {
  console.error(`
tool-use-firewall — Policy enforcement layer between AI agents and MCP servers

Usage:
  tool-use-firewall --config <path> --upstream <command> [-- <upstream-args...>]

Options:
  --config, -c       Path to policy YAML file (required)
  --upstream, -u     Command to spawn the upstream MCP server (required)
  --approval-port    Port for the approval HTTP API (optional)
  --help, -h         Show this help message
  --version, -v      Show version

Pass arguments to the upstream server after a literal "--":
  tool-use-firewall --config p.yaml --upstream node -- ./mcp-server.js --port 9000
`);
}

interface ParsedArgs {
  configPath: string;
  upstreamCommand: string;
  upstreamArgs: string[];
  approvalPort?: number;
}

function parseArgs(argv: string[]): ParsedArgs {
  const args = [...argv];
  let configPath: string | undefined;
  let upstreamCommand: string | undefined;
  const upstreamArgs: string[] = [];
  let approvalPort: number | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--config' || arg === '-c') {
      configPath = args[++i];
      continue;
    }
    if (arg === '--upstream' || arg === '-u') {
      upstreamCommand = args[++i];
      while (i + 1 < args.length) {
        const next = args[i + 1];
        if (next === '--') {
          i++;
          while (i + 1 < args.length) {
            upstreamArgs.push(args[++i]);
          }
          break;
        }
        if (FIREWALL_FLAGS.has(next)) break;
        upstreamArgs.push(args[++i]);
      }
      continue;
    }
    if (arg === '--approval-port') {
      const raw = args[++i];
      const port = Number(raw);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        console.error('Error: --approval-port must be an integer between 1 and 65535');
        process.exit(1);
      }
      approvalPort = port;
      continue;
    }
    console.error(`Error: unknown argument: ${arg}`);
    showHelp();
    process.exit(1);
  }

  if (!configPath) {
    console.error('Error: --config is required');
    showHelp();
    process.exit(1);
  }
  if (!upstreamCommand) {
    console.error('Error: --upstream is required');
    showHelp();
    process.exit(1);
  }

  return { configPath, upstreamCommand, upstreamArgs, approvalPort };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  if (argv.includes('--help') || argv.includes('-h')) {
    showHelp();
    process.exit(0);
  }
  if (argv.includes('--version') || argv.includes('-v')) {
    console.error(readVersion());
    process.exit(0);
  }

  const parsed = parseArgs(argv);

  const server = new MCPProxyServer({
    policyPath: parsed.configPath,
    upstreamCommand: parsed.upstreamCommand,
    upstreamArgs: parsed.upstreamArgs.length > 0 ? parsed.upstreamArgs : undefined,
    approvalPort: parsed.approvalPort,
  });

  process.on('SIGINT', async () => {
    await server.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    await server.stop();
    process.exit(0);
  });

  await server.start();
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
