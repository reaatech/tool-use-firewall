#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { validatePolicyFile } from '@reaatech/tool-use-firewall-config';
import { MCPProxyServer } from './server.js';

declare const __PACKAGE_VERSION__: string | undefined;

const FIREWALL_FLAGS = new Set([
  '--config',
  '-c',
  '--upstream',
  '-u',
  '--upstream-args',
  '--approval-port',
  '--help',
  '-h',
  '--version',
  '-v',
  '--init',
  '--validate',
  '--http-port',
  '--dry-run',
]);

export function readVersion(): string {
  return typeof __PACKAGE_VERSION__ === 'string' ? __PACKAGE_VERSION__ : 'unknown';
}

export function showHelp(): void {
  console.error(`
tool-use-firewall — Policy enforcement layer between AI agents and MCP servers

Usage:
  tool-use-firewall --config <path> --upstream <command> [options]

Options:
  --config, -c        Path to policy YAML file (required)
  --upstream, -u      Command to spawn the upstream MCP server (required)
  --upstream-args     Arguments to forward to the upstream server (space-separated string)
  --approval-port     Port for the approval HTTP API (optional)
  --http-port         Port for the HTTP transport (optional)
  --dry-run           Shadow mode: log blocked actions but don't enforce
  --init              Scaffold a policy YAML from the upstream server's tools/list
  --validate <path>   Validate a policy YAML (schema + ReDoS checks) and exit
  --help, -h          Show this help message
  --version, -v       Show version

Pass arguments to the upstream server after a literal "--":
  tool-use-firewall --config p.yaml --upstream node -- ./mcp-server.js --port 9000

Or use the --upstream-args flag for scripted environments:
  tool-use-firewall --config p.yaml --upstream node --upstream-args "./mcp-server.js --port 9000"
`);
}

interface ParsedArgs {
  configPath: string;
  upstreamCommand: string;
  upstreamArgs: string[];
  approvalPort?: number;
  httpPort?: number;
  dryRun?: boolean;
  initMode?: boolean;
  validatePath?: string;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const args = [...argv];
  let configPath: string | undefined;
  let upstreamCommand: string | undefined;
  const upstreamArgs: string[] = [];
  let approvalPort: number | undefined;
  let httpPort: number | undefined;
  let dryRun = false;
  let initMode = false;
  let validatePath: string | undefined;

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
    if (arg === '--upstream-args') {
      const raw = args[++i];
      if (typeof raw !== 'string' || raw.length === 0) {
        console.error('Error: --upstream-args requires a value');
        process.exit(1);
      }
      upstreamArgs.push(...raw.split(/\s+/).filter(Boolean));
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
    if (arg === '--http-port') {
      const raw = args[++i];
      const port = Number(raw);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        console.error('Error: --http-port must be an integer between 1 and 65535');
        process.exit(1);
      }
      httpPort = port;
      continue;
    }
    if (arg === '--dry-run') {
      dryRun = true;
      continue;
    }
    if (arg === '--init') {
      initMode = true;
      continue;
    }
    if (arg === '--validate') {
      const raw = args[++i];
      if (typeof raw !== 'string' || raw.length === 0 || raw.startsWith('-')) {
        console.error('Error: --validate requires a path to a policy YAML file');
        process.exit(1);
      }
      validatePath = raw;
      continue;
    }
    console.error(`Error: unknown argument: ${arg}`);
    showHelp();
    process.exit(1);
  }

  if (validatePath) {
    return {
      configPath: validatePath,
      upstreamCommand: upstreamCommand ?? '',
      upstreamArgs,
      validatePath,
    };
  }

  if (initMode) {
    if (!upstreamCommand) {
      console.error('Error: --upstream is required for --init');
      process.exit(1);
    }
    return {
      configPath: configPath ?? '',
      upstreamCommand,
      upstreamArgs,
      approvalPort,
      httpPort,
      dryRun,
      initMode,
    };
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

  return { configPath, upstreamCommand, upstreamArgs, approvalPort, httpPort, dryRun, initMode };
}

async function doInit(upstreamCommand: string, upstreamArgs: string[]): Promise<void> {
  console.error('Connecting to upstream MCP server to list tools...');

  const proc = spawn(upstreamCommand, upstreamArgs, {
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const lines: string[] = [];

  proc.stdout?.on('data', (data: Buffer) => {
    lines.push(...data.toString().split('\n').filter(Boolean));
  });

  proc.stderr?.on('data', () => {});

  proc.stdin?.write(
    `${JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {} },
    })}\n`,
  );
  proc.stdin?.write(
    `${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })}\n`,
  );

  await new Promise<void>((resolve) => {
    setTimeout(() => {
      proc.kill();
      resolve();
    }, 5000);
    proc.on('exit', () => resolve());
  });

  for (const line of lines) {
    try {
      const msg = JSON.parse(line);
      if (msg.id === 2 && msg.result?.tools) {
        const tools = msg.result.tools as Array<{ name: string; description?: string }>;
        const yaml = generatePolicyYaml(tools);
        const path = 'policy.generated.yaml';
        writeFileSync(path, yaml, 'utf-8');
        console.error(`Generated policy: ${path}`);
        console.error(`Found ${tools.length} tools`);
        process.exit(0);
      }
    } catch {
      // skip non-JSON or non-matching messages
    }
  }

  console.error('Failed to get tools/list from upstream');
  process.exit(1);
}

function generatePolicyYaml(tools: Array<{ name: string; description?: string }>): string {
  const lines: string[] = [
    'version: "1.0"',
    '',
    'settings:',
    '  default_action: block',
    '  audit_level: full',
    '',
  ];

  lines.push('validation:', '  rules:');

  const writeTools: string[] = [];
  const dbTools: string[] = [];
  const readTools: string[] = [];

  for (const tool of tools) {
    const name = tool.name.toLowerCase();
    if (/write|create|delete|update|insert|drop|remove|deploy/i.test(name)) {
      writeTools.push(tool.name);
    } else if (/database|sql|query|execute/i.test(name)) {
      dbTools.push(tool.name);
    } else {
      readTools.push(tool.name);
    }
  }

  if (dbTools.length > 0) {
    lines.push('    - id: sql_safe');
    lines.push('      type: sql_safe');
    lines.push(`      tools: ${JSON.stringify(dbTools)}`);
    lines.push('');
  }

  lines.push(
    'rate_limits:',
    '  global:',
    '    requests_per_minute: 120',
    '    burst_capacity: 20',
    '',
  );

  lines.push('rules:');

  for (const tool of readTools) {
    lines.push(`  - id: allow_${tool.replace(/[^a-z0-9_]/gi, '_').toLowerCase()}`);
    lines.push('    type: allow');
    lines.push(`    tools: ["${tool}"]`);
    lines.push('    priority: 10');
  }

  for (const tool of dbTools) {
    lines.push(`  - id: allow_${tool.replace(/[^a-z0-9_]/gi, '_').toLowerCase()}_select`);
    lines.push('    type: allow');
    lines.push(`    tools: ["${tool}"]`);
    lines.push('    conditions:');
    lines.push('      - argument: query');
    lines.push(`        pattern: "^SELECT\\\\s+"`);
    lines.push(`        flags: "i"`);
    lines.push('    priority: 100');
  }

  for (const tool of writeTools) {
    lines.push(`  - id: approve_${tool.replace(/[^a-z0-9_]/gi, '_').toLowerCase()}`);
    lines.push('    type: approval_required');
    lines.push(`    tools: ["${tool}"]`);
    lines.push('    priority: 50');
    lines.push(`    description: "${tool} requires approval"`);
  }

  lines.push('');
  lines.push('read_only_exceptions:');
  for (const tool of readTools) {
    lines.push(`  - tools: ["${tool}"]`);
    lines.push('    conditions: []');
  }

  return `${lines.join('\n')}\n`;
}

/** Validate a policy file and exit with code 0 (valid) or 1 (invalid). */
export function doValidate(path: string): never {
  const result = validatePolicyFile(path);

  for (const warning of result.warnings) {
    console.error(`⚠️  ${warning}`);
  }

  if (result.valid) {
    console.error(`✓ Policy is valid: ${path}`);
    process.exit(0);
  }

  console.error(`✗ Policy is invalid: ${path}`);
  for (const error of result.errors) {
    console.error(`  - ${error}`);
  }
  process.exit(1);
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

  if (parsed.validatePath) {
    doValidate(parsed.validatePath);
  }

  if (parsed.initMode) {
    await doInit(parsed.upstreamCommand, parsed.upstreamArgs);
    return;
  }

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

const isMainModule =
  typeof import.meta.url === 'string' &&
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === process.argv[1];

if (isMainModule) {
  main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}
