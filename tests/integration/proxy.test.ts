import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { writeFileSync, mkdtempSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('MCP Proxy Integration', () => {
  let tempDir: string;
  let proxyProc: ReturnType<typeof spawn>;
  const responses: Array<Record<string, unknown>> = [];

  beforeAll(async () => {
    tempDir = mkdtempSync(join(tmpdir(), 'firewall-integ-'));

    const policyPath = join(tempDir, 'policy.yaml');
    writeFileSync(
      policyPath,
      `
version: "1.0"
settings:
  default_action: allow
rate_limits:
  global:
    requests_per_minute: 1000
    burst_capacity: 1000
validation:
  rules:
    - id: sql_no_drop
      type: sql_safe
      tools: ["database_execute"]
      argument: "query"
`,
    );

    const upstreamPath = join(tempDir, 'upstream.js');
    writeFileSync(
      upstreamPath,
      `
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    if (msg.method === 'tools/list') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { tools: [
          { name: 'echo', description: 'Echo' },
          { name: 'database_execute', description: 'DB' }
        ]}
      }) + '\\n');
    } else if (msg.method === 'tools/call') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { content: [{ type: 'text', text: 'ok:' + msg.params.name }] }
      }) + '\\n');
    } else {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: {} }) + '\\n');
    }
  } catch (e) { /* ignore */ }
});
`,
    );

    proxyProc = spawn(
      'tsx',
      [
        join(process.cwd(), 'src/cli.ts'),
        '--config',
        policyPath,
        '--upstream',
        'node',
        upstreamPath,
      ],
      {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, NODE_ENV: 'test' },
      },
    );

    const stdout = proxyProc.stdout;
    if (stdout) {
      createInterface({ input: stdout }).on('line', (line) => {
        try {
          responses.push(JSON.parse(line));
        } catch {
          /* ignore */
        }
      });
    }

    proxyProc.stderr?.on('data', (data) => {
      console.error('[proxy stderr]', data.toString());
    });

    await new Promise((r) => setTimeout(r, 800));
  });

  afterAll(() => {
    if (proxyProc && !proxyProc.killed) {
      proxyProc.kill();
    }
    rmdirSync(tempDir, { recursive: true });
  });

  const send = (msg: Record<string, unknown>): void => {
    if (proxyProc.stdin) {
      proxyProc.stdin.write(JSON.stringify(msg) + '\n');
    }
  };

  const waitForResponse = (timeout = 3000): Promise<Record<string, unknown>> => {
    const startLen = responses.length;
    return new Promise((resolve, reject) => {
      const check = () => {
        if (responses.length > startLen) {
          resolve(responses[responses.length - 1]);
          return;
        }
        setTimeout(check, 50);
      };
      check();
      setTimeout(() => reject(new Error('Timeout waiting for response')), timeout);
    });
  };

  it('should pass through tools/list', async () => {
    responses.length = 0;
    send({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    const response = await waitForResponse();
    expect(response.result).toBeDefined();
    expect(response.error).toBeUndefined();
  });

  it('should pass through allowed tool calls and preserve the agent request id', async () => {
    responses.length = 0;
    send({
      jsonrpc: '2.0',
      id: 'agent-req-2',
      method: 'tools/call',
      params: { name: 'echo', arguments: { text: 'hello' } },
    });
    const response = await waitForResponse();
    expect(response.error).toBeUndefined();
    expect(response.result).toBeDefined();
    expect(response.id).toBe('agent-req-2');
  });

  it('should block dangerous SQL queries', async () => {
    responses.length = 0;
    send({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'database_execute',
        arguments: { query: 'DROP TABLE users' },
      },
    });
    const response = await waitForResponse();
    expect(response.error).toBeDefined();
    expect(response.error).toMatchObject({ code: -32000 });
  });

  it('should block DELETE without WHERE', async () => {
    responses.length = 0;
    send({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: {
        name: 'database_execute',
        arguments: { query: 'DELETE FROM users' },
      },
    });
    const response = await waitForResponse();
    expect(response.error).toBeDefined();
  });
});
