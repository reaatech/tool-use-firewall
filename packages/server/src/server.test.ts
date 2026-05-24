// biome-ignore-all lint/suspicious/noExplicitAny: white-box tests reach into
// private members (pipeline, upstreamConnections, …) and read untyped JSON-RPC
// response objects; `any` is intentional and confined to this test file.
import { unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import {
  ApprovalRequiredError,
  FirewallError,
  RateLimitError,
  type RequestContext,
} from '@reaatech/tool-use-firewall-core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MCPProxyServer } from './server.js';

const spawnCallbacks = vi.hoisted(() => ({}) as Record<string, (...args: unknown[]) => void>);
const mockSpawnFn = vi.hoisted(() => vi.fn());
const captureSpawnEvent = vi.hoisted(() => (_evt: string, cb: (...args: unknown[]) => void) => {
  spawnCallbacks[_evt] = cb;
});

vi.mock('node:child_process', () => ({
  spawn: mockSpawnFn.mockImplementation(() => ({
    stdout: { on: captureSpawnEvent },
    stderr: { on: captureSpawnEvent },
    stdin: { write: vi.fn() },
    on: captureSpawnEvent,
    killed: false,
    kill: vi.fn(),
  })),
}));

const rlCallbacks = vi.hoisted(() => ({}) as Record<string, (...args: unknown[]) => void>);

vi.mock('node:readline', () => ({
  createInterface: vi.fn(() => ({
    on: vi.fn((_evt: string, cb: (...args: unknown[]) => void) => {
      rlCallbacks[_evt] = cb;
    }),
    close: vi.fn(),
  })),
}));

const testPolicyPath = resolve(tmpdir(), 'mcp-proxy-test-policy.yaml');

beforeEach(() => {
  writeFileSync(testPolicyPath, 'version: "1.0"\nrules: []\n', 'utf-8');
});

afterEach(() => {
  try {
    unlinkSync(testPolicyPath);
  } catch {
    // ignore
  }
});

/** Build a server with a pipeline that blocks every tools/call, so we can
 * exercise frame/batch handling without spawning a real upstream. */
function blockingServer(): MCPProxyServer {
  const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
  (server as any).pipeline.register({
    execute: async (_ctx: RequestContext) => ({ action: 'BLOCK', reason: 'test-block' }),
  });
  return server;
}

function toolCall(id: number | string, name = 'do_thing') {
  return { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: {} } };
}

describe('MCPProxyServer.processFrame', () => {
  let server: MCPProxyServer;

  beforeEach(() => {
    server = blockingServer();
  });

  it('returns an error response object for a single blocked tools/call', async () => {
    const response = (await server.processFrame(JSON.stringify(toolCall(1)))) as {
      jsonrpc: string;
      id: number;
      error: { code: number; message: string };
    };
    expect(Array.isArray(response)).toBe(false);
    expect(response.id).toBe(1);
    expect(response.error.code).toBe(-32000);
    expect(response.error.message).toBe('test-block');
  });

  it('aggregates a batch into an array of element responses', async () => {
    const batch = [toolCall(1), toolCall(2)];
    const responses = (await server.processFrame(JSON.stringify(batch))) as Array<{
      id: number;
      error: { message: string };
    }>;
    expect(Array.isArray(responses)).toBe(true);
    expect(responses).toHaveLength(2);
    expect(responses.map((r) => r.id).sort()).toEqual([1, 2]);
    expect(responses.every((r) => r.error.message === 'test-block')).toBe(true);
  });

  it('omits notifications/passthrough messages from the batch response', async () => {
    // `initialize` is not a tools/call, so it is forwarded (no upstream here)
    // and produces no immediate response; only the blocked tools/call replies.
    const batch = [{ jsonrpc: '2.0', method: 'initialize', params: {} }, toolCall(7)];
    const responses = (await server.processFrame(JSON.stringify(batch))) as Array<{ id: number }>;
    expect(Array.isArray(responses)).toBe(true);
    expect(responses).toHaveLength(1);
    expect(responses[0].id).toBe(7);
  });

  it('returns null when a batch contains only passthrough messages', async () => {
    const batch = [
      { jsonrpc: '2.0', method: 'initialize', params: {} },
      { jsonrpc: '2.0', method: 'notifications/initialized' },
    ];
    const response = await server.processFrame(JSON.stringify(batch));
    expect(response).toBeNull();
  });

  it('rejects an empty batch as an invalid request', async () => {
    const response = (await server.processFrame('[]')) as { error: { code: number } };
    expect(Array.isArray(response)).toBe(false);
    expect(response.error.code).toBe(-32600);
  });

  it('returns a parse error for malformed JSON', async () => {
    const response = (await server.processFrame('{not json')) as {
      id: null;
      error: { code: number; message: string };
    };
    expect(response.error.code).toBe(-32700);
    expect(response.error.message).toBe('Parse error');
  });

  it('rejects frames larger than the max message size', async () => {
    const huge = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"blob":"${'a'.repeat(
      11 * 1024 * 1024,
    )}"}}}`;
    const response = (await server.processFrame(huge)) as { error: { code: number } };
    expect(response.error.code).toBe(-32700);
  });

  it('forwards non-tools/call messages to upstream stdin', async () => {
    const mockStdin = { write: vi.fn() };
    (server as any).upstreamConnections = [{ process: { stdin: mockStdin } }];
    const response = await server.processFrame(
      JSON.stringify({ jsonrpc: '2.0', method: 'initialize', params: {} }),
    );
    expect(response).toBeNull();
    expect(mockStdin.write).toHaveBeenCalled();
  });

  it('forwards non-tools/call messages even without upstream connections', async () => {
    const response = await server.processFrame(
      JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
    );
    expect(response).toBeNull();
  });

  it('handles invalid JSON-RPC message structure', async () => {
    const response = await server.processFrame('"not an object"');
    expect(response).not.toBeNull();
    expect((response as any).error?.code).toBe(-32600);
  });
});

describe('MCPProxyServer.processMessage', () => {
  it('ALLOW path forwards to upstream and returns response', async () => {
    const srv = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (srv as any).pipeline.register({
      execute: async () => ({ action: 'CONTINUE' }),
    });
    const mockResponse = { jsonrpc: '2.0', id: 1, result: { content: [] } };
    (srv as any).upstreamConnections = [
      { process: { stdin: { write: vi.fn() }, killed: false }, backend: { name: 'test' } },
    ];
    (srv as any).forwardToUpstreamAndWait = vi.fn().mockResolvedValue(mockResponse);
    const response = await srv.processFrame(JSON.stringify(toolCall(1)));
    expect(response).toEqual(mockResponse);
  });

  it('APPROVAL_REQUIRED path requests approval and returns error with approval_id', async () => {
    const srv = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (srv as any).pipeline.register({
      execute: async () => ({ action: 'APPROVAL_REQUIRED', reason: 'needs approval' }),
    });
    (srv as any).approvalWorkflow = {
      requestApproval: vi.fn().mockResolvedValue('approval-xyz-123'),
    };
    const response = await srv.processFrame(JSON.stringify(toolCall(1, 'deploy')));
    expect(response).not.toBeNull();
    expect((response as any).error?.data?.approval_id).toBe('approval-xyz-123');
    expect((response as any).error?.code).toBe(-32000);
  });

  it('BLOCK path without approval workflow blocks normally', async () => {
    const srv = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (srv as any).pipeline.register({
      execute: async () => ({ action: 'APPROVAL_REQUIRED', reason: 'needs approval' }),
    });
    const response = await srv.processFrame(JSON.stringify(toolCall(1, 'deploy')));
    expect(response).not.toBeNull();
    expect((response as any).error?.code).toBe(-32000);
    expect((response as any).error?.message).toBe('needs approval');
    expect((response as any).error?.data?.approval_id).toBeUndefined();
  });

  it('handles pipeline processing errors', async () => {
    const srv = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (srv as any).pipeline.register({
      execute: async () => {
        throw new Error('pipeline crash');
      },
    });
    const response = await srv.processFrame(JSON.stringify(toolCall(1)));
    expect(response).not.toBeNull();
    expect((response as any).error?.code).toBe(-32000);
  });

  it('returns error when no upstream is configured for a tool', async () => {
    const srv = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (srv as any).pipeline.register({
      execute: async () => ({ action: 'CONTINUE' }),
    });
    const response = await srv.processFrame(JSON.stringify(toolCall(1)));
    expect(response).not.toBeNull();
    expect((response as any).error?.code).toBe(-32000);
    expect((response as any).error?.message).toBe('No upstream configured for this tool');
  });
});

describe('MCPProxyServer.getStats', () => {
  it('returns metrics with all expected fields', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const stats = server.getStats();
    expect(stats).toHaveProperty('uptime');
    expect(stats).toHaveProperty('requestsTotal', 0);
    expect(stats).toHaveProperty('blocksTotal', 0);
    expect(stats).toHaveProperty('approvalsTotal', 0);
    expect(stats).toHaveProperty('errorsTotal', 0);
    expect(stats).toHaveProperty('averageLatencyMs', 0);
    expect(stats).toHaveProperty('upstreamsConnected', 0);
  });

  it('calculates average latency from metrics', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).metrics.upstreamLatencyMs = [10, 20, 30];
    const stats = server.getStats();
    expect(stats.averageLatencyMs).toBe(20);
  });

  it('reports connected upstreams', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).upstreamConnections = [
      { process: { killed: false } },
      { process: { killed: true } },
    ];
    const stats = server.getStats();
    expect(stats.upstreamsConnected).toBe(1);
  });
});

describe('MCPProxyServer lifecycle', () => {
  it('reloadPolicy rebuilds pipeline', () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    const initialPipeline = (server as any).pipeline;
    (server as any).reloadPolicy();
    expect((server as any).pipeline).not.toBe(initialPipeline);
    expect((server as any).policyConfig).toBeDefined();
  });

  it('reloadPolicy handles file load errors gracefully', () => {
    const server = new MCPProxyServer({ policyPath: '/nonexistent/policy/file.yaml' });
    const initialPipeline = (server as any).pipeline;
    (server as any).reloadPolicy();
    expect((server as any).pipeline).toBe(initialPipeline);
  });

  it('reloadPolicy returns early with empty policyPath', () => {
    const server = new MCPProxyServer({ policyPath: '' });
    const initialPipeline = (server as any).pipeline;
    (server as any).reloadPolicy();
    expect((server as any).pipeline).toBe(initialPipeline);
  });

  it('start() and stop() lifecycle', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    (server as any).startStdioListener = vi.fn();
    await server.start();
    expect((server as any).policyConfig).toBeDefined();
    expect((server as any).pipeline).toBeDefined();
    await server.stop();
  });

  it('stop() handles missing servers gracefully', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    await expect(server.stop()).resolves.toBeUndefined();
  });
});

describe('MCPProxyServer.buildPipeline', () => {
  it('builds minimal pipeline', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).buildPipeline({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
    });
    const pipeline = (server as any).pipeline;
    expect(pipeline.middlewares.length).toBe(2);
  });

  it('includes RateLimiter when rate_limits are configured', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).buildPipeline({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      rate_limits: { global: { requests_per_minute: 60, burst_capacity: 10 } },
    });
    const pipeline = (server as any).pipeline;
    expect(pipeline.middlewares.length).toBe(3);
    expect(pipeline.middlewares[0].constructor.name).toBe('RateLimiter');
  });

  it('includes CostTracker when cost is configured', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).buildPipeline({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      cost: { session_budget: 100 },
    });
    const pipeline = (server as any).pipeline;
    expect(pipeline.middlewares.length).toBe(3);
    expect(pipeline.middlewares[0].constructor.name).toBe('CostTracker');
  });

  it('includes SecretScanner when secret_scan is enabled', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).buildPipeline({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      secret_scan: { enabled: true },
    });
    const pipeline = (server as any).pipeline;
    expect(pipeline.middlewares.length).toBe(3);
    expect(pipeline.middlewares[0].constructor.name).toBe('SecretScanner');
  });

  it('includes ArgumentValidator when validation rules exist', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).buildPipeline({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      validation: {
        rules: [
          {
            id: 'r1',
            type: 'regex',
            argument: 'query',
            patterns: [{ pattern: '^select', message: 'must start with select' }],
          },
        ],
      },
    });
    const pipeline = (server as any).pipeline;
    expect(pipeline.middlewares.length).toBe(3);
    expect(pipeline.middlewares[0].constructor.name).toBe('ArgumentValidator');
  });

  it('includes SchemaValidator when schema validation is enabled', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).buildPipeline({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      validation: { schema_validation: { enabled: true, strict: false } },
    });
    const pipeline = (server as any).pipeline;
    expect(pipeline.middlewares.length).toBe(3);
    expect(pipeline.middlewares[0].constructor.name).toBe('SchemaValidator');
  });

  it('includes AnomalyDetector when anomaly detection is enabled', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).buildPipeline({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      anomaly_detection: { enabled: true },
    });
    const pipeline = (server as any).pipeline;
    expect(pipeline.middlewares.length).toBe(3);
    expect(pipeline.middlewares[pipeline.middlewares.length - 1].constructor.name).toBe(
      'AnomalyDetector',
    );
  });

  it('replaces engine with dry-run middleware when dry_run is set', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).buildPipeline({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: true },
      rules: [],
    });
    const pipeline = (server as any).pipeline;
    expect(pipeline.middlewares.length).toBe(2);
  });

  it('sets approvalWorkflow when approvals config exists', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).buildPipeline({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      approvals: { default_timeout_ms: 60000, max_pending_approvals: 100 },
    });
    expect((server as any).approvalWorkflow).toBeDefined();
  });

  it('builds approver groups with Slack and Discord', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    vi.stubEnv('SLACK_WEBHOOK', 'https://hooks.slack.com/test');
    vi.stubEnv('DISCORD_WEBHOOK', 'https://discord.com/api/webhooks/test');
    (server as any).buildPipeline({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      approvals: {
        default_timeout_ms: 60000,
        max_pending_approvals: 100,
        approver_groups: {
          slack_team: { type: 'slack', webhook_url_env: 'SLACK_WEBHOOK' },
          discord_ops: { type: 'discord', webhook_url_env: 'DISCORD_WEBHOOK' },
        },
      },
    });
    expect((server as any).approvalWorkflow).toBeDefined();
  });
});

describe('MCPProxyServer internals', () => {
  it('forwardToUpstream writes to upstream stdin', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const mockStdin = { write: vi.fn() };
    (server as any).upstreamConnections = [{ process: { stdin: mockStdin } }];
    (server as any).forwardToUpstream('{"jsonrpc":"2.0"}');
    expect(mockStdin.write).toHaveBeenCalledWith('{"jsonrpc":"2.0"}\n');
  });

  it('forwardToUpstream skips connections without stdin', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const mockStdin = { write: vi.fn() };
    (server as any).upstreamConnections = [{ process: {} }, { process: { stdin: mockStdin } }];
    (server as any).forwardToUpstream('{"jsonrpc":"2.0"}');
    expect(mockStdin.write).toHaveBeenCalledTimes(1);
  });

  it('sendToAgent writes to stdout', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    (server as any).sendToAgent({ jsonrpc: '2.0', result: 'ok' });
    expect(writeSpy).toHaveBeenCalledWith('{"jsonrpc":"2.0","result":"ok"}\n');
    writeSpy.mockRestore();
  });

  it('getUpstreamForTool returns first connection when only one', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const conn = { process: {}, backend: { name: 'test' } };
    (server as any).upstreamConnections = [conn];
    expect((server as any).getUpstreamForTool('any')).toBe(conn);
  });

  it('getUpstreamForTool selects by tool pattern', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const connA = { process: {}, backend: { name: 'a', tool_patterns: ['write_*'] } };
    const connB = { process: {}, backend: { name: 'b' } };
    (server as any).upstreamConnections = [connA, connB];
    expect((server as any).getUpstreamForTool('write_file')).toBe(connA);
    expect((server as any).getUpstreamForTool('read_file')).toBe(connB);
  });

  it('handleUpstreamMessage resolves pending responses', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const resolveFn = vi.fn();
    (server as any).pendingResponses.set(42, resolveFn);
    (server as any).handleUpstreamMessage(JSON.stringify({ jsonrpc: '2.0', id: 42, result: 'ok' }));
    expect(resolveFn).toHaveBeenCalledWith({ jsonrpc: '2.0', id: 42, result: 'ok' });
  });

  it('handleUpstreamMessage logs on invalid JSON', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const errorSpy = vi.spyOn((server as any).logger, 'error').mockImplementation(() => {});
    (server as any).handleUpstreamMessage('not json');
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it('handleUpstreamMessage logs on schema validation failure', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const errorSpy = vi.spyOn((server as any).logger, 'error').mockImplementation(() => {});
    (server as any).handleUpstreamMessage('"just a string"');
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it('handleUpstreamMessage updates schemaValidator on tools/list', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const updateSpy = vi.fn();
    (server as any).schemaValidator = { updateSchemas: updateSpy };
    (server as any).handleUpstreamMessage(
      JSON.stringify({ jsonrpc: '2.0', result: { tools: [{ name: 'test_tool' }] } }),
    );
    expect(updateSpy).toHaveBeenCalledWith([{ name: 'test_tool' }]);
  });

  it('handleUpstreamMessage sends non-matching messages to agent', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    (server as any).handleUpstreamMessage(
      JSON.stringify({ jsonrpc: '2.0', result: { random: 'data' } }),
    );
    expect(writeSpy).toHaveBeenCalled();
    writeSpy.mockRestore();
  });

  it('forwardToUpstreamAndWait rejects when too many pending responses', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).pendingResponses = new Map();
    for (let i = 0; i < 10000; i++) {
      (server as any).pendingResponses.set(i, vi.fn());
    }
    const mockProcess = { stdin: { write: vi.fn() } };
    await expect(
      (server as any).forwardToUpstreamAndWait('{"jsonrpc":"2.0","id":1}', 1, mockProcess),
    ).rejects.toThrow('Too many pending requests');
  });

  it('globMatch matches wildcard patterns', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    expect((server as any).globMatch('write_*', 'write_file')).toBe(true);
    expect((server as any).globMatch('write_*', 'read_file')).toBe(false);
    expect((server as any).globMatch('*', 'anything')).toBe(true);
  });

  it('makeErrorResponse creates error with data', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const error = (server as any).makeErrorResponse(1, -32000, 'test error', { extra: 'info' });
    expect(error).toEqual({
      jsonrpc: '2.0',
      id: 1,
      error: { code: -32000, message: 'test error', data: { extra: 'info' } },
    });
  });

  it('makeErrorResponse handles null id', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const error = (server as any).makeErrorResponse(null, -32700, 'parse error');
    expect(error.id).toBeNull();
    expect(error.error.data).toBeUndefined();
  });

  it('getUpstreamForTool returns default when no pattern matches', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const connA = { process: {}, backend: { name: 'a', tool_patterns: ['write_*'] } };
    const connB = { process: {}, backend: { name: 'b', tool_patterns: [] } };
    (server as any).upstreamConnections = [connA, connB];
    expect((server as any).getUpstreamForTool('read_file')).toBe(connB);
  });

  it('getUpstreamForTool returns first connection when only one (ignoring patterns)', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const conn = { process: {}, backend: { name: 'a', tool_patterns: ['write_*'] } };
    (server as any).upstreamConnections = [conn];
    expect((server as any).getUpstreamForTool('read_file')).toBe(conn);
  });

  it('getUpstreamForTool returns undefined when no match among multiple and no default', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).upstreamConnections = [
      { process: {}, backend: { name: 'a', tool_patterns: ['write_*'] } },
      { process: {}, backend: { name: 'b', tool_patterns: ['delete_*'] } },
    ];
    expect((server as any).getUpstreamForTool('read_file')).toBeUndefined();
  });

  it('globMatch handles exact match without wildcard', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    expect((server as any).globMatch('exact_tool', 'exact_tool')).toBe(true);
    expect((server as any).globMatch('exact_tool', 'other')).toBe(false);
  });

  it('forwardToUpstreamAndWait writes to upstream and resolves', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const mockStdin = { write: vi.fn() };
    const mockProcess = { stdin: mockStdin };
    const resultPromise = (server as any).forwardToUpstreamAndWait(
      JSON.stringify({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'test' } }),
      1,
      mockProcess,
    );
    const pendingKey = 1;
    const pendingResolve = (server as any).pendingResponses.get(pendingKey);
    expect(pendingResolve).toBeDefined();
    pendingResolve({ jsonrpc: '2.0', result: 'ok' });
    const result = await resultPromise;
    expect(result).toEqual({ jsonrpc: '2.0', result: 'ok', id: 1 });
    expect(mockStdin.write).toHaveBeenCalled();
  });

  it('forwardToUpstreamAndWait handles stdin write error', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const mockStdin = {
      write: vi.fn(() => {
        throw new Error('stream closed');
      }),
    };
    const mockProcess = { stdin: mockStdin };
    await expect(
      (server as any).forwardToUpstreamAndWait('{"jsonrpc":"2.0","id":1}', 1, mockProcess),
    ).rejects.toThrow('Failed to forward request');
  });

  it('forwardToUpstreamAndWait handles invalid JSON', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const mockProcess = { stdin: { write: vi.fn() } };
    await expect(
      (server as any).forwardToUpstreamAndWait('not json', 1, mockProcess),
    ).rejects.toThrow('Invalid JSON');
  });

  it('sendToAgent logs error on write failure', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => {
      throw new Error('stdout error');
    });
    const errorSpy = vi.spyOn((server as any).logger, 'error').mockImplementation(() => {});
    (server as any).sendToAgent({ test: true });
    expect(errorSpy).toHaveBeenCalled();
    writeSpy.mockRestore();
    errorSpy.mockRestore();
  });

  it('handleUpstreamMessage forwards result messages without tools to agent', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    (server as any).handleUpstreamMessage(
      JSON.stringify({ jsonrpc: '2.0', result: { someData: true } }),
    );
    expect(writeSpy).toHaveBeenCalled();
    writeSpy.mockRestore();
  });

  it('handleUpstreamMessage forwards messages with unmatched id to agent', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    (server as any).handleUpstreamMessage(
      JSON.stringify({ jsonrpc: '2.0', id: 999, result: 'done' }),
    );
    expect(writeSpy).toHaveBeenCalled();
    writeSpy.mockRestore();
  });

  it('handleUpstreamMessage sends tools/list result to agent when no schemaValidator', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    (server as any).handleUpstreamMessage(
      JSON.stringify({ jsonrpc: '2.0', result: { tools: [{ name: 't' }] } }),
    );
    expect(writeSpy).toHaveBeenCalled();
    writeSpy.mockRestore();
  });

  it('startUpstreams spawns processes for configured backends', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    await (server as any).startUpstreams({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      upstreams: [{ name: 'test-backend', command: 'echo', args: ['hello'] }],
    });
    expect((server as any).upstreamConnections).toHaveLength(1);
    expect((server as any).upstreamConnections[0].backend.name).toBe('test-backend');
  });

  it('startUpstreams spawns for legacy upstreamCommand', async () => {
    const server = new MCPProxyServer({
      policyPath: testPolicyPath,
      upstreamCommand: 'node',
      upstreamArgs: ['server.js'],
    });
    await (server as any).startUpstreams({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
    });
    expect((server as any).upstreamConnections).toHaveLength(1);
    expect((server as any).upstreamConnections[0].backend.name).toBe('default');
  });

  it('startUpstreams spawns with backend env vars', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    await (server as any).startUpstreams({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      upstreams: [{ name: 'test', command: 'echo', env: { FOO: 'bar' } }],
    });
    expect((server as any).upstreamConnections).toHaveLength(1);
  });

  it('startMetricsServer creates a metrics HTTP server', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    (server as any).startMetricsServer({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      metrics: { enabled: true, port: 0, bind_host: '127.0.0.1' },
    });
    expect((server as any).metricsServer).toBeDefined();
    await new Promise<void>((resolve) => (server as any).metricsServer?.close(() => resolve()));
  });

  it('startMetricsServer does nothing when metrics disabled', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).startMetricsServer({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
    });
    expect((server as any).metricsServer).toBeUndefined();
  });

  it('startHttpTransport creates an HTTP server', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    (server as any).startHttpTransport({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      transports: { http: { enabled: true, port: 0, bind_host: '127.0.0.1' } },
    });
    expect((server as any).httpServer).toBeDefined();
    await new Promise((r) => setTimeout(r, 50));
    await new Promise<void>((resolve) => (server as any).httpServer?.close(() => resolve()));
  });

  it('startHttpTransport does nothing when http transport disabled', () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).startHttpTransport({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
    });
    expect((server as any).httpServer).toBeUndefined();
  });

  it('HTTP transport handles POST with JSON-RPC request', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    (server as any).pipeline.register({
      execute: async () => ({ action: 'BLOCK', reason: 'policy blocked' }),
    });
    (server as any).startHttpTransport({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      transports: { http: { enabled: true, port: 0, bind_host: '127.0.0.1' } },
    });
    await new Promise((r) => setTimeout(r, 50));
    const addr = (server as any).httpServer.address();
    const port = addr.port;
    const http = await import('node:http');
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'test', arguments: {} },
    });
    const response = await new Promise<string>((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        },
        (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => resolve(data));
        },
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    });
    expect(response).toContain('blocked');
    await new Promise<void>((resolve) => (server as any).httpServer?.close(() => resolve()));
  });

  it('HTTP transport returns 204 for notifications', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    (server as any).startHttpTransport({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      transports: { http: { enabled: true, port: 0, bind_host: '127.0.0.1' } },
    });
    await new Promise((r) => setTimeout(r, 50));
    const port = (server as any).httpServer.address().port;
    const http = await import('node:http');
    const statusCode = await new Promise<number>((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        },
        (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        },
      );
      req.on('error', reject);
      req.write(JSON.stringify({ jsonrpc: '2.0', method: 'initialize', params: {} }));
      req.end();
    });
    expect(statusCode).toBe(204);
    await new Promise<void>((resolve) => (server as any).httpServer?.close(() => resolve()));
  });

  it('HTTP transport GET /health returns stats', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    (server as any).startHttpTransport({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      transports: { http: { enabled: true, port: 0, bind_host: '127.0.0.1' } },
    });
    await new Promise((r) => setTimeout(r, 50));
    const port = (server as any).httpServer.address().port;
    const http = await import('node:http');
    const response = await new Promise<string>((resolve, reject) => {
      const req = http.request(
        { hostname: '127.0.0.1', port, method: 'GET', path: '/health' },
        (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => resolve(data));
        },
      );
      req.on('error', reject);
      req.end();
    });
    expect(response).toContain('ok');
    await new Promise<void>((resolve) => (server as any).httpServer?.close(() => resolve()));
  });

  it('HTTP transport returns 405 for unsupported methods', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    (server as any).startHttpTransport({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      transports: { http: { enabled: true, port: 0, bind_host: '127.0.0.1' } },
    });
    await new Promise((r) => setTimeout(r, 50));
    const port = (server as any).httpServer.address().port;
    const http = await import('node:http');
    const statusCode = await new Promise<number>((resolve, reject) => {
      const req = http.request({ hostname: '127.0.0.1', port, method: 'PUT' }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.on('error', reject);
      req.end();
    });
    expect(statusCode).toBe(405);
    await new Promise<void>((resolve) => (server as any).httpServer?.close(() => resolve()));
  });

  it('startPolicyWatcher creates a file watcher', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    (server as any).startPolicyWatcher();
    expect((server as any).policyWatcher).toBeDefined();
    (server as any).policyWatcher?.close();
  });

  it('startPolicyWatcher handles errors', () => {
    const server = new MCPProxyServer({ policyPath: '/dev/null/nonexistent' });
    (server as any).startPolicyWatcher();
    expect((server as any).policyWatcher).toBeUndefined();
  });

  it('startApprovalServer returns early without approval config', () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    (server as any).startApprovalServer({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
    });
    expect((server as any).approvalServer).toBeUndefined();
  });

  it('startApprovalServer throws when workflow not initialized', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath, approvalPort: 9999 });
    await expect(
      (server as any).startApprovalServer({
        version: '1.0',
        settings: {
          read_only: false,
          default_action: 'block',
          audit_level: 'full',
          dry_run: false,
        },
        rules: [],
        approvals: { default_timeout_ms: 60000, max_pending_approvals: 100 },
      }),
    ).rejects.toThrow('Approval workflow not initialized');
  });

  it('startApprovalServer throws when approval_api missing', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath, approvalPort: 9999 });
    (server as any).approvalWorkflow = { stop: vi.fn() };
    await expect(
      (server as any).startApprovalServer({
        version: '1.0',
        settings: {
          read_only: false,
          default_action: 'block',
          audit_level: 'full',
          dry_run: false,
        },
        rules: [],
        approvals: { default_timeout_ms: 60000, max_pending_approvals: 100 },
      }),
    ).rejects.toThrow('approval_api');
  });

  it('startApprovalServer throws when token env not set', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath, approvalPort: 9999 });
    (server as any).approvalWorkflow = { stop: vi.fn() };
    await expect(
      (server as any).startApprovalServer({
        version: '1.0',
        settings: {
          read_only: false,
          default_action: 'block',
          audit_level: 'full',
          dry_run: false,
        },
        rules: [],
        approvals: { default_timeout_ms: 60000, max_pending_approvals: 100 },
        approval_api: { token_env: 'MISSING_TOKEN_VAR', bind_host: '127.0.0.1' },
      }),
    ).rejects.toThrow('token env var');
  });

  it('startApprovalServer creates server when configured properly', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath, approvalPort: 9876 });
    vi.stubEnv('TEST_APPROVAL_TOKEN', 'secret-value');
    (server as any).approvalWorkflow = { stop: vi.fn() };
    await (server as any).startApprovalServer({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      approvals: { default_timeout_ms: 60000, max_pending_approvals: 100 },
      approval_api: { token_env: 'TEST_APPROVAL_TOKEN', bind_host: '127.0.0.1' },
    });
    expect((server as any).approvalServer).toBeDefined();
    await new Promise((r) => setTimeout(r, 50));
    await new Promise<void>((resolve) => (server as any).approvalServer?.close(() => resolve()));
  });

  it('startApprovalServer getStats callback works', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).approvalWorkflow = { stop: vi.fn() };
    const getStatsFn = (server as any).getStats.bind(server);
    const stats = getStatsFn();
    expect(stats).toHaveProperty('uptime');
  });
});

describe('MCPProxyServer.upstream event handlers', () => {
  beforeEach(() => {
    Object.keys(spawnCallbacks).forEach((k) => {
      delete spawnCallbacks[k];
    });
  });

  it('handles process error event from spawned upstream', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    await (server as any).startUpstreams({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      upstreams: [{ name: 'test-backend', command: 'echo' }],
    });
    const errHandler = spawnCallbacks.error;
    expect(errHandler).toBeDefined();
    errHandler(new Error('spawn failed'));
  });

  it('handles process exit event from spawned upstream', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    await (server as any).startUpstreams({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      upstreams: [{ name: 'test-backend', command: 'echo' }],
    });
    const exitHandler = spawnCallbacks.exit;
    expect(exitHandler).toBeDefined();
    exitHandler(1);
  });

  it('handles stderr data from spawned upstream', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    await (server as any).startUpstreams({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      upstreams: [{ name: 'test-backend', command: 'echo' }],
    });
    const stderrHandler = spawnCallbacks.data;
    expect(stderrHandler).toBeDefined();
    stderrHandler(Buffer.from('error output'));
  });

  it('startUpstreams readline handler processes upstream output (backends path)', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath });
    await (server as any).startUpstreams({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
      upstreams: [{ name: 'test-backend', command: 'echo' }],
    });
    const lineHandler = rlCallbacks.line;
    expect(lineHandler).toBeDefined();
    lineHandler('{"jsonrpc":"2.0","id":1,"result":"ok"}');
  });

  it('startUpstreams readline handler processes upstream output (legacy path)', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath, upstreamCommand: 'echo' });
    await (server as any).startUpstreams({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
    });
    const lineHandler = rlCallbacks.line;
    if (lineHandler) {
      lineHandler('{"jsonrpc":"2.0","id":2,"result":"ok"}');
    }
  });

  it('handles process error event from legacy upstream', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath, upstreamCommand: 'echo' });
    await (server as any).startUpstreams({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
    });
    const errHandler = spawnCallbacks.error;
    expect(errHandler).toBeDefined();
    errHandler(new Error('legacy spawn failed'));
  });

  it('handles process exit event from legacy upstream', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath, upstreamCommand: 'echo' });
    await (server as any).startUpstreams({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
    });
    const exitHandler = spawnCallbacks.exit;
    expect(exitHandler).toBeDefined();
    exitHandler(1);
  });

  it('handles stderr data from legacy upstream', async () => {
    const server = new MCPProxyServer({ policyPath: testPolicyPath, upstreamCommand: 'echo' });
    await (server as any).startUpstreams({
      version: '1.0',
      settings: { read_only: false, default_action: 'block', audit_level: 'full', dry_run: false },
      rules: [],
    });
    const stderrHandler = spawnCallbacks.data;
    expect(stderrHandler).toBeDefined();
    stderrHandler(Buffer.from('legacy error output'));
  });
});

describe('MCPProxyServer.startStdioListener', () => {
  it('processes stdin lines through the pipeline', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).pipeline.register({
      execute: async () => ({ action: 'BLOCK', reason: 'blocked' }),
    });
    (server as any).startStdioListener();
    const lineHandler = rlCallbacks.line;
    expect(lineHandler).toBeDefined();
    lineHandler(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'test', arguments: {} },
      }),
    );
  });

  it('startStdioListener catch handles downstream rejection', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const errorSpy = vi.spyOn((server as any).logger, 'error').mockImplementation(() => {});
    const rejectPromise = Promise.reject(new Error('intentional rejection'));
    vi.spyOn(server as any, 'handleDownstreamMessage').mockReturnValue(rejectPromise);
    (server as any).startStdioListener();
    const lineHandler = rlCallbacks.line;
    expect(lineHandler).toBeDefined();
    lineHandler('test');
    await new Promise((r) => setTimeout(r, 10));
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it('forwardToUpstreamAndWait timeout fires', async () => {
    vi.useFakeTimers();
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const mockProcess = { stdin: { write: vi.fn() } };
    const promise = (server as any).forwardToUpstreamAndWait(
      '{"jsonrpc":"2.0","id":1}',
      1,
      mockProcess,
    );
    vi.advanceTimersByTime(30000);
    await expect(promise).rejects.toThrow('Upstream timeout');
    vi.useRealTimers();
  });
});

describe('MCPProxyServer error handling', () => {
  it('handles FirewallError thrown from pipeline', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).pipeline.register({
      execute: async () => {
        throw new FirewallError({
          code: 'INTERNAL_ERROR',
          message: 'firewall error',
          requestId: 'req-1',
        });
      },
    });
    const response = await server.processFrame(JSON.stringify(toolCall(1)));
    expect(response).not.toBeNull();
    expect((response as any).error?.code).toBe(-32000);
    expect((response as any).error?.data?.request_id).toMatch(/^req_/);
  });

  it('handles RateLimitError with retry_after_ms', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).pipeline.register({
      execute: async () => {
        throw new RateLimitError({ message: 'rate limited', retryAfterMs: 5000 });
      },
    });
    const response = await server.processFrame(JSON.stringify(toolCall(1)));
    expect(response).not.toBeNull();
    expect((response as any).error?.data?.retry_after_ms).toBe(5000);
  });

  it('handles ApprovalRequiredError thrown from pipeline', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).pipeline.register({
      execute: async () => {
        throw new ApprovalRequiredError({
          message: 'needs approval',
          requestId: 'req-1',
          approvalId: 'app-456',
        });
      },
    });
    const response = await server.processFrame(JSON.stringify(toolCall(1)));
    expect(response).not.toBeNull();
    expect((response as any).error?.data?.approval_id).toBe('app-456');
  });

  it('handles session_id truncation for long session IDs', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).policyConfig = { version: '1.0', settings: {}, rules: [] };
    (server as any).pipeline.register({
      execute: async () => ({ action: 'CONTINUE' }),
    });
    (server as any).upstreamConnections = [
      { process: { stdin: { write: vi.fn() }, killed: false }, backend: { name: 'test' } },
    ];
    (server as any).forwardToUpstreamAndWait = vi
      .fn()
      .mockResolvedValue({ jsonrpc: '2.0', result: {} });
    const longSession = 'a'.repeat(200);
    const msg = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'test', _meta: { sessionId: longSession }, arguments: {} },
    };
    const response = await server.processFrame(JSON.stringify(msg));
    expect(response).not.toBeNull();
    expect((response as any).result).toBeDefined();
  });

  it('extracts bypass_token from _meta', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    const ctxSpy = vi.fn();
    (server as any).pipeline.register({
      execute: async (ctx: any) => {
        ctxSpy(ctx.metadata.get('bypass_token'));
        return { action: 'CONTINUE' };
      },
    });
    (server as any).upstreamConnections = [
      { process: { stdin: { write: vi.fn() }, killed: false }, backend: { name: 'test' } },
    ];
    (server as any).forwardToUpstreamAndWait = vi
      .fn()
      .mockResolvedValue({ jsonrpc: '2.0', result: {} });
    const msg = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'test', _meta: { bypass_token: 'tok-123' }, arguments: {} },
    };
    await server.processFrame(JSON.stringify(msg));
    expect(ctxSpy).toHaveBeenCalledWith('tok-123');
  });

  it('handleDownstreamMessage processes and sends response to agent', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).pipeline.register({
      execute: async () => ({ action: 'BLOCK', reason: 'blocked' }),
    });
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    await (server as any).handleDownstreamMessage(JSON.stringify(toolCall(1)));
    expect(writeSpy).toHaveBeenCalledWith(expect.stringContaining('blocked'));
    writeSpy.mockRestore();
  });

  it('handleDownstreamMessage does nothing when processFrame returns null', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).pipeline.register({
      execute: async () => ({ action: 'CONTINUE' }),
    });
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    await (server as any).handleDownstreamMessage(
      JSON.stringify({ jsonrpc: '2.0', method: 'initialize', params: {} }),
    );
    expect(writeSpy).not.toHaveBeenCalled();
    writeSpy.mockRestore();
  });

  it('makes request with _meta.bypass_token in context', async () => {
    const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
    (server as any).pipeline.register({
      execute: async () => ({ action: 'CONTINUE' }),
    });
    (server as any).upstreamConnections = [
      { process: { stdin: { write: vi.fn() }, killed: false }, backend: { name: 'test' } },
    ];
    (server as any).forwardToUpstreamAndWait = vi
      .fn()
      .mockResolvedValue({ jsonrpc: '2.0', result: {} });
    const msg = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'test', _meta: { bypass_token: 'tok-123' }, arguments: {} },
    };
    const response = await server.processFrame(JSON.stringify(msg));
    expect(response).toBeDefined();
  });
});
