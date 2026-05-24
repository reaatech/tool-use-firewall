import type { RequestContext } from '@reaatech/tool-use-firewall-core';
import { beforeEach, describe, expect, it } from 'vitest';
import { MCPProxyServer } from './server.js';

/** Build a server with a pipeline that blocks every tools/call, so we can
 * exercise frame/batch handling without spawning a real upstream. */
function blockingServer(): MCPProxyServer {
  const server = new MCPProxyServer({ policyPath: 'unused.yaml' });
  // biome-ignore lint/suspicious/noExplicitAny: reaching into privates for a focused unit test
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
});
