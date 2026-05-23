import { describe, it, expect } from 'vitest';
import { createRequestContext } from './types.js';

describe('createRequestContext', () => {
  it('creates context with required fields', () => {
    const ctx = createRequestContext({
      requestId: 'req_1',
      sessionId: 'sess_1',
      method: 'tools/call',
      toolName: 'test_tool',
      arguments: { foo: 'bar' },
    });
    expect(ctx.requestId).toBe('req_1');
    expect(ctx.sessionId).toBe('sess_1');
    expect(ctx.method).toBe('tools/call');
    expect(ctx.toolName).toBe('test_tool');
    expect(ctx.arguments).toEqual({ foo: 'bar' });
    expect(ctx.receivedAt).toBeGreaterThan(0);
    expect(ctx.metadata).toBeInstanceOf(Map);
  });
});
