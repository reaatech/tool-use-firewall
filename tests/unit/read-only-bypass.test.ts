import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ReadOnlyCheck } from '../../src/policies/read-only.js';
import { createRequestContext } from '../../src/middleware/context.js';

describe('ReadOnlyCheck bypass token', () => {
  const originalEnv = process.env.BYPASS_TOKEN;

  beforeAll(() => {
    process.env.BYPASS_TOKEN = 'secret-emergency-token-123';
  });

  afterAll(() => {
    if (originalEnv !== undefined) {
      process.env.BYPASS_TOKEN = originalEnv;
    } else {
      delete process.env.BYPASS_TOKEN;
    }
  });

  it('should allow write operations with valid bypass token', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      bypassTokenEnv: 'BYPASS_TOKEN',
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_write',
      arguments: { path: '/tmp/test.txt' },
    });
    ctx.metadata.set('bypass_token', 'secret-emergency-token-123');

    const result = await check.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata).toEqual({ readOnlyBypassed: true });
  });

  it('should block write operations with invalid bypass token', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      bypassTokenEnv: 'BYPASS_TOKEN',
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_write',
      arguments: { path: '/tmp/test.txt' },
    });
    ctx.metadata.set('bypass_token', 'wrong-token');

    await expect(check.execute(ctx)).rejects.toThrow();
  });

  it('should block when bypass token env is not set', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      bypassTokenEnv: 'NONEXISTENT_TOKEN_VAR',
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_write',
      arguments: { path: '/tmp/test.txt' },
    });
    ctx.metadata.set('bypass_token', 'some-token');

    await expect(check.execute(ctx)).rejects.toThrow();
  });

  it('should block when no bypass token configured', async () => {
    const check = new ReadOnlyCheck({ enabled: true });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_write',
      arguments: { path: '/tmp/test.txt' },
    });
    ctx.metadata.set('bypass_token', 'some-token');

    await expect(check.execute(ctx)).rejects.toThrow();
  });
});
