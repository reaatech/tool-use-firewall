import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it, vi } from 'vitest';
import { ReadOnlyCheck } from './read-only.js';

describe('ReadOnlyCheck', () => {
  it('passes through when disabled', async () => {
    const check = new ReadOnlyCheck({ enabled: false });
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call' });
    const result = await check.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('blocks write operations', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'delete_record',
      arguments: {},
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('passes non-write tool', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read_data',
      arguments: {},
    });
    const result = await check.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('passes through when no toolName', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call' });
    const result = await check.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('bypasses with valid token from env', async () => {
    vi.stubEnv('READ_ONLY_BYPASS', 'super-secret-token');
    const check = new ReadOnlyCheck({ enabled: true, bypassTokenEnv: 'READ_ONLY_BYPASS' });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'delete_record',
      arguments: {},
    });
    ctx.metadata.set('bypass_token', 'super-secret-token');
    const result = await check.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.readOnlyBypassed).toBe(true);
    vi.unstubAllEnvs();
  });

  it('does not bypass with wrong token', async () => {
    vi.stubEnv('READ_ONLY_BYPASS', 'real-token');
    const check = new ReadOnlyCheck({ enabled: true, bypassTokenEnv: 'READ_ONLY_BYPASS' });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'delete_record',
      arguments: {},
    });
    ctx.metadata.set('bypass_token', 'wrong-token');
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
    vi.unstubAllEnvs();
  });

  it('does not bypass when bypass_token is not a string', async () => {
    vi.stubEnv('READ_ONLY_BYPASS', 'token');
    const check = new ReadOnlyCheck({ enabled: true, bypassTokenEnv: 'READ_ONLY_BYPASS' });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'delete_record',
      arguments: {},
    });
    ctx.metadata.set('bypass_token', 123);
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
    vi.unstubAllEnvs();
  });

  it('bypass token env not set skips bypass', async () => {
    const check = new ReadOnlyCheck({ enabled: true, bypassTokenEnv: 'MISSING_VAR' });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'delete_record',
      arguments: {},
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('exception matches by tool and condition', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          tools: ['read_tool'],
          conditions: [{ argument: 'path', pattern: '^/safe/', flags: '' }],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read_tool',
      arguments: { path: '/safe/foo' },
    });
    const result = await check.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('exception does not match wrong tool', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          tools: ['allowed_tool'],
          conditions: [{ argument: 'path', pattern: '^/safe/', flags: '' }],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'write_tool',
      arguments: { path: '/safe/foo' },
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('exception requires all conditions to match', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          conditions: [
            { argument: 'path', pattern: '^/safe/', flags: '' },
            { argument: 'method', pattern: '^GET$', flags: '' },
          ],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'write_tool',
      arguments: { path: '/safe/foo', method: 'POST' },
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('exception handles non-string argument value', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          conditions: [{ argument: 'count', pattern: '\\d+', flags: '' }],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'write_tool',
      arguments: { count: 42 },
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('exception handles invalid regex pattern gracefully', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          conditions: [{ argument: 'path', pattern: '[invalid', flags: '' }],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'write_tool',
      arguments: { path: '/safe/foo' },
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('multiple exceptions - first matches', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          tools: ['write_tool'],
          conditions: [{ argument: 'path', pattern: '^/safe/', flags: '' }],
        },
        {
          tools: ['other_tool'],
          conditions: [{ argument: 'path', pattern: '^/also/', flags: '' }],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'write_tool',
      arguments: { path: '/safe/data' },
    });
    const result = await check.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('detects write operation via SQL query arg', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read_tool',
      arguments: { query: 'INSERT INTO users VALUES (1)' },
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('detects write operation via UPDATE in query arg', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read_tool',
      arguments: { query: 'UPDATE users SET name = "foo"' },
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('detects write operation via DELETE in query arg', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read_tool',
      arguments: { query: 'DELETE FROM users' },
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('detects write operation via ALTER in query arg', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read_tool',
      arguments: { query: 'ALTER TABLE users ADD COLUMN x INT' },
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('detects write operation via DROP in query arg', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read_tool',
      arguments: { query: 'DROP TABLE users' },
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('detects write operation via CREATE in query arg', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read_tool',
      arguments: { query: 'CREATE TABLE users (id INT)' },
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('non-write query arg passes through', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read_tool',
      arguments: { query: 'SELECT * FROM users' },
    });
    const result = await check.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('non-string query arg does not trigger SQL check', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read_tool',
      arguments: { query: 123 },
    });
    const result = await check.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('detects write via tool name containing write', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'write_document',
      arguments: { content: 'hello' },
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('detects write via tool name containing create', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'create_user',
      arguments: {},
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('detects write via tool name containing update', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'update_record',
      arguments: {},
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('detects write operation via TRUNCATE in query arg', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read_tool',
      arguments: { query: 'TRUNCATE TABLE users' },
    });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });
});
