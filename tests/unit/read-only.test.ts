import { describe, it, expect } from 'vitest';
import { ReadOnlyCheck } from '../../src/policies/read-only.js';
import { createRequestContext } from '../../src/middleware/context.js';
import { PolicyViolationError } from '../../src/utils/errors.js';

describe('ReadOnlyCheck', () => {
  it('should allow all operations when disabled', async () => {
    const check = new ReadOnlyCheck({ enabled: false });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_write',
      arguments: { path: '/tmp/test.txt' },
    });

    await expect(check.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should block write operations when enabled', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_write',
      arguments: { path: '/tmp/test.txt' },
    });

    await expect(check.execute(ctx)).rejects.toThrow(PolicyViolationError);
  });

  it('should allow read operations when enabled', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_read',
      arguments: { path: '/tmp/test.txt' },
    });

    await expect(check.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should block SQL write operations', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'INSERT INTO users VALUES (1)' },
    });

    await expect(check.execute(ctx)).rejects.toThrow(PolicyViolationError);
  });

  it('should allow SQL read operations', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users' },
    });

    await expect(check.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should allow exceptions when configured', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          tools: ['database_execute'],
          conditions: [{ argument: 'query', pattern: '^SELECT\\s+', flags: 'i' }],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users' },
    });

    await expect(check.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should allow when arguments are missing', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_write',
    });
    await expect(check.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should allow exception without tools array to match any tool', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          conditions: [{ argument: 'query', pattern: '^SELECT\\s+', flags: 'i' }],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users' },
    });
    await expect(check.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should not match exception when condition value is non-string', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          tools: ['database_execute'],
          conditions: [{ argument: 'query', pattern: '^SELECT\\s+', flags: 'i' }],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 123 },
    });
    await expect(check.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should not match exception when not all conditions match', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          tools: ['database_execute'],
          conditions: [
            { argument: 'query', pattern: '^SELECT\\s+', flags: 'i' },
            { argument: 'table', pattern: '^users$', flags: 'i' },
          ],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users', table: 'admins' },
    });
    await expect(check.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should detect write operations by tool name', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'my_create_tool',
      arguments: {},
    });
    await expect(check.execute(ctx)).rejects.toThrow(PolicyViolationError);
  });

  it('should detect SQL write operations via query argument', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'sql_runner',
      arguments: { query: 'INSERT INTO users VALUES (1)' },
    });
    await expect(check.execute(ctx)).rejects.toThrow(PolicyViolationError);
  });
});
