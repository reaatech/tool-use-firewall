import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it } from 'vitest';
import { ArgumentValidator } from './validator.js';

describe('ArgumentValidator', () => {
  it('passes through when no rules match', async () => {
    const validator = new ArgumentValidator([]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { query: 'SELECT 1' },
    });
    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('blocks shell dangerous sequences', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'shell_safe', tools: ['shell'], argument: 'cmd' },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'shell',
      arguments: { cmd: 'ls; rm -rf /' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow('Contains dangerous shell sequence');
  });

  it('passes through when no toolName', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'shell_safe', tools: ['shell'], argument: 'cmd' },
    ]);
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call' });
    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('passes through when no arguments', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'shell_safe', tools: ['shell'], argument: 'cmd' },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'shell',
    });
    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('sql_safe type with SQLValidator delegation blocks dangerous SQL', async () => {
    const validator = new ArgumentValidator(
      [{ id: 'r1', type: 'sql_safe', tools: ['db'], argument: 'query' }],
      {
        blocked_patterns: [{ pattern: 'DROP\\s+TABLE', message: 'DROP TABLE blocked' }],
        injection_patterns: [],
      },
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db',
      arguments: { query: 'DROP TABLE users' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow('DROP TABLE blocked');
  });

  it('sql_safe type without SQLValidator uses built-in patterns', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'sql_safe', tools: ['db'], argument: 'query' },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db',
      arguments: { query: 'DROP TABLE users' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow('Blocked by SQL pattern');
  });

  it('sql_safe passes safe queries', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'sql_safe', tools: ['db'], argument: 'query' },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db',
      arguments: { query: 'SELECT * FROM users' },
    });
    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('sql_safe non-string value passes', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'sql_safe', tools: ['db'], argument: 'query' },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db',
      arguments: { query: 42 },
    });
    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('shell_safe blocks all dangerous characters', async () => {
    const dangerous = [';', '&&', '||', '|', '`', '$(', '${'];
    for (const seq of dangerous) {
      const validator = new ArgumentValidator([
        { id: 'r1', type: 'shell_safe', tools: ['shell'], argument: 'cmd' },
      ]);
      const ctx = createRequestContext({
        requestId: '1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'shell',
        arguments: { cmd: `ls ${seq} rm` },
      });
      await expect(validator.execute(ctx)).rejects.toThrow('Contains dangerous shell sequence');
    }
  });

  it('shell_safe passes safe strings', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'shell_safe', tools: ['shell'], argument: 'cmd' },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'shell',
      arguments: { cmd: 'ls -la /tmp' },
    });
    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('shell_safe non-string value passes', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'shell_safe', tools: ['shell'], argument: 'cmd' },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'shell',
      arguments: { cmd: ['ls'] },
    });
    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('regex type matches pattern on argument value', async () => {
    const validator = new ArgumentValidator([
      {
        id: 'r1',
        type: 'regex',
        tools: ['test'],
        argument: 'val',
        patterns: [{ pattern: 'badword', message: 'Bad word detected' }],
      },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'contains badword here' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow('Bad word detected');
  });

  it('regex type passes when no match', async () => {
    const validator = new ArgumentValidator([
      {
        id: 'r1',
        type: 'regex',
        tools: ['test'],
        argument: 'val',
        patterns: [{ pattern: 'badword', message: 'Bad word detected' }],
      },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'safe content' },
    });
    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('regex type handles non-string value', async () => {
    const validator = new ArgumentValidator([
      {
        id: 'r1',
        type: 'regex',
        tools: ['test'],
        argument: 'val',
        patterns: [{ pattern: 'bad', message: 'bad' }],
      },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 123 },
    });
    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('regex type handles invalid pattern', async () => {
    const validator = new ArgumentValidator([
      {
        id: 'r1',
        type: 'regex',
        tools: ['test'],
        argument: 'val',
        patterns: [{ pattern: '[invalid', message: 'bad' }],
      },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'test' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow('Invalid regex pattern');
  });

  it('matchesTool with glob patterns', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'shell_safe', tools: ['db_*'], argument: 'cmd' },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
      arguments: { cmd: 'ls; rm' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow('Contains dangerous shell sequence');
  });

  it('matchesTool with empty tools list matches all', async () => {
    const validator = new ArgumentValidator([{ id: 'r1', type: 'sql_safe', argument: 'query' }]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'any_tool',
      arguments: { query: 'DROP TABLE users' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow('Blocked by SQL pattern');
  });

  it('multiple rules - first matching rule blocks', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'shell_safe', tools: ['tool1'], argument: 'cmd' },
      {
        id: 'r2',
        type: 'regex',
        tools: ['tool2'],
        argument: 'val',
        patterns: [{ pattern: 'bad', message: 'Blocked by r2' }],
      },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool2',
      arguments: { val: 'bad content' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow('Blocked by r2');
  });

  it('blocks DELETE FROM without WHERE via sql_safe', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'sql_safe', tools: ['db'], argument: 'query' },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db',
      arguments: { query: 'DELETE FROM users' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow('Blocked by SQL pattern');
  });

  it('blocks UNION SELECT', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'sql_safe', tools: ['db'], argument: 'query' },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db',
      arguments: { query: 'SELECT * FROM users UNION SELECT * FROM admins' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow('Blocked by SQL pattern');
  });

  it('matchesTool with invalid glob falls back to exact match', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'shell_safe', tools: ['*(((((((((((inval)))))))))))'], argument: 'cmd' },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'nonexistent',
      arguments: { cmd: 'ls; rm' },
    });
    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('rule without argument field matches all args', async () => {
    const validator = new ArgumentValidator([{ id: 'r1', type: 'shell_safe', tools: ['test'] }]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { cmd: 'safe command' },
    });
    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });
});
