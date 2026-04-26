import { describe, it, expect } from 'vitest';
import { ArgumentValidator } from '../../src/policies/validator.js';
import { createRequestContext } from '../../src/middleware/context.js';
import { ValidationError } from '../../src/utils/errors.js';
import type { ValidationRule } from '../../src/config/schema.js';

describe('ArgumentValidator', () => {
  const sqlRules: ValidationRule[] = [
    {
      id: 'sql_safe',
      type: 'sql_safe',
      tools: ['database_execute'],
      argument: 'query',
    },
  ];

  const regexRules: ValidationRule[] = [
    {
      id: 'no_drop',
      type: 'regex',
      tools: ['database_execute'],
      argument: 'query',
      patterns: [{ pattern: 'DROP\\s+TABLE', flags: 'i', message: 'DROP TABLE is not allowed' }],
    },
  ];

  const shellRules: ValidationRule[] = [
    {
      id: 'shell_safe',
      type: 'shell_safe',
      tools: ['shell_exec'],
      argument: 'command',
    },
  ];

  it('should block DROP TABLE via sql_safe validator', async () => {
    const validator = new ArgumentValidator(sqlRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'DROP TABLE users' },
    });

    await expect(validator.execute(ctx)).rejects.toThrow(ValidationError);
  });

  it('should allow safe SQL via sql_safe validator', async () => {
    const validator = new ArgumentValidator(sqlRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users' },
    });

    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should block shell metacharacters', async () => {
    const validator = new ArgumentValidator(shellRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'shell_exec',
      arguments: { command: 'rm -rf /; echo done' },
    });

    await expect(validator.execute(ctx)).rejects.toThrow(ValidationError);
  });

  it('should allow safe shell commands', async () => {
    const validator = new ArgumentValidator(shellRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'shell_exec',
      arguments: { command: 'echo hello' },
    });

    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should match regex patterns', async () => {
    const validator = new ArgumentValidator(regexRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'DROP TABLE users' },
    });

    await expect(validator.execute(ctx)).rejects.toThrow(ValidationError);
  });

  it('should skip validation for non-matching tools', async () => {
    const validator = new ArgumentValidator(sqlRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_read',
      arguments: { path: '/etc/passwd' },
    });

    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should skip validation when no arguments provided', async () => {
    const validator = new ArgumentValidator(sqlRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
    });

    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should skip validation when toolName is undefined', async () => {
    const validator = new ArgumentValidator(sqlRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      arguments: { query: 'DROP TABLE users' },
    });
    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should skip unknown validator types', async () => {
    const rules: ValidationRule[] = [
      {
        id: 'custom_check',
        type: 'custom',
        tools: ['database_execute'],
        argument: 'query',
      },
    ];
    const validator = new ArgumentValidator(rules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'DROP TABLE users' },
    });
    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should allow when regex does not match', async () => {
    const validator = new ArgumentValidator(regexRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users' },
    });
    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should allow valid SQL via configured SQLValidator', async () => {
    const validator = new ArgumentValidator(sqlRules, {
      blocked_patterns: [
        { pattern: 'DROP\\s+TABLE', flags: 'i', message: 'DROP TABLE is not allowed' },
      ],
      injection_patterns: [],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users' },
    });
    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should support wildcard tool matching', async () => {
    const wildcardRules: ValidationRule[] = [
      {
        id: 'block_drop_wildcard',
        type: 'regex',
        tools: ['database_*'],
        argument: 'query',
        patterns: [{ pattern: 'DROP', flags: 'i', message: 'No DROP' }],
      },
    ];
    const validator = new ArgumentValidator(wildcardRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_query',
      arguments: { query: 'DROP TABLE users' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow(ValidationError);
  });

  it('should handle dangerous wildcard patterns safely', async () => {
    const dangerousRules: ValidationRule[] = [
      {
        id: 'dangerous_pattern',
        type: 'regex',
        tools: ['(a+)+*'],
        argument: 'query',
        patterns: [{ pattern: 'DROP', flags: 'i', message: 'No DROP' }],
      },
    ];
    const validator = new ArgumentValidator(dangerousRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'something_else',
      arguments: { query: 'DROP TABLE users' },
    });
    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should allow non-string values for shell_safe', async () => {
    const validator = new ArgumentValidator(shellRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'shell_exec',
      arguments: { command: 123 },
    });
    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should allow non-string values for sql_safe', async () => {
    const validator = new ArgumentValidator(sqlRules);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 123 },
    });
    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });
});
