import { describe, it, expect } from 'vitest';
import { ArgumentValidator } from '../../src/policies/validator.js';
import { createRequestContext } from '../../src/middleware/context.js';
import { ValidationError } from '../../src/utils/errors.js';

describe('ArgumentValidator with SQLValidator', () => {
  const sqlConfig = {
    blocked_patterns: [
      { pattern: 'DROP\\s+TABLE', flags: 'i', message: 'DROP TABLE is not allowed' },
    ],
    injection_patterns: [
      { pattern: 'UNION\\s+SELECT', flags: 'i', message: 'UNION SELECT is not allowed' },
    ],
    require_where_clause: ['DELETE', 'UPDATE'],
    read_only_statements: ['SELECT'],
  };

  it('should use dedicated SQLValidator when configured', async () => {
    const validator = new ArgumentValidator(
      [
        {
          id: 'sql_check',
          type: 'sql_safe',
          tools: ['database_execute'],
          argument: 'query',
        },
      ],
      sqlConfig,
    );

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'DROP TABLE users' },
    });

    await expect(validator.execute(ctx)).rejects.toThrow(ValidationError);
  });

  it('should allow safe queries with dedicated SQLValidator', async () => {
    const validator = new ArgumentValidator(
      [
        {
          id: 'sql_check',
          type: 'sql_safe',
          tools: ['database_execute'],
          argument: 'query',
        },
      ],
      sqlConfig,
    );

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users' },
    });

    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should block DELETE without WHERE using SQLValidator', async () => {
    const validator = new ArgumentValidator(
      [
        {
          id: 'sql_check',
          type: 'sql_safe',
          tools: ['database_execute'],
          argument: 'query',
        },
      ],
      sqlConfig,
    );

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'DELETE FROM users' },
    });

    await expect(validator.execute(ctx)).rejects.toThrow(ValidationError);
  });

  it('should skip sql_safe validation for non-matching tools', async () => {
    const validator = new ArgumentValidator(
      [
        {
          id: 'sql_check',
          type: 'sql_safe',
          tools: ['database_execute'],
          argument: 'query',
        },
      ],
      sqlConfig,
    );

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_read',
      arguments: { path: '/etc/passwd' },
    });

    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should skip sql_safe when no sqlConfig provided', async () => {
    const validator = new ArgumentValidator([
      {
        id: 'sql_check',
        type: 'sql_safe',
        tools: ['database_execute'],
        argument: 'query',
      },
    ]);

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'DROP TABLE users' },
    });

    // Uses legacy regex-based validator which should also block this
    await expect(validator.execute(ctx)).rejects.toThrow(ValidationError);
  });
});
