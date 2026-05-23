import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it } from 'vitest';
import { SchemaValidator } from './schema-validator.js';

describe('SchemaValidator', () => {
  it('passes when no schemas are loaded', async () => {
    const v = new SchemaValidator();
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { foo: 'bar' },
    });
    const result = await v.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('validates required arguments', async () => {
    const v = new SchemaValidator({ strict: true });
    v.updateSchemas([
      {
        name: 'test',
        inputSchema: {
          type: 'object',
          properties: { name: { type: 'string' } },
          required: ['name'],
        },
      },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: {},
    });
    await expect(v.execute(ctx)).rejects.toThrow();
  });

  it('passes valid arguments', async () => {
    const v = new SchemaValidator();
    v.updateSchemas([
      {
        name: 'test',
        inputSchema: {
          type: 'object',
          properties: { name: { type: 'string' } },
          required: ['name'],
        },
      },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { name: 'hello' },
    });
    const result = await v.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });
});
