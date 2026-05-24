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

  it('strict mode validates string type', async () => {
    const v = new SchemaValidator({ strict: true });
    v.updateSchemas([
      { name: 'test', inputSchema: { type: 'object', properties: { name: { type: 'string' } } } },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { name: 42 },
    });
    await expect(v.execute(ctx)).rejects.toThrow('expected string');
  });

  it('strict mode validates number type', async () => {
    const v = new SchemaValidator({ strict: true });
    v.updateSchemas([
      { name: 'test', inputSchema: { type: 'object', properties: { age: { type: 'number' } } } },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { age: 'twenty' },
    });
    await expect(v.execute(ctx)).rejects.toThrow('expected number');
  });

  it('strict mode validates boolean type', async () => {
    const v = new SchemaValidator({ strict: true });
    v.updateSchemas([
      {
        name: 'test',
        inputSchema: { type: 'object', properties: { active: { type: 'boolean' } } },
      },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { active: 'yes' },
    });
    await expect(v.execute(ctx)).rejects.toThrow('expected boolean');
  });

  it('strict mode validates array type', async () => {
    const v = new SchemaValidator({ strict: true });
    v.updateSchemas([
      { name: 'test', inputSchema: { type: 'object', properties: { items: { type: 'array' } } } },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { items: 'not-array' },
    });
    await expect(v.execute(ctx)).rejects.toThrow('expected array');
  });

  it('strict mode with additionalProperties false rejects unknown args', async () => {
    const v = new SchemaValidator({ strict: true });
    v.updateSchemas([
      {
        name: 'test',
        inputSchema: {
          type: 'object',
          properties: { name: { type: 'string' } },
          additionalProperties: false,
        },
      },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { name: 'hello', extra: 'bad' },
    });
    await expect(v.execute(ctx)).rejects.toThrow('Unexpected argument');
  });

  it('schema not found for tool name skips validation', async () => {
    const v = new SchemaValidator({ strict: true });
    v.updateSchemas([{ name: 'known_tool', inputSchema: { type: 'object', properties: {} } }]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'unknown_tool',
      arguments: { foo: 'bar' },
    });
    const result = await v.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('updateSchemas with invalid schema is skipped', async () => {
    const v = new SchemaValidator();
    v.updateSchemas([{ name: 'test', inputSchema: null }] as never[]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: {},
    });
    const result = await v.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('no toolName path skips validation', async () => {
    const v = new SchemaValidator({ strict: true });
    v.updateSchemas([
      { name: 'test', inputSchema: { type: 'object', properties: { name: { type: 'string' } } } },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
    });
    const result = await v.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('non-strict mode passes type mismatches', async () => {
    const v = new SchemaValidator({ strict: false });
    v.updateSchemas([
      { name: 'test', inputSchema: { type: 'object', properties: { name: { type: 'string' } } } },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { name: 42 },
    });
    const result = await v.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('schema with no required field does not error', async () => {
    const v = new SchemaValidator({ strict: true });
    v.updateSchemas([
      { name: 'test', inputSchema: { type: 'object', properties: { name: { type: 'string' } } } },
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
