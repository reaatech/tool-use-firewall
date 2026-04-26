import { describe, it, expect } from 'vitest';
import { PolicyEngine } from '../../src/policies/engine.js';
import type { PolicyConfig } from '../../src/config/schema.js';
import { createRequestContext } from '../../src/middleware/context.js';

describe('PolicyEngine', () => {
  const basePolicy: PolicyConfig = {
    version: '1.0',
    settings: { default_action: 'block' },
    rules: [
      {
        id: 'block_drop',
        type: 'block',
        tools: ['database_execute'],
        conditions: [{ argument: 'query', pattern: 'DROP', flags: 'i' }],
        priority: 100,
      },
      {
        id: 'allow_select',
        type: 'allow',
        tools: ['database_execute'],
        conditions: [{ argument: 'query', pattern: '^SELECT', flags: 'i' }],
        priority: 90,
      },
      {
        id: 'require_approval_for_delete',
        type: 'approval_required',
        tools: ['database_execute'],
        conditions: [{ argument: 'query', pattern: 'DELETE', flags: 'i' }],
        priority: 95,
      },
    ],
  };

  it('should block DROP queries', async () => {
    const engine = new PolicyEngine(basePolicy);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'DROP TABLE users' },
    });

    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
    expect(result.rule?.id).toBe('block_drop');
  });

  it('should allow SELECT queries', async () => {
    const engine = new PolicyEngine(basePolicy);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users' },
    });

    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('should require approval for DELETE', async () => {
    const engine = new PolicyEngine(basePolicy);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'DELETE FROM users WHERE id = 1' },
    });

    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('APPROVAL_REQUIRED');
  });

  it('should block non-matching queries by default', async () => {
    const engine = new PolicyEngine(basePolicy);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'INSERT INTO users VALUES (1)' },
    });

    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('should use allow default when configured', async () => {
    const engine = new PolicyEngine({
      ...basePolicy,
      settings: { default_action: 'allow' },
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'INSERT INTO users VALUES (1)' },
    });

    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('should support wildcard tool matching', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'block_all_db',
          type: 'block',
          tools: ['database_*'],
          conditions: [],
          priority: 100,
        },
      ],
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_query',
      arguments: {},
    });

    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('should apply rules in priority order', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'low_priority_allow',
          type: 'allow',
          tools: ['tool'],
          conditions: [],
          priority: 10,
        },
        {
          id: 'high_priority_block',
          type: 'block',
          tools: ['tool'],
          conditions: [],
          priority: 100,
        },
      ],
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool',
      arguments: {},
    });

    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
    expect(result.rule?.id).toBe('high_priority_block');
  });

  it('should evaluate rules when toolName is undefined', async () => {
    const engine = new PolicyEngine(basePolicy);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      arguments: { query: 'DROP TABLE users' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('should match tools exactly when no wildcard', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'exact_match',
          type: 'allow',
          tools: ['specific_tool'],
          conditions: [],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'specific_tool',
      arguments: {},
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('should handle invalid regex in conditions', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'allow' },
      rules: [
        {
          id: 'invalid_regex',
          type: 'block',
          tools: ['tool'],
          conditions: [{ argument: 'query', pattern: '(a+)+' }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool',
      arguments: { query: 'test' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('should match equals condition', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'equals_match',
          type: 'allow',
          tools: ['tool'],
          conditions: [{ argument: 'status', equals: 'active' }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool',
      arguments: { status: 'active' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('should match contains condition', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'contains_match',
          type: 'allow',
          tools: ['tool'],
          conditions: [{ argument: 'query', contains: 'SELECT' }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool',
      arguments: { query: 'SELECT * FROM users' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('should match gt and lt conditions on numbers', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'range_match',
          type: 'allow',
          tools: ['tool'],
          conditions: [
            { argument: 'count', gt: 5 },
            { argument: 'count', lt: 15 },
          ],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool',
      arguments: { count: 10 },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('fails closed when a numeric comparator is applied to a non-number', async () => {
    // A `gt` comparator against a string value should NOT match the rule —
    // the engine falls through to the default action (BLOCK here).
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'range_match',
          type: 'allow',
          tools: ['tool'],
          conditions: [{ argument: 'count', gt: 5 }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool',
      arguments: { count: 'ten' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('should handle completely missing arguments', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'arg_check',
          type: 'allow',
          tools: ['tool'],
          conditions: [{ argument: 'missing', equals: 'value' }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });
});
