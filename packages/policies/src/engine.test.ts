import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it } from 'vitest';
import { PolicyEngine } from './engine.js';

describe('PolicyEngine', () => {
  it('defaults to BLOCK', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      rules: [],
      settings: { default_action: 'block', audit_level: 'full', read_only: false },
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('matches rules by tool name', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      rules: [{ id: 'r1', type: 'allow', tools: ['allowed_tool'], priority: 10, conditions: [] }],
      settings: { default_action: 'block', audit_level: 'full', read_only: false },
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'allowed_tool',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });
});
