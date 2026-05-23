import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it } from 'vitest';
import { PolicyEngine } from './engine.js';

describe('PolicyEngine', () => {
  it('defaults to BLOCK', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      rules: [],
      settings: { default_action: 'block', audit_level: 'full', read_only: false, dry_run: false },
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
      settings: { default_action: 'block', audit_level: 'full', read_only: false, dry_run: false },
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

  it('evaluates condition groups with anyOf', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      rules: [
        {
          id: 'r1',
          type: 'block',
          tools: ['test'],
          priority: 10,
          conditions: [],
          conditionGroups: [
            {
              anyOf: [
                { argument: 'val', contains: 'bad' },
                { argument: 'val', contains: 'evil' },
              ],
            },
          ],
        },
      ],
      settings: { default_action: 'allow', audit_level: 'full', read_only: false, dry_run: false },
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'this is evil stuff' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('records safe calls for auto-approval', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      rules: [
        { id: 'r1', type: 'approval_required', tools: ['write'], priority: 10, conditions: [] },
      ],
      settings: { default_action: 'block', audit_level: 'full', read_only: false, dry_run: false },
      approvals: {
        default_timeout_ms: 300000,
        max_pending_approvals: 1000,
        auto_approval: { enabled: true, safe_call_threshold: 2, per_session_tracking: true },
      },
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read',
    });
    engine.recordSafeCall(ctx);
    engine.recordSafeCall(ctx);
    const ctx2 = createRequestContext({
      requestId: '2',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'write',
    });
    const result = await engine.evaluate(ctx2);
    expect(result.action).toBe('ALLOW');
  });
});
