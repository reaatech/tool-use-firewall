import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it, vi } from 'vitest';
import { PolicyEngine } from './engine.js';

function baseConfig(overrides?: Record<string, unknown>) {
  return {
    version: '1.0',
    rules: [],
    settings: { default_action: 'block', audit_level: 'full', read_only: false, dry_run: false },
    ...overrides,
  } as never;
}

describe('PolicyEngine', () => {
  it('defaults to BLOCK', async () => {
    const engine = new PolicyEngine(baseConfig());
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('defaults to ALLOW when configured', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        settings: {
          default_action: 'allow',
          audit_level: 'full',
          read_only: false,
          dry_run: false,
        },
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('matches rules by tool name', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [{ id: 'r1', type: 'allow', tools: ['allowed_tool'], priority: 10, conditions: [] }],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'allowed_tool',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('matches no toolName against all rules', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [{ id: 'r1', type: 'block', tools: ['some_tool'], priority: 10, conditions: [] }],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('evaluates condition groups with anyOf', async () => {
    const engine = new PolicyEngine(
      baseConfig({
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
        settings: {
          default_action: 'allow',
          audit_level: 'full',
          read_only: false,
          dry_run: false,
        },
      }),
    );
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

  it('condition type pattern matches', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'val', pattern: '^\\d+$', flags: '' }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: '123' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('condition type pattern does not match non-string', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'val', pattern: '^\\d+$', flags: '' }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 123 },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('condition type equals matches', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'allow',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'val', equals: 'exact' }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'exact' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('condition type contains matches', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'val', contains: 'bad' }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'something bad here' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('condition type contains fails on non-string', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'val', contains: 'bad' }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 42 },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('condition type gt matches', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'val', gt: 100 }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 200 },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('condition type gt fails on non-number', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'val', gt: 100 }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'abc' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('condition type lt matches', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'val', lt: 100 }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 50 },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('condition type lt fails on non-number', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'val', lt: 100 }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: null },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('conditionGroup with allOf', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [],
            conditionGroups: [
              {
                allOf: [
                  { argument: 'a', equals: 'x' },
                  { argument: 'b', equals: 'y' },
                ],
              },
            ],
          },
        ],
        settings: {
          default_action: 'allow',
          audit_level: 'full',
          read_only: false,
          dry_run: false,
        },
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { a: 'x', b: 'y' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('conditionGroup allOf fails when one condition mismatches', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [],
            conditionGroups: [
              {
                allOf: [
                  { argument: 'a', equals: 'x' },
                  { argument: 'b', equals: 'y' },
                ],
              },
            ],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { a: 'x', b: 'z' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('conditionGroup with timeWindow in window', async () => {
    vi.useFakeTimers();
    const wed = new Date('2025-01-01T14:00:00');
    wed.setFullYear(2025, 0, 1);
    vi.setSystemTime(wed);
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [],
            conditionGroups: [
              {
                timeWindow: { days: ['wed'], after: '09:00', before: '17:00' },
                anyOf: [{ argument: 'val', contains: 'bad' }],
              },
            ],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'bad stuff' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
    vi.useRealTimers();
  });

  it('conditionGroup with timeWindow out of window', async () => {
    vi.useFakeTimers();
    const mon = new Date('2025-01-06T14:00:00');
    vi.setSystemTime(mon);
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [],
            conditionGroups: [
              {
                timeWindow: { days: ['wed'], after: '09:00', before: '17:00' },
                anyOf: [{ argument: 'val', contains: 'bad' }],
              },
            ],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'bad stuff' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
    vi.useRealTimers();
  });

  it('timeWindow on rule skips out of window', async () => {
    vi.useFakeTimers();
    const mon = new Date('2025-01-06T14:00:00');
    vi.setSystemTime(mon);
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [],
            timeWindow: { days: ['wed'] },
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
    vi.useRealTimers();
  });

  it('timeWindow timezone fallback on invalid tz', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-06T14:00:00'));
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [],
            timeWindow: { days: ['mon'], timezone: 'Invalid/Timezone' },
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
    vi.useRealTimers();
  });

  it('records safe calls for auto-approval', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          { id: 'r1', type: 'approval_required', tools: ['write'], priority: 10, conditions: [] },
        ],
        settings: {
          default_action: 'block',
          audit_level: 'full',
          read_only: false,
          dry_run: false,
        },
        approvals: {
          default_timeout_ms: 300000,
          max_pending_approvals: 1000,
          auto_approval: { enabled: true, safe_call_threshold: 2, per_session_tracking: true },
        },
      }),
    );
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

  it('auto-approval trust patterns with glob matching', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'approval_required',
            tools: ['admin_write'],
            priority: 10,
            conditions: [],
          },
        ],
        settings: {
          default_action: 'block',
          audit_level: 'full',
          read_only: false,
          dry_run: false,
        },
        approvals: {
          default_timeout_ms: 300000,
          max_pending_approvals: 1000,
          auto_approval: {
            enabled: true,
            safe_call_threshold: 100,
            trust_tool_patterns: ['admin_*'],
            per_session_tracking: true,
          },
        },
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'admin_read',
    });
    engine.recordSafeCall(ctx);
    const ctx2 = createRequestContext({
      requestId: '2',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'admin_write',
    });
    const result = await engine.evaluate(ctx2);
    expect(result.action).toBe('ALLOW');
  });

  it('wildcard tool matching', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [{ id: 'r1', type: 'block', tools: ['db_*'], priority: 10, conditions: [] }],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('matchesTool with empty tools list', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [{ id: 'r1', type: 'block', tools: [], priority: 10, conditions: [] }],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'anything',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('extractArgValue with nested path', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'foo.bar.baz', equals: 'deep' }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { foo: { bar: { baz: 'deep' } } },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('extractArgValue with null segment', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'foo.bar', equals: 'x' }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { foo: null },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('extractArgValue with undefined args', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'foo', equals: 'x' }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('invalid condition regex falls through', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'val', pattern: '[invalid', flags: '' }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'anything' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('multiple rules sorted by priority', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          { id: 'low', type: 'allow', tools: ['test'], priority: 1, conditions: [] },
          { id: 'high', type: 'block', tools: ['test'], priority: 10, conditions: [] },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
    expect(result.rule?.id).toBe('high');
  });

  it('session eviction on recordSafeCall', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [],
        approvals: {
          default_timeout_ms: 300000,
          max_pending_approvals: 1000,
          auto_approval: { enabled: true, safe_call_threshold: 1, per_session_tracking: true },
        },
      }),
    );
    for (let i = 0; i < 10001; i++) {
      const ctx = createRequestContext({
        requestId: `${i}`,
        sessionId: `session-${i}`,
        method: 'tools/call',
        toolName: 'tool',
      });
      engine.recordSafeCall(ctx);
    }
    expect(
      (engine as unknown as { sessionTrust: Map<string, unknown> }).sessionTrust.size,
    ).toBeLessThanOrEqual(9000);
  });

  it('recordSafeCall does nothing when auto-approval disabled', () => {
    const engine = new PolicyEngine(baseConfig());
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool',
    });
    engine.recordSafeCall(ctx);
    expect((engine as unknown as { sessionTrust: Map<string, unknown> }).sessionTrust.size).toBe(0);
  });

  it('condition with no comparator is truthy', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [{ id: 'r1', type: 'allow', tools: ['test'], priority: 10, conditions: [{}] }],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('no conditions and no conditionGroups returns true', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [{ id: 'r1', type: 'allow', tools: ['test'], priority: 10, conditions: [] }],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('isTrustedSession with no trust returns false', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          { id: 'r1', type: 'approval_required', tools: ['test'], priority: 10, conditions: [] },
        ],
        approvals: {
          default_timeout_ms: 300000,
          max_pending_approvals: 1000,
          auto_approval: {
            enabled: true,
            safe_call_threshold: 2,
            trust_tool_patterns: ['trusted_*'],
            per_session_tracking: true,
          },
        },
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 'no-session',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('APPROVAL_REQUIRED');
  });

  it('isTrustedSession with invalid glob falls back to exact match', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          { id: 'r1', type: 'approval_required', tools: ['test'], priority: 10, conditions: [] },
        ],
        settings: {
          default_action: 'block',
          audit_level: 'full',
          read_only: false,
          dry_run: false,
        },
        approvals: {
          default_timeout_ms: 300000,
          max_pending_approvals: 1000,
          auto_approval: {
            enabled: true,
            safe_call_threshold: 100,
            trust_tool_patterns: ['(((((((((((inval)))))))))))'],
            per_session_tracking: true,
          },
        },
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'safe_tool',
    });
    engine.recordSafeCall(ctx);
    const ctx2 = createRequestContext({
      requestId: '2',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx2);
    expect(result.action).toBe('APPROVAL_REQUIRED');
  });

  it('matchesTool with invalid glob pattern falls back', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['*(((((((((((test)))))))))))'],
            priority: 10,
            conditions: [],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'nonexistent',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('timeWindow with after fails when time is before', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-01T08:00:00'));
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [],
            timeWindow: { after: '09:00' },
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
    vi.useRealTimers();
  });

  it('timeWindow with before fails when time is after', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-01T18:00:00'));
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [],
            timeWindow: { after: '09:00', before: '17:00' },
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
    vi.useRealTimers();
  });

  it('isTrustedSession returns false when no trust patterns match', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          { id: 'r1', type: 'approval_required', tools: ['test'], priority: 10, conditions: [] },
        ],
        approvals: {
          default_timeout_ms: 300000,
          max_pending_approvals: 1000,
          auto_approval: {
            enabled: true,
            safe_call_threshold: 100,
            trust_tool_patterns: ['trusted_*'],
            per_session_tracking: true,
          },
        },
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'read',
    });
    engine.recordSafeCall(ctx);
    const ctx2 = createRequestContext({
      requestId: '2',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx2);
    expect(result.action).toBe('APPROVAL_REQUIRED');
  });

  it('matchesTool with pattern equals tool name (no glob)', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [{ id: 'r1', type: 'block', tools: ['exact_name'], priority: 10, conditions: [] }],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'exact_name',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('anyOf with no matching conditions fails', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'allow',
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
        settings: {
          default_action: 'block',
          audit_level: 'full',
          read_only: false,
          dry_run: false,
        },
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'safe stuff' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('condition with no argument but comparator uses undefined value', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'allow',
            tools: ['test'],
            priority: 10,
            conditions: [{ pattern: '^\\d+$' }],
          },
        ],
        settings: {
          default_action: 'block',
          audit_level: 'full',
          read_only: false,
          dry_run: false,
        },
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: '123' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('condition with pattern and flags undefined', async () => {
    const engine = new PolicyEngine(
      baseConfig({
        rules: [
          {
            id: 'r1',
            type: 'block',
            tools: ['test'],
            priority: 10,
            conditions: [{ argument: 'val', pattern: 'hello' }],
          },
        ],
      }),
    );
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'hello' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });
});
