import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CostTracker } from './cost-tracker.js';

describe('CostTracker', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('allows within budget', async () => {
    const tracker = new CostTracker({
      session_budget: 100,
      tool_costs: { expensive_tool: 10 },
      budget_action: 'block',
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'expensive_tool',
    });
    const result = await tracker.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.cost).toBe(10);
  });

  it('blocks when budget exceeded', async () => {
    const tracker = new CostTracker({
      session_budget: 5,
      tool_costs: { expensive_tool: 10 },
      budget_action: 'block',
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'expensive_tool',
    });
    await expect(tracker.execute(ctx)).rejects.toThrow('Session budget exceeded');
  });

  it('warns when budget exceeded with warn action', async () => {
    const tracker = new CostTracker({
      session_budget: 5,
      tool_costs: { expensive_tool: 10 },
      budget_action: 'warn',
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'expensive_tool',
    });
    const result = await tracker.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.budgetWarning).toBe(true);
  });

  it('unknown tool cost defaults to 0', async () => {
    const tracker = new CostTracker({
      session_budget: 100,
      tool_costs: { known_tool: 10 },
      budget_action: 'block',
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'unknown_tool',
    });
    const result = await tracker.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.cost).toBe(0);
  });

  it('returns 0 cost when toolName is undefined', async () => {
    const tracker = new CostTracker({
      session_budget: 100,
      tool_costs: { expensive_tool: 10 },
      budget_action: 'block',
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
    });
    const result = await tracker.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.cost).toBe(0);
  });

  it('cost accumulates across multiple calls', async () => {
    const tracker = new CostTracker({
      session_budget: 100,
      tool_costs: { tool: 10 },
      budget_action: 'block',
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool',
    });
    const r1 = await tracker.execute(ctx);
    expect(r1.metadata?.totalCost).toBe(10);
    const r2 = await tracker.execute(ctx);
    expect(r2.metadata?.totalCost).toBe(20);
    const r3 = await tracker.execute(ctx);
    expect(r3.metadata?.totalCost).toBe(30);
  });

  it('budget exceeded with block action throws', async () => {
    const tracker = new CostTracker({
      session_budget: 10,
      tool_costs: { tool: 15 },
      budget_action: 'block',
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool',
    });
    await expect(tracker.execute(ctx)).rejects.toThrow('Session budget exceeded');
  });

  it('session eviction when exceeding max sessions', async () => {
    const tracker = new CostTracker({
      session_budget: 1000,
      tool_costs: { tool: 1 },
      budget_action: 'block',
    });
    for (let i = 0; i < 10001; i++) {
      const ctx = createRequestContext({
        requestId: `${i}`,
        sessionId: `session-${i}`,
        method: 'tools/call',
        toolName: 'tool',
      });
      await tracker.execute(ctx);
    }
    expect(
      (tracker as unknown as { sessions: Map<string, unknown> }).sessions.size,
    ).toBeLessThanOrEqual(10000);
  });
});
