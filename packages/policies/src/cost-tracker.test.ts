import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it } from 'vitest';
import { CostTracker } from './cost-tracker.js';

describe('CostTracker', () => {
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
});
