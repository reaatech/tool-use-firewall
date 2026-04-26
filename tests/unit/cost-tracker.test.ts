import { describe, it, expect } from 'vitest';
import { CostTracker } from '../../src/policies/cost-tracker.js';
import { createRequestContext } from '../../src/middleware/context.js';
import { BudgetExceededError } from '../../src/utils/errors.js';

describe('CostTracker', () => {
  it('should allow requests within budget', async () => {
    const tracker = new CostTracker({
      session_budget: 10,
      tool_costs: { expensive_tool: 1, cheap_tool: 0.1 },
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'expensive_tool',
    });

    for (let i = 0; i < 10; i++) {
      const result = await tracker.execute(ctx);
      expect(result.action).toBe('CONTINUE');
    }
  });

  it('should block when budget exceeded', async () => {
    const tracker = new CostTracker({
      session_budget: 1,
      tool_costs: { expensive_tool: 1 },
      budget_action: 'block',
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'expensive_tool',
    });

    await tracker.execute(ctx);
    await expect(tracker.execute(ctx)).rejects.toThrow(BudgetExceededError);
  });

  it('should warn when budget exceeded if configured', async () => {
    const tracker = new CostTracker({
      session_budget: 1,
      tool_costs: { expensive_tool: 1 },
      budget_action: 'warn',
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'expensive_tool',
    });

    await tracker.execute(ctx);
    const result = await tracker.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.budgetWarning).toBe(true);
  });

  it('should track costs per session independently', async () => {
    const tracker = new CostTracker({
      session_budget: 2,
      tool_costs: { tool: 1 },
    });

    const ctxA = createRequestContext({
      requestId: 'r1',
      sessionId: 'session-a',
      method: 'tools/call',
      toolName: 'tool',
    });
    const ctxB = createRequestContext({
      requestId: 'r2',
      sessionId: 'session-b',
      method: 'tools/call',
      toolName: 'tool',
    });

    await tracker.execute(ctxA);
    await tracker.execute(ctxA);
    await expect(tracker.execute(ctxA)).rejects.toThrow(BudgetExceededError);

    // session-b should still have budget
    await expect(tracker.execute(ctxB)).resolves.toBeDefined();
  });

  it('should treat unknown tools as zero cost', async () => {
    const tracker = new CostTracker({
      session_budget: 1,
      tool_costs: {},
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'unknown_tool',
    });

    const result = await tracker.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('should use defaults with empty config', async () => {
    const tracker = new CostTracker({});
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'any_tool',
    });
    const result = await tracker.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('should handle undefined toolName', async () => {
    const tracker = new CostTracker({
      session_budget: 10,
      tool_costs: { tool: 1 },
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
    });
    const result = await tracker.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.cost).toBe(0);
  });

  it('should hard evict oldest sessions when over capacity', async () => {
    const tracker = new CostTracker({
      session_budget: 1000,
      tool_costs: { tool: 1 },
    });

    for (let i = 0; i < 10002; i++) {
      const ctx = createRequestContext({
        requestId: `r${i}`,
        sessionId: `session-${i}`,
        method: 'tools/call',
        toolName: 'tool',
      });
      await tracker.execute(ctx);
    }

    const ctx = createRequestContext({
      requestId: 'r-new',
      sessionId: 'session-new',
      method: 'tools/call',
      toolName: 'tool',
    });
    const result = await tracker.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });
});
