import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AnomalyDetector } from './anomaly-detector.js';

describe('AnomalyDetector', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('passes when disabled', async () => {
    const d = new AnomalyDetector({ enabled: false });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'dangerous_write',
    });
    const result = await d.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.anomalyDetected).toBeUndefined();
  });

  it('does not flag below window size', async () => {
    const d = new AnomalyDetector({ enabled: true, window_size: 5 });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'new_tool',
    });
    const result = await d.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.anomalyDetected).toBeUndefined();
  });

  it('passes when no toolName', async () => {
    const d = new AnomalyDetector({ enabled: true });
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call' });
    const result = await d.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('triggers anomaly when score exceeds sensitivity', async () => {
    vi.useFakeTimers();
    const d = new AnomalyDetector({ enabled: true, window_size: 2, sensitivity: 0.1 });
    for (let i = 0; i < 2; i++) {
      const ctx = createRequestContext({
        requestId: `${i}`,
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'common_tool',
      });
      await d.execute(ctx);
    }
    const ctxRare = createRequestContext({
      requestId: '4',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'rare_tool',
    });
    const result = await d.execute(ctxRare);
    expect(result.metadata?.anomalyDetected).toBe(true);
    expect(result.metadata?.anomalyScore).toBeGreaterThan(0.1);
    expect(result.metadata?.recentToolCall).toBe('rare_tool');
    expect(result.metadata?.sessionTotalCalls).toBe(3);
    vi.useRealTimers();
  });

  it('does not trigger anomaly for common tool', async () => {
    const d = new AnomalyDetector({ enabled: true, window_size: 5, sensitivity: 0.3 });
    for (let i = 0; i < 6; i++) {
      const ctx = createRequestContext({
        requestId: `${i}`,
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'common_tool',
      });
      await d.execute(ctx);
    }
    const ctxSame = createRequestContext({
      requestId: '7',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'common_tool',
    });
    const result = await d.execute(ctxSame);
    expect(result.metadata?.anomalyDetected).toBeUndefined();
  });

  it('multiple sessions tracked independently', async () => {
    const d = new AnomalyDetector({ enabled: true, window_size: 2, sensitivity: 0.1 });
    for (let i = 0; i < 2; i++) {
      const ctx = createRequestContext({
        requestId: `${i}`,
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'tool_a',
      });
      await d.execute(ctx);
    }
    for (let i = 0; i < 2; i++) {
      const ctx = createRequestContext({
        requestId: `${i}b`,
        sessionId: 's2',
        method: 'tools/call',
        toolName: 'tool_b',
      });
      await d.execute(ctx);
    }
    const ctxA = createRequestContext({
      requestId: '3',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool_b',
    });
    const resultA = await d.execute(ctxA);
    expect(resultA.metadata?.anomalyDetected).toBe(true);
    const ctxB = createRequestContext({
      requestId: '3b',
      sessionId: 's2',
      method: 'tools/call',
      toolName: 'tool_a',
    });
    const resultB = await d.execute(ctxB);
    expect(resultB.metadata?.anomalyDetected).toBe(true);
  });

  it('handles division by zero when profile total is 0', async () => {
    const d = new AnomalyDetector({ enabled: true, window_size: 0, sensitivity: 0.5 });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await d.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('handles zero diversity case', async () => {
    const d = new AnomalyDetector({ enabled: true, window_size: 1, sensitivity: 0.5 });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await d.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('evicts stale sessions on capacity exceed', async () => {
    const d = new AnomalyDetector({ enabled: true, window_size: 1, sensitivity: 0.5 });
    for (let i = 0; i < 10001; i++) {
      const ctx = createRequestContext({
        requestId: `${i}`,
        sessionId: `session-${i}`,
        method: 'tools/call',
        toolName: 'tool',
      });
      await d.execute(ctx);
    }
    expect((d as unknown as { sessions: Map<string, unknown> }).sessions.size).toBeLessThanOrEqual(
      10000,
    );
  });
});
