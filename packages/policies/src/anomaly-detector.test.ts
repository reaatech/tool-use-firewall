import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it } from 'vitest';
import { AnomalyDetector } from './anomaly-detector.js';

describe('AnomalyDetector', () => {
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
});
