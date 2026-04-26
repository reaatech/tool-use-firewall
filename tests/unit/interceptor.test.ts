import { describe, it, expect } from 'vitest';
import { InterceptorPipeline } from '../../src/middleware/interceptor.js';
import { createRequestContext } from '../../src/middleware/context.js';

describe('InterceptorPipeline', () => {
  it('should allow request when all middlewares continue', async () => {
    const pipeline = new InterceptorPipeline();
    pipeline.register({
      execute: async () => ({ action: 'CONTINUE' }),
    });
    pipeline.register({
      execute: async () => ({ action: 'CONTINUE' }),
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
    });

    const result = await pipeline.process(ctx);
    expect(result.allowed).toBe(true);
    expect(result.action).toBe('CONTINUE');
  });

  it('should block on first blocking middleware', async () => {
    const pipeline = new InterceptorPipeline();
    pipeline.register({
      execute: async () => ({ action: 'CONTINUE' }),
    });
    pipeline.register({
      execute: async () => ({ action: 'BLOCK', reason: 'Test block' }),
    });
    pipeline.register({
      execute: async () => ({ action: 'CONTINUE' }),
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
    });

    const result = await pipeline.process(ctx);
    expect(result.allowed).toBe(false);
    expect(result.action).toBe('BLOCK');
    expect(result.reason).toBe('Test block');
  });

  it('should require approval when middleware returns approval_required', async () => {
    const pipeline = new InterceptorPipeline();
    pipeline.register({
      execute: async () => ({ action: 'APPROVAL_REQUIRED', reason: 'Needs approval' }),
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
    });

    const result = await pipeline.process(ctx);
    expect(result.allowed).toBe(false);
    expect(result.action).toBe('APPROVAL_REQUIRED');
    expect(result.reason).toBe('Needs approval');
  });

  it('should carry metadata through the pipeline', async () => {
    const pipeline = new InterceptorPipeline();
    pipeline.register({
      execute: async () => ({
        action: 'BLOCK',
        reason: 'Blocked',
        metadata: { ruleId: 'test-rule' },
      }),
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
    });

    const result = await pipeline.process(ctx);
    expect(result.metadata).toEqual({ ruleId: 'test-rule' });
  });
});
