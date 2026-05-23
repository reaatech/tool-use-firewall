import { describe, it, expect, vi } from 'vitest';
import { InterceptorPipeline } from './interceptor.js';
import { createRequestContext, type Middleware } from '@reaatech/tool-use-firewall-core';

describe('InterceptorPipeline', () => {
  it('allows when all middlewares return CONTINUE', async () => {
    const pipeline = new InterceptorPipeline();
    pipeline.register({ execute: async () => ({ action: 'CONTINUE' as const }) });
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call' });
    const result = await pipeline.process(ctx);
    expect(result.allowed).toBe(true);
  });

  it('blocks when middleware returns BLOCK', async () => {
    const pipeline = new InterceptorPipeline();
    pipeline.register({ execute: async () => ({ action: 'BLOCK' as const, reason: 'blocked' }) });
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call' });
    const result = await pipeline.process(ctx);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('blocked');
  });

  it('accumulates metadata across middlewares', async () => {
    const pipeline = new InterceptorPipeline();
    pipeline.register({ execute: async () => ({ action: 'CONTINUE' as const, metadata: { step1: 'done' } }) });
    pipeline.register({ execute: async () => ({ action: 'CONTINUE' as const, metadata: { step2: 'done' } }) });
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call' });
    const result = await pipeline.process(ctx);
    expect(result.metadata).toEqual({ step1: 'done', step2: 'done' });
  });
});
