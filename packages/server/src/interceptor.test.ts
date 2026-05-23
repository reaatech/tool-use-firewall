import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it, vi } from 'vitest';
import { InterceptorPipeline } from './interceptor.js';

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
    pipeline.register({
      execute: async () => ({ action: 'BLOCK' as const, reason: 'blocked' }),
    });
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call' });
    const result = await pipeline.process(ctx);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('blocked');
  });

  it('accumulates metadata across middlewares', async () => {
    const pipeline = new InterceptorPipeline();
    pipeline.register({
      execute: async () => ({ action: 'CONTINUE' as const, metadata: { step1: 'done' } }),
    });
    pipeline.register({
      execute: async () => ({ action: 'CONTINUE' as const, metadata: { step2: 'done' } }),
    });
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call' });
    const result = await pipeline.process(ctx);
    expect(result.metadata).toEqual({ step1: 'done', step2: 'done' });
  });

  it('returns APPROVAL_REQUIRED action', async () => {
    const pipeline = new InterceptorPipeline();
    pipeline.register({
      execute: async () => ({
        action: 'APPROVAL_REQUIRED' as const,
        reason: 'needs approval',
      }),
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'deploy',
    });
    const result = await pipeline.process(ctx);
    expect(result.allowed).toBe(false);
    expect(result.action).toBe('APPROVAL_REQUIRED');
    expect(result.reason).toBe('needs approval');
  });

  it('processes multiple middlewares and stops at first BLOCK', async () => {
    const pipeline = new InterceptorPipeline();
    const secondCalled = vi.fn();

    pipeline.register({
      execute: async () => ({ action: 'BLOCK' as const, reason: 'blocked' }),
    });
    pipeline.register({
      execute: async () => {
        secondCalled();
        return { action: 'CONTINUE' as const };
      },
    });

    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
    });

    const result = await pipeline.process(ctx);
    expect(result.allowed).toBe(false);
    expect(result.action).toBe('BLOCK');
    expect(secondCalled).not.toHaveBeenCalled();
  });

  it('stops at first APPROVAL_REQUIRED and skips subsequent middleware', async () => {
    const pipeline = new InterceptorPipeline();
    const secondCalled = vi.fn();

    pipeline.register({
      execute: async () => ({
        action: 'APPROVAL_REQUIRED' as const,
        reason: 'needs approval',
      }),
    });
    pipeline.register({
      execute: async () => {
        secondCalled();
        return { action: 'CONTINUE' as const };
      },
    });

    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
    });

    const result = await pipeline.process(ctx);
    expect(result.action).toBe('APPROVAL_REQUIRED');
    expect(secondCalled).not.toHaveBeenCalled();
  });

  it('returns CONTINUE when pipeline is empty', async () => {
    const pipeline = new InterceptorPipeline();
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
    });
    const result = await pipeline.process(ctx);
    expect(result.allowed).toBe(true);
    expect(result.action).toBe('CONTINUE');
  });

  it('includes metadata from BLOCK middleware in result', async () => {
    const pipeline = new InterceptorPipeline();

    pipeline.register({
      execute: async () => ({ action: 'CONTINUE' as const, metadata: { before: true } }),
    });
    pipeline.register({
      execute: async () => ({
        action: 'BLOCK' as const,
        reason: 'blocked',
        metadata: { blockedBy: 'test' },
      }),
    });

    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
    });

    const result = await pipeline.process(ctx);
    expect(result.allowed).toBe(false);
    expect(result.metadata).toEqual({ before: true, blockedBy: 'test' });
  });
});
