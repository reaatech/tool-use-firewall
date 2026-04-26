import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TokenBucket, RateLimiter } from '../../src/policies/rate-limit.js';
import { createRequestContext } from '../../src/middleware/context.js';
import { RateLimitError } from '../../src/utils/errors.js';

describe('TokenBucket', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should allow requests within capacity', () => {
    const bucket = new TokenBucket(10, 1); // 10 tokens, 1 token/ms
    expect(bucket.consume(5)).toBe(true);
    expect(bucket.consume(5)).toBe(true);
    expect(bucket.consume(1)).toBe(false);
  });

  it('should refill tokens over time', () => {
    const bucket = new TokenBucket(10, 0.1); // 10 tokens, 0.1 token/ms
    bucket.consume(10); // Empty the bucket

    vi.advanceTimersByTime(100); // Wait 100ms

    expect(bucket.consume(10)).toBe(true);
  });

  it('should not exceed capacity when refilling', () => {
    const bucket = new TokenBucket(10, 1);
    bucket.consume(5);

    vi.advanceTimersByTime(1000);

    expect(bucket.consume(10)).toBe(true);
    expect(bucket.consume(1)).toBe(false);
  });

  it('should calculate correct wait time', () => {
    const bucket = new TokenBucket(10, 0.1);
    bucket.consume(10);

    expect(bucket.getWaitTimeMs(5)).toBe(50);
  });
});

describe('RateLimiter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should allow requests within global limit', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 60, burst_capacity: 10 },
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });

    for (let i = 0; i < 10; i++) {
      await expect(limiter.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
    }
  });

  it('should block when global limit exceeded', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 60, burst_capacity: 2 },
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });

    await limiter.execute(ctx);
    await limiter.execute(ctx);
    await expect(limiter.execute(ctx)).rejects.toThrow(RateLimitError);
  });

  it('should track per-tool limits', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 100, burst_capacity: 100 },
      per_tool: {
        expensive_tool: { requests_per_minute: 60, burst_capacity: 1 },
      },
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'expensive_tool',
    });

    await limiter.execute(ctx);
    await expect(limiter.execute(ctx)).rejects.toThrow(RateLimitError);
  });

  it('should track per-session limits', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 100, burst_capacity: 100 },
      per_session: { requests_per_minute: 60, burst_capacity: 2 },
    });

    const ctx1 = createRequestContext({
      requestId: 'r1',
      sessionId: 'session-a',
      method: 'tools/call',
      toolName: 'test',
    });

    await limiter.execute(ctx1);
    await limiter.execute(ctx1);
    await expect(limiter.execute(ctx1)).rejects.toThrow(RateLimitError);

    // Different session should still work
    const ctx2 = createRequestContext({
      requestId: 'r2',
      sessionId: 'session-b',
      method: 'tools/call',
      toolName: 'test',
    });
    await expect(limiter.execute(ctx2)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should work without global config', async () => {
    const limiter = new RateLimiter({
      per_tool: {
        expensive_tool: { requests_per_minute: 60, burst_capacity: 1 },
      },
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'expensive_tool',
    });
    await expect(limiter.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should handle undefined toolName', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 60, burst_capacity: 10 },
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
    });
    await expect(limiter.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should hard evict oldest tool limiters when over capacity', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 100000, burst_capacity: 10000 },
    });

    for (let i = 0; i < 1002; i++) {
      const ctx = createRequestContext({
        requestId: `r${i}`,
        sessionId: 's1',
        method: 'tools/call',
        toolName: `tool-${i}`,
      });
      await limiter.execute(ctx);
    }

    const ctx = createRequestContext({
      requestId: 'r-new',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool-new',
    });
    await expect(limiter.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should hard evict oldest session limiters when over capacity', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 1000000, burst_capacity: 1000000 },
      per_session: { requests_per_minute: 100000, burst_capacity: 10000 },
    });

    for (let i = 0; i < 10002; i++) {
      const ctx = createRequestContext({
        requestId: `r${i}`,
        sessionId: `session-${i}`,
        method: 'tools/call',
        toolName: 'test',
      });
      await limiter.execute(ctx);
    }

    const ctx = createRequestContext({
      requestId: 'r-new',
      sessionId: 'session-new',
      method: 'tools/call',
      toolName: 'test',
    });
    await expect(limiter.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });
});
