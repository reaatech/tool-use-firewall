import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { RateLimiter, TokenBucket } from './rate-limit.js';

describe('TokenBucket', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('allows consuming within capacity', () => {
    const bucket = new TokenBucket(10, 1);
    expect(bucket.consume()).toBe(true);
    expect(bucket.consume(5)).toBe(true);
  });

  it('blocks when empty', () => {
    const bucket = new TokenBucket(1, 0);
    expect(bucket.consume()).toBe(true);
    expect(bucket.consume()).toBe(false);
  });

  it('refills tokens over time', () => {
    vi.useFakeTimers();
    const bucket = new TokenBucket(10, 1);
    expect(bucket.consume(10)).toBe(true);
    expect(bucket.consume()).toBe(false);
    vi.advanceTimersByTime(2000);
    expect(bucket.consume()).toBe(true);
    vi.useRealTimers();
  });

  it('getWaitTimeMs returns 0 when enough tokens', () => {
    const bucket = new TokenBucket(10, 1);
    expect(bucket.getWaitTimeMs()).toBe(0);
  });

  it('getWaitTimeMs returns wait time when not enough tokens', () => {
    vi.useFakeTimers();
    const bucket = new TokenBucket(2, 1);
    expect(bucket.consume(2)).toBe(true);
    const wait = bucket.getWaitTimeMs(1);
    expect(wait).toBeGreaterThan(0);
    vi.useRealTimers();
  });
});

describe('RateLimiter', () => {
  it('allows requests within limits', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 1000, burst_capacity: 100 },
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
    });
    const result = await limiter.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('blocks when global limit exceeded', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 1, burst_capacity: 1 },
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
    });
    await limiter.execute(ctx);
    await expect(limiter.execute(ctx)).rejects.toThrow('Global rate limit exceeded');
  });

  it('blocks when tool limit exceeded', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 1000, burst_capacity: 100 },
      per_tool: { fast_tool: { requests_per_minute: 1, burst_capacity: 1 } },
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'fast_tool',
    });
    await limiter.execute(ctx);
    await expect(limiter.execute(ctx)).rejects.toThrow('Rate limit exceeded for tool');
  });

  it('blocks when session limit exceeded', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 1000, burst_capacity: 100 },
      per_session: { requests_per_minute: 1, burst_capacity: 1 },
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool',
    });
    await limiter.execute(ctx);
    await expect(limiter.execute(ctx)).rejects.toThrow('Session rate limit exceeded');
  });

  it('per-tool config falls back to global', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 1000, burst_capacity: 100 },
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'unknown_tool',
    });
    const result = await limiter.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('per-session config uses default when not specified', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 1000, burst_capacity: 100 },
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
    });
    const result = await limiter.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('multiple sessions with different limits', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 1000, burst_capacity: 100 },
      per_session: { requests_per_minute: 1, burst_capacity: 2 },
    });
    const ctx1 = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'tool',
    });
    const ctx2 = createRequestContext({
      requestId: '2',
      sessionId: 's2',
      method: 'tools/call',
      toolName: 'tool',
    });
    await limiter.execute(ctx1);
    await limiter.execute(ctx1);
    await limiter.execute(ctx2);
    await expect(limiter.execute(ctx1)).rejects.toThrow('Session rate limit exceeded');
    const result2 = await limiter.execute(ctx2);
    expect(result2.action).toBe('CONTINUE');
  });

  it('no global config does not check global limit', async () => {
    const limiter = new RateLimiter({});
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
    });
    const result = await limiter.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('token bucket refill behavior', () => {
    vi.useFakeTimers();
    const bucket = new TokenBucket(10, 1);
    expect(bucket.consume(10)).toBe(true);
    vi.advanceTimersByTime(5000);
    expect(bucket.consume(5)).toBe(true);
    expect(bucket.consume(6)).toBe(false);
    vi.useRealTimers();
  });

  it('includes retryAfterMs in error', async () => {
    vi.useFakeTimers();
    const limiter = new RateLimiter({
      global: { requests_per_minute: 1, burst_capacity: 1 },
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
    });
    await limiter.execute(ctx);
    try {
      await limiter.execute(ctx);
    } catch (e: unknown) {
      const err = e as { retryAfterMs?: number };
      expect(err.retryAfterMs).toBeGreaterThan(0);
    }
    vi.useRealTimers();
  });

  it('evicts stale tool limiters', async () => {
    vi.useFakeTimers();
    const limiter = new RateLimiter({
      global: { requests_per_minute: 1000000, burst_capacity: 1000000 },
    });
    for (let i = 0; i < 1001; i++) {
      const ctx = createRequestContext({
        requestId: `${i}`,
        sessionId: 's1',
        method: 'tools/call',
        toolName: `tool_${i}`,
      });
      await limiter.execute(ctx);
    }
    expect(
      (limiter as unknown as { toolLimiters: Map<string, unknown> }).toolLimiters.size,
    ).toBeLessThanOrEqual(1000);
    vi.useRealTimers();
  });

  it('evicts stale session limiters', async () => {
    vi.useFakeTimers();
    const limiter = new RateLimiter({
      global: { requests_per_minute: 10000000, burst_capacity: 10000000 },
      per_session: { requests_per_minute: 1000000, burst_capacity: 1000000 },
    });
    for (let i = 0; i < 10001; i++) {
      const ctx = createRequestContext({
        requestId: `${i}`,
        sessionId: `session-${i}`,
        method: 'tools/call',
      });
      await limiter.execute(ctx);
    }
    expect(
      (limiter as unknown as { sessionLimiters: Map<string, unknown> }).sessionLimiters.size,
    ).toBeLessThanOrEqual(10000);
    vi.useRealTimers();
  });
});
