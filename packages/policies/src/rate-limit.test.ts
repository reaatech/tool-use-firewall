import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it } from 'vitest';
import { RateLimiter, TokenBucket } from './rate-limit.js';

describe('TokenBucket', () => {
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
});
