# Skill: Rate Limiter

## Description
Configure and manage rate limiting for tool invocations. Rate limiting prevents abuse and ensures fair usage of tools by restricting the number of requests that can be made within a specified time window.

## When to Use
- Protecting upstream services from overload
- Preventing abuse of expensive operations
- Implementing per-session or per-tool limits
- Managing burst traffic

## Capabilities
- Token bucket algorithm implementation
- Per-tool rate limits
- Per-session rate limits
- Global rate limits
- Burst capacity configuration
- Rate limit headers in responses

## Rate Limit Configuration

```yaml
# policy.yaml
rate_limits:
  # Global limits applied to all tools
  global:
    requests_per_minute: 60
    requests_per_hour: 1000
    burst_capacity: 10
    
  # Per-tool specific limits
  per_tool:
    "database_execute":
      requests_per_minute: 10
      burst_capacity: 3
      
    "file_write":
      requests_per_minute: 30
      burst_capacity: 5
      
    "shell_exec":
      requests_per_minute: 5
      burst_capacity: 1
      
  # Per-session limits
  per_session:
    max_requests_per_minute: 100
    max_cost_per_minute: 10.00
```

## Implementation

### Token Bucket Algorithm
```typescript
// src/policies/rate-limiter.ts
export class TokenBucket {
  private capacity: number;
  private tokens: number;
  private refillRate: number; // tokens per ms
  private lastRefill: number;

  constructor(capacity: number, refillRate: number) {
    this.capacity = capacity;
    this.tokens = capacity;
    this.refillRate = refillRate;
    this.lastRefill = Date.now();
  }

  consume(tokens: number = 1): boolean {
    this.refill();
    
    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return true;
    }
    return false;
  }

  private refill(): void {
    const now = Date.now();
    const timePassed = now - this.lastRefill;
    const newTokens = timePassed * this.refillRate;
    
    this.tokens = Math.min(this.capacity, this.tokens + newTokens);
    this.lastRefill = now;
  }

  getWaitTime(tokens: number = 1): number {
    if (this.tokens >= tokens) return 0;
    const needed = tokens - this.tokens;
    return Math.ceil(needed / this.refillRate);
  }
}
```

### Rate Limiter Manager
```typescript
// src/policies/rate-limiter-manager.ts
export class RateLimiterManager {
  private globalLimiter: TokenBucket;
  private toolLimiters: Map<string, TokenBucket> = new Map();
  private sessionLimiters: Map<string, TokenBucket> = new Map();
  private sessionLastAccessed: Map<string, number> = new Map();
  private toolConfigs: Record<string, ToolRateLimitConfig>;
  private defaultToolConfig: ToolRateLimitConfig;
  private sessionConfig: SessionRateLimitConfig;
  private readonly sessionTtlMs: number;
  private readonly maxSessionLimiters: number;

  constructor(config: RateLimitConfig) {
    this.globalLimiter = new TokenBucket(
      config.global.burst_capacity,
      config.global.requests_per_minute / 60000
    );
    this.toolConfigs = config.per_tool || {};
    this.defaultToolConfig = config.per_tool_default || config.global;
    this.sessionConfig = config.per_session || config.global;
    this.sessionTtlMs = config.session_ttl_ms || 3600000; // 1 hour default
    this.maxSessionLimiters = config.max_session_limiters || 10000;
  }

  async checkLimit(context: RequestContext): Promise<RateLimitResult> {
    // Check global limit
    if (!this.globalLimiter.consume()) {
      return {
        allowed: false,
        reason: 'GLOBAL_RATE_LIMIT_EXCEEDED',
        retryAfter: this.globalLimiter.getWaitTime()
      };
    }

    // Check tool-specific limit
    const toolLimiter = this.getToolLimiter(context.toolName);
    if (!toolLimiter.consume()) {
      return {
        allowed: false,
        reason: 'TOOL_RATE_LIMIT_EXCEEDED',
        retryAfter: toolLimiter.getWaitTime(),
        tool: context.toolName
      };
    }

    // Check session limit
    const sessionLimiter = this.getSessionLimiter(context.sessionId);
    if (!sessionLimiter.consume()) {
      return {
        allowed: false,
        reason: 'SESSION_RATE_LIMIT_EXCEEDED',
        retryAfter: sessionLimiter.getWaitTime()
      };
    }

    return { allowed: true };
  }

  private getToolLimiter(toolName: string): TokenBucket {
    if (!this.toolLimiters.has(toolName)) {
      const config = this.toolConfigs[toolName] || this.defaultToolConfig;
      this.toolLimiters.set(toolName, new TokenBucket(
        config.burst_capacity,
        config.requests_per_minute / 60000
      ));
    }
    return this.toolLimiters.get(toolName)!;
  }

  private getSessionLimiter(sessionId: string): TokenBucket {
    // Evict stale sessions to prevent unbounded memory growth
    this.evictStaleSessions();

    if (!this.sessionLimiters.has(sessionId)) {
      this.sessionLimiters.set(sessionId, new TokenBucket(
        this.sessionConfig.burst_capacity,
        this.sessionConfig.requests_per_minute / 60000
      ));
    }
    this.sessionLastAccessed.set(sessionId, Date.now());
    return this.sessionLimiters.get(sessionId)!;
  }

  private evictStaleSessions(): void {
    if (this.sessionLimiters.size < this.maxSessionLimiters) return;

    const now = Date.now();
    for (const [id, lastAccess] of this.sessionLastAccessed.entries()) {
      if (now - lastAccess > this.sessionTtlMs) {
        this.sessionLimiters.delete(id);
        this.sessionLastAccessed.delete(id);
      }
    }
  }
  }
}
```

## Response Headers

When rate limits are exceeded, include these headers:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1682000000
Retry-After: 1000
```

## Error Response

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded for tool 'database_execute'",
    "details": {
      "tool": "database_execute",
      "limit": 10,
      "window": "minute",
      "retry_after_ms": 5000
    }
  }
}
```

## Testing

### Unit Tests
```typescript
describe('TokenBucket', () => {
  it('should allow requests within capacity', () => {
    const bucket = new TokenBucket(10, 1); // 10 tokens, 1 token/ms
    expect(bucket.consume(5)).toBe(true);
    expect(bucket.consume(5)).toBe(true);
    expect(bucket.consume(1)).toBe(false);
  });

  it('should refill tokens over time', async () => {
    const bucket = new TokenBucket(10, 0.1); // 10 tokens, 0.1 token/ms
    bucket.consume(10); // Empty the bucket
    
    await sleep(100); // Wait 100ms
    expect(bucket.consume(10)).toBe(true); // Should have ~10 tokens
  });
});
```

## Output
- Token bucket rate limiter implementation
- Per-tool, per-session, and global rate limiting
- Proper error responses with retry information
- Rate limit headers in responses

## Related Skills
- `policy-engine` - Integrate rate limiting as a policy
- `cost-tracker` - Combine with cost-based limits
- `testing` - Test rate limiter implementation
