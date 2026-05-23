import type { RateLimitConfig } from '@reaatech/tool-use-firewall-config';
import type {
  Middleware,
  MiddlewareResult,
  RequestContext,
} from '@reaatech/tool-use-firewall-core';
import { RateLimitError } from '@reaatech/tool-use-firewall-core';

export class TokenBucket {
  private tokens: number;
  private lastRefill: number;

  constructor(
    private readonly capacity: number,
    private readonly refillRatePerMs: number,
  ) {
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  consume(tokens = 1): boolean {
    this.refill();
    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return true;
    }
    return false;
  }

  getWaitTimeMs(tokens = 1): number {
    this.refill();
    if (this.tokens >= tokens) return 0;
    const needed = tokens - this.tokens;
    return Math.ceil(needed / this.refillRatePerMs);
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const newTokens = elapsed * this.refillRatePerMs;
    this.tokens = Math.min(this.capacity, this.tokens + newTokens);
    this.lastRefill = now;
  }
}

interface ToolRateLimitConfig {
  requests_per_minute: number;
  burst_capacity: number;
}

export class RateLimiter implements Middleware {
  private readonly globalLimiter?: TokenBucket;
  private readonly toolLimiters = new Map<string, TokenBucket>();
  private readonly sessionLimiters = new Map<string, TokenBucket>();
  private readonly sessionLastAccessed = new Map<string, number>();
  private readonly toolConfigs: Record<string, ToolRateLimitConfig>;
  private readonly defaultToolConfig: ToolRateLimitConfig;
  private readonly sessionConfig: ToolRateLimitConfig;
  private readonly sessionTtlMs: number;
  private readonly maxSessionLimiters: number;
  private readonly maxToolLimiters: number;

  constructor(config: RateLimitConfig) {
    if (config.global) {
      this.globalLimiter = new TokenBucket(
        config.global.burst_capacity,
        config.global.requests_per_minute / 60000,
      );
    }
    this.toolConfigs = config.per_tool ?? {};
    this.defaultToolConfig = config.global ?? { requests_per_minute: 60, burst_capacity: 10 };
    this.sessionConfig = config.per_session ?? this.defaultToolConfig;
    this.sessionTtlMs = 3600000;
    this.maxSessionLimiters = 10000;
    this.maxToolLimiters = 1000;
  }

  async execute(context: RequestContext): Promise<MiddlewareResult> {
    if (this.globalLimiter && !this.globalLimiter.consume()) {
      const wait = this.globalLimiter.getWaitTimeMs();
      throw new RateLimitError({
        message: 'Global rate limit exceeded',
        requestId: context.requestId,
        retryAfterMs: wait,
        details: { limitType: 'global' },
      });
    }

    if (context.toolName) {
      const toolLimiter = this.getToolLimiter(context.toolName);
      if (!toolLimiter.consume()) {
        const wait = toolLimiter.getWaitTimeMs();
        throw new RateLimitError({
          message: `Rate limit exceeded for tool: ${context.toolName}`,
          requestId: context.requestId,
          retryAfterMs: wait,
          details: { limitType: 'tool', toolName: context.toolName },
        });
      }
    }

    const sessionLimiter = this.getSessionLimiter(context.sessionId);
    if (!sessionLimiter.consume()) {
      const wait = sessionLimiter.getWaitTimeMs();
      throw new RateLimitError({
        message: `Session rate limit exceeded for session: ${context.sessionId}`,
        requestId: context.requestId,
        retryAfterMs: wait,
        details: { limitType: 'session', sessionId: context.sessionId },
      });
    }

    return { action: 'CONTINUE' };
  }

  private getToolLimiter(toolName: string): TokenBucket {
    this.evictStaleToolLimiters();

    if (!this.toolLimiters.has(toolName)) {
      const config = this.toolConfigs[toolName] ?? this.defaultToolConfig;
      this.toolLimiters.set(
        toolName,
        new TokenBucket(config.burst_capacity, config.requests_per_minute / 60000),
      );
    }
    return this.toolLimiters.get(toolName) as TokenBucket;
  }

  private getSessionLimiter(sessionId: string): TokenBucket {
    this.evictStaleSessions();

    if (!this.sessionLimiters.has(sessionId)) {
      this.sessionLimiters.set(
        sessionId,
        new TokenBucket(
          this.sessionConfig.burst_capacity,
          this.sessionConfig.requests_per_minute / 60000,
        ),
      );
    }
    this.sessionLastAccessed.set(sessionId, Date.now());
    return this.sessionLimiters.get(sessionId) as TokenBucket;
  }

  private evictStaleToolLimiters(): void {
    if (this.toolLimiters.size < this.maxToolLimiters) return;
    const entries = Array.from(this.toolLimiters.entries());
    const toRemove = entries.slice(0, entries.length - this.maxToolLimiters + 1);
    for (const [key] of toRemove) {
      this.toolLimiters.delete(key);
    }
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
    if (this.sessionLimiters.size >= this.maxSessionLimiters) {
      const entries = Array.from(this.sessionLastAccessed.entries());
      entries.sort((a, b) => a[1] - b[1]);
      const toRemove = entries.slice(0, entries.length - this.maxSessionLimiters + 1);
      for (const [id] of toRemove) {
        this.sessionLimiters.delete(id);
        this.sessionLastAccessed.delete(id);
      }
    }
  }
}
