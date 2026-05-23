import type {
  Middleware,
  MiddlewareResult,
  RequestContext,
} from '@reaatech/tool-use-firewall-core';

interface SessionProfile {
  toolFreq: Map<string, number>;
  lastAccessed: number;
  totalCalls: number;
}

export class AnomalyDetector implements Middleware {
  private readonly sessions = new Map<string, SessionProfile>();
  private readonly enabled: boolean;
  private readonly windowSize: number;
  private readonly sensitivity: number;
  private readonly maxSessions = 10000;
  private readonly sessionTtlMs = 3600000;

  constructor(config?: { enabled?: boolean; window_size?: number; sensitivity?: number }) {
    this.enabled = config?.enabled ?? false;
    this.windowSize = config?.window_size ?? 50;
    this.sensitivity = config?.sensitivity ?? 0.7;
  }

  async execute(context: RequestContext): Promise<MiddlewareResult> {
    if (!this.enabled || !context.toolName) {
      return { action: 'CONTINUE' };
    }

    this.evictStale();

    const profile = this.getOrCreateProfile(context.sessionId);
    profile.totalCalls++;
    profile.toolFreq.set(context.toolName, (profile.toolFreq.get(context.toolName) ?? 0) + 1);
    profile.lastAccessed = Date.now();

    if (profile.totalCalls < this.windowSize) {
      return { action: 'CONTINUE' };
    }

    const anomalyScore = this.computeAnomalyScore(profile, context.toolName);
    if (anomalyScore > this.sensitivity) {
      return {
        action: 'CONTINUE',
        metadata: {
          anomalyDetected: true,
          anomalyScore,
          recentToolCall: context.toolName,
          sessionTotalCalls: profile.totalCalls,
        },
      };
    }

    return { action: 'CONTINUE' };
  }

  private computeAnomalyScore(profile: SessionProfile, currentTool: string): number {
    const total = profile.totalCalls || 1;
    const freq = profile.toolFreq.get(currentTool) ?? 0;

    if (freq === 0) return 1.0;

    const diversity = profile.toolFreq.size;
    const expectedFreq = total / Math.max(diversity, 1);

    if (expectedFreq === 0) return 1.0;

    const ratio = freq / expectedFreq;
    if (ratio >= 1) return 0;

    return 1 - Math.min(ratio, 1);
  }

  private getOrCreateProfile(sessionId: string): SessionProfile {
    let profile = this.sessions.get(sessionId);
    if (!profile) {
      profile = { toolFreq: new Map(), lastAccessed: Date.now(), totalCalls: 0 };
      this.sessions.set(sessionId, profile);
    }
    return profile;
  }

  private evictStale(): void {
    if (this.sessions.size < this.maxSessions) return;
    const now = Date.now();
    for (const [id, profile] of this.sessions.entries()) {
      if (now - profile.lastAccessed > this.sessionTtlMs) {
        this.sessions.delete(id);
      }
    }
    if (this.sessions.size >= this.maxSessions) {
      const entries = Array.from(this.sessions.entries());
      entries.sort((a, b) => a[1].lastAccessed - b[1].lastAccessed);
      for (const [id] of entries.slice(0, entries.length - this.maxSessions + 1)) {
        this.sessions.delete(id);
      }
    }
  }
}
