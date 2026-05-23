import type { RequestContext, Middleware, MiddlewareResult } from '@reaatech/tool-use-firewall-core';
import { BudgetExceededError } from '@reaatech/tool-use-firewall-core';
import type { CostConfig } from '@reaatech/tool-use-firewall-config';

interface SessionCost {
  totalCost: number;
  lastAccessed: number;
}

export class CostTracker implements Middleware {
  private readonly sessions = new Map<string, SessionCost>();
  private readonly sessionBudget: number;
  private readonly toolCosts: Record<string, number>;
  private readonly budgetAction: 'block' | 'warn';
  private readonly sessionTtlMs = 3600000;
  private readonly maxSessions = 10000;

  constructor(config: CostConfig) {
    this.sessionBudget = config.session_budget ?? Number.POSITIVE_INFINITY;
    this.toolCosts = config.tool_costs ?? {};
    this.budgetAction = config.budget_action ?? 'block';
  }

  async execute(context: RequestContext): Promise<MiddlewareResult> {
    const estimate = this.estimateCost(context.toolName);
    const session = this.getOrCreateSession(context.sessionId);

    if (session.totalCost + estimate > this.sessionBudget) {
      if (this.budgetAction === 'block') {
        throw new BudgetExceededError({
          message: `Session budget exceeded: ${session.totalCost + estimate} > ${this.sessionBudget}`,
          requestId: context.requestId,
          details: {
            sessionBudget: this.sessionBudget,
            currentCost: session.totalCost,
            estimatedCost: estimate,
          },
        });
      }
      return {
        action: 'CONTINUE',
        metadata: {
          budgetWarning: true,
          sessionBudget: this.sessionBudget,
          currentCost: session.totalCost,
          estimatedCost: estimate,
        },
      };
    }

    session.totalCost += estimate;
    return { action: 'CONTINUE', metadata: { cost: estimate, totalCost: session.totalCost } };
  }

  private estimateCost(toolName?: string): number {
    if (!toolName) return 0;
    return this.toolCosts[toolName] ?? 0;
  }

  private getOrCreateSession(sessionId: string): SessionCost {
    this.evictStaleSessions();

    let session = this.sessions.get(sessionId);
    if (!session) {
      session = { totalCost: 0, lastAccessed: Date.now() };
      this.sessions.set(sessionId, session);
    } else {
      session.lastAccessed = Date.now();
    }
    return session;
  }

  private evictStaleSessions(): void {
    if (this.sessions.size < this.maxSessions) return;
    const now = Date.now();
    for (const [id, session] of this.sessions.entries()) {
      if (now - session.lastAccessed > this.sessionTtlMs) {
        this.sessions.delete(id);
      }
    }
    if (this.sessions.size >= this.maxSessions) {
      const entries = Array.from(this.sessions.entries());
      entries.sort((a, b) => a[1].lastAccessed - b[1].lastAccessed);
      const toRemove = entries.slice(0, entries.length - this.maxSessions + 1);
      for (const [id] of toRemove) {
        this.sessions.delete(id);
      }
    }
  }
}
