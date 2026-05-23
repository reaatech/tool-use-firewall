import type {
  ConditionGroup,
  PolicyConfig,
  Rule,
  RuleCondition,
} from '@reaatech/tool-use-firewall-config';
import type { RequestContext } from '@reaatech/tool-use-firewall-core';
import { globToRegex, safeRegExp } from '@reaatech/tool-use-firewall-core';

export interface EvaluationResult {
  action: 'ALLOW' | 'BLOCK' | 'APPROVAL_REQUIRED';
  rule?: Rule;
  reason?: string;
}

interface SessionTrust {
  safeCallCount: number;
  lastAccessed: number;
  toolCounts: Map<string, number>;
}

/** Evaluates policy rules in priority order against incoming tool-call requests.
 *
 * Rules are sorted by priority (highest first). The first rule whose tool
 * pattern and conditions match the request determines the outcome
 * (ALLOW, BLOCK, or APPROVAL_REQUIRED). If no rule matches, the configured
 * default action is used.
 *
 * @example
 * ```ts
 * const config = loadPolicyConfig('./policies/database-safe.yaml');
 * const engine = new PolicyEngine(config);
 * const result = await engine.evaluate(context);
 * if (result.action === 'BLOCK') {
 *   throw new Error(`Blocked: ${result.reason}`);
 * }
 * ```
 */
export class PolicyEngine {
  private readonly rules: Rule[];
  private readonly defaultAction: 'ALLOW' | 'BLOCK';
  private readonly sessionTrust = new Map<string, SessionTrust>();
  private readonly safeCallThreshold: number;
  private readonly trustPatterns: string[];
  private readonly autoApprovalEnabled: boolean;

  constructor(config: PolicyConfig) {
    this.rules = [...config.rules].sort((a, b) => b.priority - a.priority);
    this.defaultAction =
      config.settings?.default_action?.toUpperCase() === 'ALLOW' ? 'ALLOW' : 'BLOCK';
    this.autoApprovalEnabled = config.approvals?.auto_approval?.enabled ?? false;
    this.safeCallThreshold = config.approvals?.auto_approval?.safe_call_threshold ?? 50;
    this.trustPatterns = config.approvals?.auto_approval?.trust_tool_patterns ?? [];
  }

  async evaluate(context: RequestContext): Promise<EvaluationResult> {
    const applicableRules = this.getApplicableRules(context);

    for (const rule of applicableRules) {
      if (rule.timeWindow && !this.isInTimeWindow(rule.timeWindow)) continue;

      const matches = this.evaluateConditions(rule.conditions, rule.conditionGroups, context);
      if (matches) {
        const action = rule.type.toUpperCase() as EvaluationResult['action'];

        if (
          this.autoApprovalEnabled &&
          action === 'APPROVAL_REQUIRED' &&
          this.isTrustedSession(context)
        ) {
          return {
            action: 'ALLOW',
            rule,
            reason: `${rule.description ?? `Matched rule: ${rule.id}`} (auto-approved: trusted session)`,
          };
        }

        return {
          action,
          rule,
          reason: rule.description ?? `Matched rule: ${rule.id}`,
        };
      }
    }

    return { action: this.defaultAction };
  }

  recordSafeCall(context: RequestContext): void {
    if (!this.autoApprovalEnabled) return;

    const sessionId = context.sessionId;
    let trust = this.sessionTrust.get(sessionId);
    if (!trust) {
      trust = { safeCallCount: 0, lastAccessed: Date.now(), toolCounts: new Map() };
      this.sessionTrust.set(sessionId, trust);
    }

    trust.safeCallCount++;
    trust.lastAccessed = Date.now();

    if (context.toolName) {
      const count = trust.toolCounts.get(context.toolName) ?? 0;
      trust.toolCounts.set(context.toolName, count + 1);
    }

    if (this.sessionTrust.size > 10000) {
      const oldest = Array.from(this.sessionTrust.entries()).sort(
        (a, b) => a[1].lastAccessed - b[1].lastAccessed,
      );
      for (const [id] of oldest.slice(0, oldest.length - 9000)) {
        this.sessionTrust.delete(id);
      }
    }
  }

  private isTrustedSession(context: RequestContext): boolean {
    const trust = this.sessionTrust.get(context.sessionId);
    if (!trust) return false;

    if (trust.safeCallCount >= this.safeCallThreshold) return true;

    if (this.trustPatterns.length > 0 && context.toolName) {
      const matched = this.trustPatterns.some((p) => {
        try {
          return globToRegex(p).test(context.toolName ?? '');
        } catch {
          return p === context.toolName;
        }
      });
      if (matched && trust.safeCallCount > 0) return true;
    }

    return false;
  }

  private isInTimeWindow(tw: {
    days?: string[];
    after?: string;
    before?: string;
    timezone?: string;
  }): boolean {
    const tz = tw.timezone ?? 'UTC';
    let now: Date;
    try {
      const formatter = new Intl.DateTimeFormat('en-US', {
        timeZone: tz,
        weekday: 'short',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      });
      const parts = formatter.formatToParts(new Date());
      const get = (t: string) => parts.find((p) => p.type === t)?.value ?? '';
      const day = get('weekday').toLowerCase();
      const hour = get('hour');
      const minute = get('minute');
      const time = `${hour}:${minute}`;

      if (tw.days && tw.days.length > 0) {
        if (!tw.days.includes(day)) return false;
      }

      if (tw.after) {
        if (time < tw.after) return false;
      }

      if (tw.before) {
        if (time >= tw.before) return false;
      }

      return true;
    } catch {
      now = new Date();
      if (tw.days && tw.days.length > 0) {
        const days = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
        if (!tw.days.includes(days[now.getDay()])) return false;
      }
      return true;
    }
  }

  private getApplicableRules(context: RequestContext): Rule[] {
    if (!context.toolName) {
      return this.rules;
    }
    return this.rules.filter((rule) =>
      context.toolName ? this.matchesTool(context.toolName, rule.tools) : true,
    );
  }

  private matchesTool(toolName: string, tools?: string[]): boolean {
    if (!tools || tools.length === 0) {
      return true;
    }
    return tools.some((pattern) => {
      if (pattern.includes('*')) {
        try {
          return globToRegex(pattern).test(toolName);
        } catch {
          return pattern === toolName;
        }
      }
      return pattern === toolName;
    });
  }

  private evaluateConditions(
    conditions: RuleCondition[],
    conditionGroups: ConditionGroup[] | undefined,
    context: RequestContext,
  ): boolean {
    if (conditions.length === 0 && (!conditionGroups || conditionGroups.length === 0)) {
      return true;
    }

    if (conditions.length > 0) {
      if (!this.allConditionsMatch(conditions, context)) return false;
    }

    if (conditionGroups && conditionGroups.length > 0) {
      return conditionGroups.every((group) => this.evaluateConditionGroup(group, context));
    }

    return true;
  }

  private evaluateConditionGroup(group: ConditionGroup, context: RequestContext): boolean {
    if (group.timeWindow && !this.isInTimeWindow(group.timeWindow)) {
      return false;
    }

    const allOfMatch =
      !group.allOf || group.allOf.length === 0 || this.allConditionsMatch(group.allOf, context);
    if (!allOfMatch) return false;

    const anyOfMatch =
      !group.anyOf ||
      group.anyOf.length === 0 ||
      group.anyOf.some((c) => this.evaluateCondition(c, context));
    if (!anyOfMatch) return false;

    return true;
  }

  private allConditionsMatch(conditions: RuleCondition[], context: RequestContext): boolean {
    for (const condition of conditions) {
      if (!this.evaluateCondition(condition, context)) {
        return false;
      }
    }
    return true;
  }

  private evaluateCondition(condition: RuleCondition, context: RequestContext): boolean {
    const hasComparator =
      condition.pattern !== undefined ||
      condition.equals !== undefined ||
      condition.contains !== undefined ||
      condition.gt !== undefined ||
      condition.lt !== undefined;
    if (!hasComparator) return true;

    const value = condition.argument
      ? this.extractArgValue(context.arguments, condition.argument)
      : undefined;

    if (condition.pattern !== undefined) {
      if (typeof value !== 'string') return false;
      try {
        const flags = condition.flags ?? '';
        const regex = safeRegExp(condition.pattern, flags);
        if (!regex.test(value)) return false;
      } catch {
        return false;
      }
    }

    if (condition.equals !== undefined) {
      if (value !== condition.equals) return false;
    }

    if (condition.contains !== undefined) {
      if (typeof value !== 'string' || !value.includes(condition.contains)) return false;
    }

    if (condition.gt !== undefined) {
      if (typeof value !== 'number' || !(value > condition.gt)) return false;
    }

    if (condition.lt !== undefined) {
      if (typeof value !== 'number' || !(value < condition.lt)) return false;
    }

    return true;
  }

  private extractArgValue(args: Record<string, unknown> | undefined, path: string): unknown {
    if (!args) return undefined;
    const segments = path.split('.');
    let current: unknown = args;
    for (const segment of segments) {
      if (current === null || current === undefined || typeof current !== 'object') {
        return undefined;
      }
      current = (current as Record<string, unknown>)[segment];
    }
    return current;
  }
}
