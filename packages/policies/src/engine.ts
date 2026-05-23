import type { PolicyConfig, Rule, RuleCondition } from '@reaatech/tool-use-firewall-config';
import type { RequestContext } from '@reaatech/tool-use-firewall-core';
import { globToRegex, safeRegExp } from '@reaatech/tool-use-firewall-core';

export interface EvaluationResult {
  action: 'ALLOW' | 'BLOCK' | 'APPROVAL_REQUIRED';
  rule?: Rule;
  reason?: string;
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

  constructor(config: PolicyConfig) {
    this.rules = [...config.rules].sort((a, b) => b.priority - a.priority);
    this.defaultAction =
      config.settings?.default_action?.toUpperCase() === 'ALLOW' ? 'ALLOW' : 'BLOCK';
  }

  async evaluate(context: RequestContext): Promise<EvaluationResult> {
    const applicableRules = this.getApplicableRules(context);

    for (const rule of applicableRules) {
      const matches = await this.evaluateConditions(rule.conditions, context);
      if (matches) {
        return {
          action: rule.type.toUpperCase() as EvaluationResult['action'],
          rule,
          reason: rule.description ?? `Matched rule: ${rule.id}`,
        };
      }
    }

    return { action: this.defaultAction };
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

  private async evaluateConditions(
    conditions: RuleCondition[],
    context: RequestContext,
  ): Promise<boolean> {
    if (conditions.length === 0) {
      return true;
    }

    for (const condition of conditions) {
      if (!(await this.evaluateCondition(condition, context))) {
        return false;
      }
    }
    return true;
  }

  private async evaluateCondition(
    condition: RuleCondition,
    context: RequestContext,
  ): Promise<boolean> {
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
