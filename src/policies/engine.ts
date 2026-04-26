import type { RequestContext } from '../middleware/context.js';
import type { PolicyConfig, Rule, RuleCondition } from '../config/schema.js';
import { globToRegex, safeRegExp } from '../utils/safe-regex.js';

/**
 * Result of evaluating a policy against a request.
 */
export interface EvaluationResult {
  action: 'ALLOW' | 'BLOCK' | 'APPROVAL_REQUIRED';
  rule?: Rule;
  reason?: string;
}

/**
 * The policy engine evaluates incoming tool calls against configured rules.
 * Rules are evaluated in priority order (highest first). The first matching rule wins.
 * If no rule matches, the default action from settings is applied.
 */
export class PolicyEngine {
  private readonly rules: Rule[];
  private readonly defaultAction: 'ALLOW' | 'BLOCK';

  constructor(config: PolicyConfig) {
    this.rules = [...config.rules].sort((a, b) => b.priority - a.priority);
    this.defaultAction =
      config.settings?.default_action?.toUpperCase() === 'ALLOW' ? 'ALLOW' : 'BLOCK';
  }

  /**
   * Evaluate the given request context against the loaded policy.
   */
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
    // A condition with no comparators is treated as "always match" so a rule
    // can target a tool by name alone.
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
    // eslint-disable-next-line security/detect-object-injection
    return args[path];
  }
}
