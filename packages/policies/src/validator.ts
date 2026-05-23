import type { RequestContext, Middleware, MiddlewareResult } from '@reaatech/tool-use-firewall-core';
import { ValidationError } from '@reaatech/tool-use-firewall-core';
import type { ValidationRule } from '@reaatech/tool-use-firewall-config';
import { globToRegex, safeRegExp } from '@reaatech/tool-use-firewall-core';
import { SQLValidator } from './sql-validator.js';
import type { SQLValidationConfig } from './sql-validator.js';

export interface ValidationResult {
  valid: boolean;
  reason?: string;
  ruleId?: string;
}

export type ValidatorFn = (value: unknown) => ValidationResult;

export class ArgumentValidator implements Middleware {
  private readonly validators = new Map<string, ValidatorFn>();
  private readonly rules: ValidationRule[];
  private readonly sqlValidator?: SQLValidator;

  constructor(
    rules: ValidationRule[] = [],
    sqlConfig?: SQLValidationConfig,
  ) {
    this.rules = rules;
    this.registerDefaultValidators();
    if (sqlConfig) {
      this.sqlValidator = new SQLValidator(sqlConfig);
    }
  }

  async execute(context: RequestContext): Promise<MiddlewareResult> {
    if (!context.toolName || !context.arguments) {
      return { action: 'CONTINUE' };
    }

    const result = this.validate(context.toolName, context.arguments);
    if (!result.valid) {
      throw new ValidationError({
        message: result.reason ?? 'Argument validation failed',
        requestId: context.requestId,
        details: { ruleId: result.ruleId, toolName: context.toolName },
      });
    }

    return { action: 'CONTINUE' };
  }

  private validate(toolName: string, args: Record<string, unknown>): ValidationResult {
    for (const rule of this.rules) {
      if (!this.matchesTool(toolName, rule.tools)) continue;

      const value = rule.argument ? args[rule.argument] : undefined;

      if (rule.type === 'sql_safe' && this.sqlValidator && typeof value === 'string') {
        const sqlResult = this.sqlValidator.validate(value);
        if (!sqlResult.valid) {
          return {
            valid: false,
            reason: sqlResult.reason ?? 'SQL validation failed',
            ruleId: rule.id,
          };
        }
      } else {
        const validator = this.validators.get(rule.type);
        if (validator) {
          const result = validator(value);
          if (!result.valid) {
            return { valid: false, reason: result.reason, ruleId: rule.id };
          }
        }
      }

      if (rule.type === 'regex' && rule.patterns && typeof value === 'string') {
        for (const pattern of rule.patterns) {
          try {
            const regex = safeRegExp(pattern.pattern, pattern.flags ?? '');
            if (regex.test(value)) {
              return {
                valid: false,
                reason: pattern.message,
                ruleId: rule.id,
              };
            }
          } catch {
            return {
              valid: false,
              reason: `Invalid regex pattern in rule: ${rule.id}`,
              ruleId: rule.id,
            };
          }
        }
      }
    }

    return { valid: true };
  }

  private matchesTool(toolName: string, tools?: string[]): boolean {
    if (!tools || tools.length === 0) return true;
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

  private registerDefaultValidators(): void {
    this.validators.set('shell_safe', (value: unknown) => {
      if (typeof value !== 'string') return { valid: true };
      const dangerous = [';', '&&', '||', '|', '`', '$(', '${', '\n', '\r', '>', '<', '\\'];
      for (const seq of dangerous) {
        if (value.includes(seq)) {
          return {
            valid: false,
            reason: `Contains dangerous shell sequence: ${JSON.stringify(seq)}`,
          };
        }
      }
      return { valid: true };
    });

    this.validators.set('sql_safe', (value: unknown) => {
      if (typeof value !== 'string') return { valid: true };
      const dangerousPatterns = [
        /DROP\s+TABLE/i,
        /DELETE\s+FROM\s+\w+\s*$/i,
        /TRUNCATE/i,
        /;\s*DROP/i,
        /UNION\s+SELECT/i,
        /OR\s+1\s*=\s*1/i,
      ];
      for (const pattern of dangerousPatterns) {
        if (pattern.test(value)) {
          return { valid: false, reason: `Blocked by SQL pattern: ${pattern.source}` };
        }
      }
      return { valid: true };
    });
  }
}
