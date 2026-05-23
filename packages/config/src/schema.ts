import { z } from 'zod';

export const ruleConditionSchema = z.object({
  argument: z.string().optional(),
  pattern: z.string().optional(),
  flags: z.string().optional(),
  equals: z.unknown().optional(),
  contains: z.string().optional(),
  gt: z.number().optional(),
  lt: z.number().optional(),
});

export const ruleSchema = z.object({
  id: z.string().min(1),
  type: z.enum(['allow', 'block', 'approval_required']),
  tools: z.array(z.string()).optional(),
  conditions: z.array(ruleConditionSchema).default([]),
  priority: z.number().int().default(0),
  description: z.string().optional(),
});

export const rateLimitConfigSchema = z.object({
  global: z
    .object({
      requests_per_minute: z.number().positive(),
      burst_capacity: z.number().positive(),
    })
    .optional(),
  per_tool: z
    .record(
      z.string(),
      z.object({
        requests_per_minute: z.number().positive(),
        burst_capacity: z.number().positive(),
      }),
    )
    .optional(),
  per_session: z
    .object({
      requests_per_minute: z.number().positive(),
      burst_capacity: z.number().positive(),
    })
    .optional(),
});

export const costConfigSchema = z.object({
  session_budget: z.number().nonnegative().optional(),
  tool_costs: z.record(z.string(), z.number().nonnegative()).optional(),
  budget_action: z.enum(['block', 'warn']).default('block'),
});

export const validationRuleSchema = z.object({
  id: z.string().min(1),
  tools: z.array(z.string()).optional(),
  argument: z.string().optional(),
  type: z.enum(['regex', 'shell_safe', 'sql_safe', 'custom']).default('regex'),
  patterns: z
    .array(
      z.object({
        pattern: z.string(),
        flags: z.string().optional(),
        message: z.string(),
      }),
    )
    .optional(),
});

export const approvalConfigSchema = z.object({
  default_timeout_ms: z.number().positive().default(300000),
  max_pending_approvals: z.number().positive().default(1000),
  required_for: z
    .array(
      z.object({
        tools: z.array(z.string()).optional(),
        conditions: z.array(ruleConditionSchema).optional(),
        approvers: z.array(z.string()).optional(),
        min_approvals: z.number().positive().optional(),
      }),
    )
    .optional(),
});

export const auditConfigSchema = z.object({
  level: z.enum(['none', 'summary', 'full']).default('full'),
  output: z
    .array(
      z.object({
        type: z.enum(['file', 'stdout']),
        path: z.string().optional(),
        format: z.enum(['json']).default('json'),
        rotation: z.enum(['daily', 'size']).optional(),
        max_files: z.number().positive().optional(),
        compress: z.boolean().optional(),
        endpoint: z.string().optional(),
        api_key_env: z.string().optional(),
      }),
    )
    .optional(),
  redaction: z
    .object({
      enabled: z.boolean().default(true),
      patterns: z
        .array(
          z.object({
            name: z.string(),
            pattern: z.string(),
            replacement: z.string(),
          }),
        )
        .optional(),
    })
    .optional(),
});

export const policyConfigSchema = z.object({
  version: z.string().default('1.0'),
  settings: z
    .object({
      read_only: z.boolean().default(false),
      default_action: z.enum(['block', 'allow']).default('block'),
      audit_level: z.enum(['none', 'summary', 'full']).default('full'),
    })
    .default({ read_only: false, default_action: 'block', audit_level: 'full' }),
  rate_limits: rateLimitConfigSchema.optional(),
  cost: costConfigSchema.optional(),
  validation: z
    .object({
      rules: z.array(validationRuleSchema).default([]),
    })
    .optional(),
  rules: z.array(ruleSchema).default([]),
  approvals: approvalConfigSchema.optional(),
  audit: auditConfigSchema.optional(),
  read_only_exceptions: z
    .array(
      z.object({
        tools: z.array(z.string()).optional(),
        conditions: z.array(ruleConditionSchema).optional(),
      }),
    )
    .optional(),
  emergency_override: z
    .object({
      enabled: z.boolean().default(false),
      token_env: z.string().optional(),
    })
    .optional(),
  approval_api: z
    .object({
      token_env: z.string().min(1),
      bind_host: z.string().default('127.0.0.1'),
    })
    .optional(),
});

export type PolicyConfig = z.infer<typeof policyConfigSchema>;
export type Rule = z.infer<typeof ruleSchema>;
export type RuleCondition = z.infer<typeof ruleConditionSchema>;
export type ValidationRule = z.infer<typeof validationRuleSchema>;
export type RateLimitConfig = z.infer<typeof rateLimitConfigSchema>;
export type CostConfig = z.infer<typeof costConfigSchema>;
export type ApprovalConfig = z.infer<typeof approvalConfigSchema>;
export type AuditConfig = z.infer<typeof auditConfigSchema>;
