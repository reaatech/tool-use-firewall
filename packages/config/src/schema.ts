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

export const exceptionConditionSchema = z.object({
  argument: z.string().min(1),
  pattern: z.string().min(1),
  flags: z.string().optional(),
});

export const timeWindowSchema = z.object({
  days: z.array(z.enum(['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'])).optional(),
  after: z
    .string()
    .regex(/^\d{2}:\d{2}$/, 'Use HH:MM format')
    .optional(),
  before: z
    .string()
    .regex(/^\d{2}:\d{2}$/, 'Use HH:MM format')
    .optional(),
  timezone: z.string().default('UTC'),
});

export const conditionGroupSchema = z.object({
  allOf: z.array(ruleConditionSchema).optional(),
  anyOf: z.array(ruleConditionSchema).optional(),
  timeWindow: timeWindowSchema.optional(),
});

export const ruleSchema = z.object({
  id: z.string().min(1),
  type: z.enum(['allow', 'block', 'approval_required']),
  tools: z.array(z.string()).optional(),
  conditions: z.array(ruleConditionSchema).default([]),
  conditionGroups: z.array(conditionGroupSchema).optional(),
  timeWindow: timeWindowSchema.optional(),
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

export const schemaValidationRuleSchema = z.object({
  id: z.string().min(1),
  tools: z.array(z.string()).optional(),
});

export const validationRuleSchema = z.object({
  id: z.string().min(1),
  tools: z.array(z.string()).optional(),
  argument: z.string().optional(),
  type: z
    .enum(['regex', 'shell_safe', 'sql_safe', 'custom', 'json_schema', 'secret_scan'])
    .default('regex'),
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

export const secretScanConfigSchema = z.object({
  enabled: z.boolean().default(false),
  patterns: z
    .array(
      z.object({
        name: z.string(),
        pattern: z.string(),
        flags: z.string().optional(),
      }),
    )
    .optional(),
});

export const anomalyConfigSchema = z.object({
  enabled: z.boolean().default(false),
  window_size: z.number().positive().default(50),
  sensitivity: z.number().min(0).max(1).default(0.7),
});

export const slackApproverSchema = z.object({
  type: z.literal('slack'),
  webhook_url_env: z.string().min(1),
  channel: z.string().optional(),
});

export const discordApproverSchema = z.object({
  type: z.literal('discord'),
  webhook_url_env: z.string().min(1),
});

export const approverGroupSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('webhook'), url: z.string(), api_key_env: z.string().optional() }),
  z.object({ type: z.literal('cli') }),
  slackApproverSchema,
  discordApproverSchema,
]);

export const autoApprovalConfigSchema = z.object({
  enabled: z.boolean().default(false),
  safe_call_threshold: z.number().positive().default(50),
  trust_tool_patterns: z.array(z.string()).optional(),
  per_session_tracking: z.boolean().default(true),
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
  approver_groups: z.record(z.string(), approverGroupSchema).optional(),
  auto_approval: autoApprovalConfigSchema.optional(),
});

export const auditOutputSchema = z.object({
  type: z.enum(['file', 'stdout', 'sidecar']),
  path: z.string().optional(),
  format: z.enum(['json']).default('json'),
  rotation: z.enum(['daily', 'size']).optional(),
  max_files: z.number().positive().optional(),
  compress: z.boolean().optional(),
  endpoint: z.string().optional(),
  api_key_env: z.string().optional(),
});

export const auditConfigSchema = z.object({
  level: z.enum(['none', 'summary', 'full']).default('full'),
  output: z.array(auditOutputSchema).optional(),
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

export const upstreamBackendSchema = z.object({
  name: z.string().min(1),
  command: z.string(),
  args: z.array(z.string()).optional(),
  tool_patterns: z.array(z.string()).optional(),
  env: z.record(z.string(), z.string()).optional(),
});

export const metricsConfigSchema = z.object({
  enabled: z.boolean().default(false),
  port: z.number().int().positive().default(9090),
  bind_host: z.string().default('127.0.0.1'),
});

export const policyConfigSchema = z.object({
  version: z.string().default('1.0'),
  settings: z
    .object({
      read_only: z.boolean().default(false),
      default_action: z.enum(['block', 'allow']).default('block'),
      audit_level: z.enum(['none', 'summary', 'full']).default('full'),
      dry_run: z.boolean().default(false),
    })
    .default({
      read_only: false,
      default_action: 'block',
      audit_level: 'full',
      dry_run: false,
    }),
  rate_limits: rateLimitConfigSchema.optional(),
  cost: costConfigSchema.optional(),
  validation: z
    .object({
      rules: z.array(validationRuleSchema).default([]),
      schema_validation: z
        .object({
          enabled: z.boolean().default(false),
          strict: z.boolean().default(false),
          rules: z.array(schemaValidationRuleSchema).optional(),
        })
        .optional(),
    })
    .optional(),
  rules: z.array(ruleSchema).default([]),
  approvals: approvalConfigSchema.optional(),
  audit: auditConfigSchema.optional(),
  read_only_exceptions: z
    .array(
      z.object({
        tools: z.array(z.string()).optional(),
        conditions: z.array(exceptionConditionSchema),
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
  upstreams: z.array(upstreamBackendSchema).optional(),
  metrics: metricsConfigSchema.optional(),
  secret_scan: secretScanConfigSchema.optional(),
  anomaly_detection: anomalyConfigSchema.optional(),
  transports: z
    .object({
      http: z
        .object({
          enabled: z.boolean().default(false),
          port: z.number().int().positive().default(3000),
          bind_host: z.string().default('127.0.0.1'),
        })
        .optional(),
    })
    .optional(),
});

export type PolicyConfig = z.infer<typeof policyConfigSchema>;
export type Rule = z.infer<typeof ruleSchema>;
export type RuleCondition = z.infer<typeof ruleConditionSchema>;
export type ConditionGroup = z.infer<typeof conditionGroupSchema>;
export type TimeWindow = z.infer<typeof timeWindowSchema>;
export type ExceptionCondition = z.infer<typeof exceptionConditionSchema>;
export type ValidationRule = z.infer<typeof validationRuleSchema>;
export type SchemaValidationRule = z.infer<typeof schemaValidationRuleSchema>;
export type RateLimitConfig = z.infer<typeof rateLimitConfigSchema>;
export type CostConfig = z.infer<typeof costConfigSchema>;
export type ApprovalConfig = z.infer<typeof approvalConfigSchema>;
export type ApproverGroupConfig = z.infer<typeof approverGroupSchema>;
export type AutoApprovalConfig = z.infer<typeof autoApprovalConfigSchema>;
export type AuditConfig = z.infer<typeof auditConfigSchema>;
export type UpstreamBackend = z.infer<typeof upstreamBackendSchema>;
export type MetricsConfig = z.infer<typeof metricsConfigSchema>;
export type SecretScanConfig = z.infer<typeof secretScanConfigSchema>;
export type AnomalyConfig = z.infer<typeof anomalyConfigSchema>;
