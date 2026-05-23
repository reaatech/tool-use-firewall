import { describe, expect, it } from 'vitest';
import { policyConfigSchema } from './schema.js';

describe('policyConfigSchema', () => {
  it('validates a minimal policy', () => {
    const result = policyConfigSchema.safeParse({});
    expect(result.success).toBe(true);
    expect(result.data?.settings?.default_action).toBe('block');
    expect(result.data?.version).toBe('1.0');
  });

  it('validates a full policy', () => {
    const config = {
      version: '1.0',
      settings: { read_only: true, default_action: 'block', audit_level: 'full' },
      rules: [{ id: 'rule1', type: 'block', tools: ['dangerous_tool'], priority: 10 }],
      rate_limits: {
        global: { requests_per_minute: 60, burst_capacity: 10 },
      },
    };
    const result = policyConfigSchema.safeParse(config);
    expect(result.success).toBe(true);
  });

  it('rejects invalid rule type', () => {
    const result = policyConfigSchema.safeParse({
      rules: [{ id: 'r1', type: 'invalid_type' }],
    });
    expect(result.success).toBe(false);
  });
});
