import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPolicyConfig } from '@reaatech/tool-use-firewall-config';
import {
  createRequestContext,
  PolicyViolationError,
  ValidationError,
} from '@reaatech/tool-use-firewall-core';
import {
  ArgumentValidator,
  CostTracker,
  PolicyEngine,
  RateLimiter,
  ReadOnlyCheck,
} from '@reaatech/tool-use-firewall-policies';
import { describe, expect, it } from 'vitest';

const __dirname = dirname(fileURLToPath(import.meta.url));
const policiesDir = resolve(__dirname, '..', '..', 'policies');

describe('E2E: Default Policy Pipeline', () => {
  it('blocks unknown tools with default policy (default_action: block)', async () => {
    const config = loadPolicyConfig(resolve(policiesDir, 'default.yaml'));
    const engine = new PolicyEngine(config);

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'unknown_tool',
    });

    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('BLOCK');
  });

  it('passes known tools through rate limiter under limit', async () => {
    const config = loadPolicyConfig(resolve(policiesDir, 'default.yaml'));
    const rateLimits = config.rate_limits;
    if (!rateLimits) throw new Error('Expected rate_limits in default policy');
    const rateLimiter = new RateLimiter(rateLimits);

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'echo',
    });

    const result = await rateLimiter.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('enforces session cost budget', async () => {
    const config = loadPolicyConfig(resolve(policiesDir, 'default.yaml'));
    const cost = config.cost;
    if (!cost) throw new Error('Expected cost config in default policy');
    const costTracker = new CostTracker(cost);

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'expensive_tool',
    });

    const result = await costTracker.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });
});

describe('E2E: Database Safety Policy', () => {
  function getValidator() {
    const config = loadPolicyConfig(resolve(policiesDir, 'database-safe.yaml'));
    const rules = config.validation?.rules;
    if (!rules) throw new Error('Expected validation rules in database-safe policy');
    return new ArgumentValidator(rules);
  }

  it('blocks DROP TABLE statements', async () => {
    const validator = getValidator();

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'DROP TABLE users CASCADE' },
    });

    await expect(validator.execute(ctx)).rejects.toThrow(ValidationError);
  });

  it('blocks TRUNCATE statements', async () => {
    const validator = getValidator();

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'TRUNCATE TABLE audit_log' },
    });

    await expect(validator.execute(ctx)).rejects.toThrow(ValidationError);
  });

  it('allows safe SELECT statements', async () => {
    const validator = getValidator();

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users WHERE id = 1' },
    });

    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('blocks DELETE without WHERE clause', async () => {
    const validator = getValidator();

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'DELETE FROM users' },
    });

    await expect(validator.execute(ctx)).rejects.toThrow(ValidationError);
  });

  it('allows database_describe tool', async () => {
    const config = loadPolicyConfig(resolve(policiesDir, 'database-safe.yaml'));
    const engine = new PolicyEngine(config);

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_describe',
    });

    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });
});

describe('E2E: Read-Only Policy', () => {
  it('blocks writes in read-only mode', async () => {
    const config = loadPolicyConfig(resolve(policiesDir, 'read-only.yaml'));
    const readOnly = new ReadOnlyCheck({
      enabled: config.settings?.read_only ?? false,
      exceptions: config.read_only_exceptions,
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_write',
      arguments: { path: '/tmp/test.txt', content: 'hello' },
    });

    await expect(readOnly.execute(ctx)).rejects.toThrow(PolicyViolationError);
  });

  it('allows reads in read-only mode', async () => {
    const config = loadPolicyConfig(resolve(policiesDir, 'read-only.yaml'));
    const readOnly = new ReadOnlyCheck({
      enabled: config.settings?.read_only ?? false,
      exceptions: config.read_only_exceptions,
    });

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_read',
      arguments: { path: '/tmp/test.txt' },
    });

    const result = await readOnly.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });
});

describe('E2E: Full Pipeline Integration', () => {
  it('runs full pipeline: rate limiter -> cost tracker -> validator -> policy engine', async () => {
    const config = loadPolicyConfig(resolve(policiesDir, 'database-safe.yaml'));

    const rateLimits = config.rate_limits;
    if (!rateLimits) throw new Error('Expected rate_limits in database-safe policy');

    const rules = config.validation?.rules;
    if (!rules) throw new Error('Expected validation rules in database-safe policy');

    const rateLimiter = new RateLimiter(rateLimits);
    const costTracker = new CostTracker(
      config.cost ?? { session_budget: 100, budget_action: 'block' },
    );
    const validator = new ArgumentValidator(rules);
    const engine = new PolicyEngine(config);

    const ctx = createRequestContext({
      requestId: 'r-full',
      sessionId: 's-full',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'SELECT 1' },
    });

    const rlResult = await rateLimiter.execute(ctx);
    expect(rlResult.action).toBe('CONTINUE');

    const ctResult = await costTracker.execute(ctx);
    expect(ctResult.action).toBe('CONTINUE');

    const vResult = await validator.execute(ctx);
    expect(vResult.action).toBe('CONTINUE');

    const peResult = await engine.evaluate(ctx);
    expect(peResult.action).toBe('ALLOW');
  });
});
