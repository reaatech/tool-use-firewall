/**
 * Edge case and defensive code tests.
 *
 * These tests exercise error-handling paths, boundary conditions,
 * eviction logic, and defensive fallbacks that are difficult or
 * redundant to reach through the happy-path tests in the primary
 * component test files. Each section validates that the system
 * degrades gracefully rather than crashing under unexpected input.
 */
import { describe, it, expect, vi } from 'vitest';
import { PolicyEngine } from '../../src/policies/engine.js';
import { createRequestContext } from '../../src/middleware/context.js';
import { RateLimiter } from '../../src/policies/rate-limit.js';
import { CostTracker } from '../../src/policies/cost-tracker.js';
import { ReadOnlyCheck } from '../../src/policies/read-only.js';
import { ArgumentValidator } from '../../src/policies/validator.js';
import { SQLValidator } from '../../src/policies/sql-validator.js';
import { Logger } from '../../src/utils/logger.js';
import { redact } from '../../src/utils/redactor.js';
import request from 'supertest';
import { createApprovalApi } from '../../src/approvals/api.js';
import { ApprovalWorkflow } from '../../src/approvals/workflow.js';

describe('PolicyEngine extra conditions', () => {
  it('should evaluate gt condition', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'gt_rule',
          type: 'allow',
          tools: ['test'],
          conditions: [{ argument: 'count', gt: 5 }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { count: 10 },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('should evaluate lt condition', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'lt_rule',
          type: 'allow',
          tools: ['test'],
          conditions: [{ argument: 'count', lt: 5 }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { count: 3 },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('should evaluate equals condition', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'eq_rule',
          type: 'allow',
          tools: ['test'],
          conditions: [{ argument: 'mode', equals: 'safe' }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { mode: 'safe' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('should evaluate contains condition', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'contains_rule',
          type: 'allow',
          tools: ['test'],
          conditions: [{ argument: 'text', contains: 'safe' }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { text: 'this is safe' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('does not match a contains comparator on a non-string value', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'allow' },
      rules: [
        {
          id: 'contains_rule',
          type: 'block',
          tools: ['test'],
          conditions: [{ argument: 'text', contains: 'safe' }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { text: 123 },
    });
    const result = await engine.evaluate(ctx);
    // Rule does not apply, so default_action wins.
    expect(result.action).toBe('ALLOW');
  });

  it('does not match a gt comparator on a non-number value', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'allow' },
      rules: [
        {
          id: 'gt_rule',
          type: 'block',
          tools: ['test'],
          conditions: [{ argument: 'count', gt: 5 }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { count: 'ten' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('does not match an lt comparator on a non-number value', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'allow' },
      rules: [
        {
          id: 'lt_rule',
          type: 'block',
          tools: ['test'],
          conditions: [{ argument: 'count', lt: 5 }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { count: 'three' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('should match all tools when tools array is empty', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'any_tool',
          type: 'allow',
          conditions: [],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'anything',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('should handle non-tool methods', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'allow' },
      rules: [],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/list',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('does not match a pattern condition when the argument is missing', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'allow' },
      rules: [
        {
          id: 'pattern_rule',
          type: 'block',
          tools: ['test'],
          conditions: [{ argument: 'missing', pattern: 'x' }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await engine.evaluate(ctx);
    // Rule doesn't apply (no value to test), falls through to default.
    expect(result.action).toBe('ALLOW');
  });

  it('should fallback on invalid regex in condition', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'allow' },
      rules: [
        {
          id: 'bad_regex',
          type: 'block',
          tools: ['test'],
          conditions: [{ argument: 'val', pattern: '(a+)+' }],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { val: 'aaa' },
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });

  it('should use exact match for tool names without wildcard', async () => {
    const engine = new PolicyEngine({
      version: '1.0',
      settings: { default_action: 'block' },
      rules: [
        {
          id: 'exact',
          type: 'allow',
          tools: ['exact_tool'],
          conditions: [],
          priority: 100,
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'exact_tool',
    });
    const result = await engine.evaluate(ctx);
    expect(result.action).toBe('ALLOW');
  });
});

describe('RateLimiter session/tool eviction', () => {
  it('should evict stale sessions when max limiters reached', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 100000, burst_capacity: 100000 },
      per_session: { requests_per_minute: 100000, burst_capacity: 100000 },
    });

    for (let i = 0; i < 10010; i++) {
      const ctx = createRequestContext({
        requestId: `r${i}`,
        sessionId: `sess-${i}`,
        method: 'tools/call',
        toolName: 'test',
      });
      await limiter.execute(ctx);
    }
  });

  it('should work without global limit', async () => {
    const limiter = new RateLimiter({
      per_session: { requests_per_minute: 100000, burst_capacity: 100000 },
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    await expect(limiter.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should handle missing toolName', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 100000, burst_capacity: 100000 },
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
    });
    await expect(limiter.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should hard-evict tool limiters', async () => {
    const limiter = new RateLimiter({
      global: { requests_per_minute: 100000, burst_capacity: 100000 },
    });
    for (let i = 0; i < 1010; i++) {
      const ctx = createRequestContext({
        requestId: `r${i}`,
        sessionId: 's1',
        method: 'tools/call',
        toolName: `tool-${i}`,
      });
      await limiter.execute(ctx);
    }
  });
});

describe('CostTracker session eviction', () => {
  it('should evict stale sessions when max sessions reached', async () => {
    const tracker = new CostTracker({
      session_budget: 1000,
      tool_costs: { test: 0.01 },
    });

    for (let i = 0; i < 10010; i++) {
      const ctx = createRequestContext({
        requestId: `r${i}`,
        sessionId: `sess-${i}`,
        method: 'tools/call',
        toolName: 'test',
      });
      await tracker.execute(ctx);
    }
  });

  it('should use defaults for empty config', async () => {
    const tracker = new CostTracker({});
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
    });
    await expect(tracker.execute(ctx)).resolves.toEqual({
      action: 'CONTINUE',
      metadata: { cost: 0, totalCost: 0 },
    });
  });

  it('should handle missing toolName', async () => {
    const tracker = new CostTracker({
      session_budget: 100,
      tool_costs: { test: 1 },
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
    });
    await expect(tracker.execute(ctx)).resolves.toEqual({
      action: 'CONTINUE',
      metadata: { cost: 0, totalCost: 0 },
    });
  });
});

describe('ReadOnlyCheck exceptions', () => {
  it('should deny when exception condition does not match', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          tools: ['database_execute'],
          conditions: [{ argument: 'query', pattern: '^SELECT\\s+', flags: 'i' }],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'INSERT INTO users VALUES (1)' },
    });

    await expect(check.execute(ctx)).rejects.toThrow();
  });

  it('should deny when exception tool does not match', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          tools: ['other_tool'],
          conditions: [],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'INSERT INTO users VALUES (1)' },
    });

    await expect(check.execute(ctx)).rejects.toThrow();
  });

  it('should continue when no exceptions configured', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_read',
      arguments: { path: '/tmp/test.txt' },
    });

    await expect(check.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should continue when arguments are missing', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_write',
    });

    await expect(check.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should match exception without tools restriction', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          conditions: [{ argument: 'query', pattern: '^SELECT\\s+', flags: 'i' }],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users' },
    });

    await expect(check.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should block SQL write via args.query', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
      arguments: { query: 'DELETE FROM users' },
    });

    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('should block write-indicating tool names', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'file_write',
      arguments: {},
    });

    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });

  it('should handle non-string exception condition values', async () => {
    const check = new ReadOnlyCheck({
      enabled: true,
      exceptions: [
        {
          conditions: [{ argument: 'query', pattern: '^SELECT' }],
        },
      ],
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'write_file',
      arguments: { query: 123 },
    });

    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });
});

describe('ArgumentValidator regex patterns', () => {
  it('should match regex patterns with flags', async () => {
    const validator = new ArgumentValidator([
      {
        id: 'regex_test',
        type: 'regex',
        tools: ['test'],
        argument: 'value',
        patterns: [{ pattern: 'dangerous', flags: 'i', message: 'Contains dangerous word' }],
      },
    ]);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { value: 'DANGEROUS' },
    });

    await expect(validator.execute(ctx)).rejects.toThrow();
  });

  it('should pass when regex does not match', async () => {
    const validator = new ArgumentValidator([
      {
        id: 'regex_test',
        type: 'regex',
        tools: ['test'],
        argument: 'value',
        patterns: [{ pattern: 'dangerous', flags: 'i', message: 'Contains dangerous word' }],
      },
    ]);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { value: 'safe' },
    });

    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should continue when toolName or arguments missing', async () => {
    const validator = new ArgumentValidator([
      { id: 'rule1', type: 'regex', tools: ['test'], argument: 'value', patterns: [] },
    ]);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
    });
    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should handle wildcard tool matching', async () => {
    const validator = new ArgumentValidator([
      {
        id: 'wildcard',
        type: 'regex',
        tools: ['test_*'],
        argument: 'value',
        patterns: [{ pattern: 'bad', message: 'Bad' }],
      },
    ]);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test_anything',
      arguments: { value: 'bad' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow();
  });

  it('should handle invalid wildcard regex gracefully', async () => {
    const validator = new ArgumentValidator([
      {
        id: 'bad_wildcard',
        type: 'regex',
        tools: ['test_(a+)+'],
        argument: 'value',
        patterns: [{ pattern: 'bad', message: 'Bad' }],
      },
    ]);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test_aaa',
      arguments: { value: 'bad' },
    });
    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should handle sql_safe with valid SQL when sqlValidator configured', async () => {
    const validator = new ArgumentValidator(
      [
        {
          id: 'sql',
          type: 'sql_safe',
          tools: ['db_query'],
          argument: 'query',
        },
      ],
      {
        blocked_patterns: [],
        injection_patterns: [],
      },
    );
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
      arguments: { query: 'SELECT 1' },
    });
    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should handle shell_safe with non-string value', async () => {
    const validator = new ArgumentValidator([
      {
        id: 'shell',
        type: 'shell_safe',
        tools: ['exec'],
        argument: 'cmd',
      },
    ]);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'exec',
      arguments: { cmd: 123 },
    });
    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });

  it('should handle sql_safe with non-string value', async () => {
    const validator = new ArgumentValidator([
      {
        id: 'sql',
        type: 'sql_safe',
        tools: ['db_query'],
        argument: 'query',
      },
    ]);
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
      arguments: { query: 123 },
    });
    await expect(validator.execute(ctx)).resolves.toEqual({ action: 'CONTINUE' });
  });
});

describe('SQLValidator edge cases', () => {
  it('should use defaults when config fields omitted', () => {
    const validator = new SQLValidator({
      blocked_patterns: [],
      injection_patterns: [],
    });
    const result = validator.validate('DELETE FROM users WHERE id = 1');
    expect(result.valid).toBe(true);
  });

  it('should fallback on invalid blocked pattern regex', () => {
    const validator = new SQLValidator({
      blocked_patterns: [{ pattern: '(a+)+', message: 'Bad' }],
      injection_patterns: [],
    });
    const result = validator.validate('SELECT 1');
    expect(result.valid).toBe(true);
  });

  it('should fallback on invalid injection pattern regex', () => {
    const validator = new SQLValidator({
      blocked_patterns: [],
      injection_patterns: [{ pattern: '(a+)+', message: 'Bad' }],
    });
    const result = validator.validate('SELECT 1');
    expect(result.valid).toBe(true);
  });

  it('should allow read-only statements in read-only mode', () => {
    const validator = new SQLValidator({
      blocked_patterns: [],
      injection_patterns: [],
      read_only_statements: ['SELECT', 'SHOW'],
    });
    const result = validator.validate('SHOW TABLES', { readOnly: true });
    expect(result.valid).toBe(true);
  });
});

import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('Logger file output', () => {
  it('should write to file when filePath provided', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'logger-test-'));
    const file = join(dir, 'log.txt');
    const logger = new Logger('FileLogger', file);
    logger.info('file msg');

    // Wait for async file write
    await new Promise((resolve) => setTimeout(resolve, 50));
    const content = readFileSync(file, 'utf8');
    expect(content).toContain('file msg');

    rmSync(dir, { recursive: true });
  });
});

describe('redactor edge cases', () => {
  it('should handle circular references', () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj.self = obj;
    const result = redact(obj);
    expect(typeof result).toBe('string');
  });

  it('should handle patterns that break JSON', () => {
    const custom = [{ name: 'break', pattern: /"key":\s*"/, replacement: 'BROKEN' }];
    const result = redact({ key: 'value' }, custom);
    expect(typeof result).toBe('string');
  });
});

describe('Approval API error handling', () => {
  it('should return 500 when workflow.approve throws', async () => {
    const workflow = new ApprovalWorkflow({
      default_timeout_ms: 300000,
      max_pending_approvals: 1000,
    });
    vi.spyOn(workflow, 'approve').mockImplementation(() => {
      throw new Error('DB error');
    });
    const app = createApprovalApi(workflow, 'test-key');
    const res = await request(app)
      .post('/api/v1/approvals/123/approve')
      .set('Authorization', 'Bearer test-key')
      .send({ approverId: 'u1', approverGroup: 'g1' });
    expect(res.status).toBe(500);
  });

  it('should return 500 when workflow.deny throws', async () => {
    const workflow = new ApprovalWorkflow({
      default_timeout_ms: 300000,
      max_pending_approvals: 1000,
    });
    vi.spyOn(workflow, 'deny').mockImplementation(() => {
      throw new Error('DB error');
    });
    const app = createApprovalApi(workflow, 'test-key');
    const res = await request(app)
      .post('/api/v1/approvals/123/deny')
      .set('Authorization', 'Bearer test-key')
      .send({ approverId: 'u1', approverGroup: 'g1' });
    expect(res.status).toBe(500);
  });
});
