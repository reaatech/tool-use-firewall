# Skill: Testing

## Description
Write and run tests for the tool-use-firewall project. This skill covers unit testing, integration testing, security testing, and performance testing with a focus on maintaining ≥90% code coverage.

## When to Use
- Writing tests for new features
- Adding tests for bug fixes
- Running the test suite before commits
- Setting up CI/CD test pipelines
- Performing security-focused testing

## Capabilities
- Unit test implementation with Vitest
- Integration testing for MCP proxy
- Security testing for validation rules
- Performance benchmarking
- Test coverage analysis
- Mock and fixture generation

## Testing Configuration

```yaml
# vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      threshold: {
        global: {
          statements: 90,
          branches: 90,
          functions: 90,
          lines: 90,
        },
      },
      exclude: [
        'src/**/*.test.ts',
        'src/index.ts',
        'src/cli.ts',
      ],
    },
  },
});
```

## Unit Testing

### Basic Unit Test Structure
```typescript
// src/policies/sql-validator.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { SQLValidator } from './sql-validator';

describe('SQLValidator', () => {
  let validator: SQLValidator;

  beforeEach(() => {
    validator = new SQLValidator({
      blocked_patterns: [
        { pattern: 'DROP\\s+TABLE', flags: 'i', message: 'DROP TABLE is not allowed' },
        { pattern: 'TRUNCATE', flags: 'i', message: 'TRUNCATE is not allowed' },
      ],
      injection_patterns: [
        { pattern: 'UNION\\s+(ALL\\s+)?SELECT', flags: 'i', message: 'UNION SELECT not allowed' },
      ],
      require_where_clause: ['DELETE', 'UPDATE'],
      read_only_statements: ['SELECT', 'SHOW', 'DESCRIBE', 'EXPLAIN'],
    });
  });

  describe('blocked_patterns', () => {
    it('should block DROP TABLE queries', () => {
      const result = validator.validate('DROP TABLE users');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('DROP TABLE is not allowed');
      expect(result.riskLevel).toBe('CRITICAL');
    });

    it('should block DROP TABLE with lowercase', () => {
      const result = validator.validate('drop table users');
      expect(result.valid).toBe(false);
    });

    it('should block TRUNCATE queries', () => {
      const result = validator.validate('TRUNCATE TABLE users');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('TRUNCATE is not allowed');
    });

    it('should allow SELECT queries', () => {
      const result = validator.validate('SELECT * FROM users');
      expect(result.valid).toBe(true);
      expect(result.queryType).toBe('SELECT');
    });
  });

  describe('where_clause_validation', () => {
    it('should block DELETE without WHERE clause', () => {
      const result = validator.validate('DELETE FROM users');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('WHERE clause');
    });

    it('should allow DELETE with WHERE clause', () => {
      const result = validator.validate('DELETE FROM users WHERE id = 1');
      expect(result.valid).toBe(true);
      expect(result.hasWhereClause).toBe(true);
    });

    it('should block UPDATE without WHERE clause', () => {
      const result = validator.validate('UPDATE users SET name = "test"');
      expect(result.valid).toBe(false);
    });

    it('should allow UPDATE with WHERE clause', () => {
      const result = validator.validate('UPDATE users SET name = "test" WHERE id = 1');
      expect(result.valid).toBe(true);
    });
  });

  describe('injection_detection', () => {
    it('should detect UNION SELECT injection', () => {
      const result = validator.validate('SELECT * FROM users WHERE id = 1 UNION SELECT * FROM passwords');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('UNION SELECT not allowed');
    });

    it('should detect UNION ALL SELECT injection', () => {
      const result = validator.validate("SELECT * FROM users UNION ALL SELECT * FROM passwords");
      expect(result.valid).toBe(false);
    });
  });

  describe('read_only_mode', () => {
    it('should block INSERT in read-only mode', () => {
      const result = validator.validate('INSERT INTO users VALUES (1, "test")', { readOnly: true });
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('read-only mode');
    });

    it('should allow SELECT in read-only mode', () => {
      const result = validator.validate('SELECT * FROM users', { readOnly: true });
      expect(result.valid).toBe(true);
    });
  });
});
```

### Testing Rate Limiter
```typescript
// src/policies/rate-limiter.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { TokenBucket } from './rate-limiter';

describe('TokenBucket', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should allow requests within capacity', () => {
    const bucket = new TokenBucket(10, 1); // 10 tokens, 1 token/ms
    
    expect(bucket.consume(5)).toBe(true);
    expect(bucket.consume(5)).toBe(true);
    expect(bucket.consume(1)).toBe(false); // No tokens left
  });

  it('should refill tokens over time', () => {
    const bucket = new TokenBucket(10, 0.1); // 10 tokens, 0.1 token/ms
    bucket.consume(10); // Empty the bucket
    
    vi.advanceTimersByTime(100); // Wait 100ms
    
    expect(bucket.consume(10)).toBe(true); // Should have ~10 tokens
  });

  it('should not exceed capacity when refilling', () => {
    const bucket = new TokenBucket(10, 1); // 10 tokens, 1 token/ms
    bucket.consume(5); // 5 tokens left
    
    vi.advanceTimersByTime(1000); // Wait 1000ms (would add 1000 tokens)
    
    expect(bucket.consume(10)).toBe(true); // But max is 10
    expect(bucket.consume(1)).toBe(false); // Only 10 tokens max
  });

  it('should calculate correct wait time', () => {
    const bucket = new TokenBucket(10, 0.1); // 10 tokens, 0.1 token/ms
    bucket.consume(10); // Empty the bucket
    
    expect(bucket.getWaitTime(5)).toBe(50); // Need 50ms for 5 tokens
  });
});
```

### Testing Policy Engine
```typescript
// src/policies/policy-engine.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { PolicyEngine } from './policy-engine';

describe('PolicyEngine', () => {
  let engine: PolicyEngine;

  beforeEach(() => {
    engine = new PolicyEngine({
      version: '1.0',
      settings: {
        default_action: 'BLOCK',
      },
      rules: [
        {
          id: 'block_drop',
          type: 'block',
          tools: ['database_execute'],
          conditions: [
            { argument: 'query', pattern: 'DROP', flags: 'i' }
          ],
          priority: 100,
        },
        {
          id: 'allow_select',
          type: 'allow',
          tools: ['database_execute'],
          conditions: [
            { argument: 'query', pattern: '^SELECT', flags: 'i' }
          ],
          priority: 90,
        },
      ],
    });
  });

  it('should block DROP queries', async () => {
    const result = await engine.evaluate({
      sessionId: 'test',
      toolName: 'database_execute',
      arguments: { query: 'DROP TABLE users' },
    });

    expect(result.action).toBe('BLOCK');
    expect(result.rule?.id).toBe('block_drop');
  });

  it('should allow SELECT queries', async () => {
    const result = await engine.evaluate({
      sessionId: 'test',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users' },
    });

    expect(result.action).toBe('ALLOW');
  });

  it('should block non-matching queries by default', async () => {
    const result = await engine.evaluate({
      sessionId: 'test',
      toolName: 'database_execute',
      arguments: { query: 'INSERT INTO users VALUES (1)' },
    });

    expect(result.action).toBe('BLOCK');
  });
});
```

## Integration Testing

### MCP Proxy Integration Test
```typescript
// tests/integration/proxy.test.ts
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ToolUseFirewall } from '../../src/server';
import { MockMCPServer } from '../fixtures/mock-mcp-server';

describe('MCP Proxy Integration', () => {
  let firewall: ToolUseFirewall;
  let mockServer: MockMCPServer;

  beforeAll(async () => {
    mockServer = new MockMCPServer();
    await mockServer.start();

    firewall = new ToolUseFirewall({
      upstreamUrl: mockServer.url,
      policyPath: './test-policy.yaml',
    });
    await firewall.start();
  });

  afterAll(async () => {
    await firewall.stop();
    await mockServer.stop();
  });

  it('should pass through allowed tool calls', async () => {
    const response = await firewall.callTool({
      name: 'database_execute',
      arguments: { query: 'SELECT * FROM users' },
    });

    expect(response).toBeDefined();
    expect(response.content).toBeDefined();
  });

  it('should block disallowed tool calls', async () => {
    await expect(
      firewall.callTool({
        name: 'database_execute',
        arguments: { query: 'DROP TABLE users' },
      })
    ).rejects.toThrow('DROP TABLE is not allowed');
  });

  it('should enforce rate limits', async () => {
    const calls = Array(100).fill(null).map(() =>
      firewall.callTool({
        name: 'database_execute',
        arguments: { query: 'SELECT 1' },
      })
    );

    const results = await Promise.allSettled(calls);
    const rejected = results.filter(r => r.status === 'rejected');
    
    expect(rejected.length).toBeGreaterThan(0);
  });
});
```

## Security Testing

### SQL Injection Bypass Tests
```typescript
// tests/security/sql-injection.test.ts
import { describe, it, expect } from 'vitest';
import { SQLValidator } from '../../src/policies/sql-validator';

describe('SQL Injection Bypass Prevention', () => {
  const validator = createStrictValidator();

  describe('encoding bypasses', () => {
    it('should detect URL-encoded injection', () => {
      const result = validator.validate('SELECT * FROM users WHERE name = %27 OR 1=1 --');
      expect(result.valid).toBe(false);
    });

    it('should detect unicode bypass attempts', () => {
      const result = validator.validate('SELECT * FROM users WHERE name = ＵＮＩＯＮ SELECT');
      expect(result.valid).toBe(false);
    });
  });

  describe('comment bypasses', () => {
    it('should detect SQL comment injection', () => {
      const result = validator.validate('DROP/*comment*/TABLE users');
      expect(result.valid).toBe(false);
    });

    it('should detect double dash injection', () => {
      const result = validator.validate("SELECT * FROM users WHERE id = 1; -- DROP TABLE users");
      expect(result.valid).toBe(false);
    });
  });

  describe('stacked queries', () => {
    it('should detect stacked DROP TABLE', () => {
      const result = validator.validate('SELECT 1; DROP TABLE users');
      expect(result.valid).toBe(false);
    });

    it('should detect stacked queries without semicolon', () => {
      const result = validator.validate('SELECT 1 DROP TABLE users');
      expect(result.valid).toBe(false);
    });
  });
});
```

## Performance Testing

### Latency Benchmark
```typescript
// tests/performance/latency.test.ts
import { describe, it, expect } from 'vitest';
import { PolicyEngine } from '../../src/policies/policy-engine';

describe('Performance Benchmarks', () => {
  it('should evaluate simple rules in under 5ms', async () => {
    const engine = new PolicyEngine(simplePolicy);
    const context = {
      sessionId: 'test',
      toolName: 'database_execute',
      arguments: { query: 'SELECT 1' },
    };

    const start = performance.now();
    await engine.evaluate(context);
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(5);
  });

  it('should evaluate complex policies in under 10ms', async () => {
    const engine = new PolicyEngine(complexPolicy);
    const context = {
      sessionId: 'test',
      toolName: 'database_execute',
      arguments: { query: 'SELECT * FROM users WHERE id = 1' },
    };

    const start = performance.now();
    await engine.evaluate(context);
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(10);
  });

  it('should handle 1000 requests per second', async () => {
    const engine = new PolicyEngine(simplePolicy);
    const requests = Array(1000).fill(null).map((_, i) => ({
      sessionId: `session-${i}`,
      toolName: 'database_execute',
      arguments: { query: 'SELECT 1' },
    }));

    const start = performance.now();
    await Promise.all(requests.map(r => engine.evaluate(r)));
    const elapsed = performance.now() - start;

    // Should complete in under 1 second (1000 req/s)
    expect(elapsed).toBeLessThan(1000);
  });
});
```

## Running Tests

### Run All Tests
```bash
pnpm test
```

### Run with Coverage
```bash
pnpm test:coverage
```

### Run Specific Test File
```bash
pnpm test src/policies/sql-validator.test.ts
```

### Run Tests in Watch Mode
```bash
pnpm test:watch
```

### Check Coverage Report
```bash
pnpm test:coverage
open coverage/index.html
```

## Test Fixtures

### Mock MCP Server
```typescript
// tests/fixtures/mock-mcp-server.ts
export class MockMCPServer {
  private server: http.Server;
  private tools: Map<string, ToolHandler> = new Map();

  registerTool(name: string, handler: ToolHandler) {
    this.tools.set(name, handler);
  }

  async start(): Promise<void> {
    this.server = http.createServer((req, res) => {
      // Handle MCP protocol
    });
    await new Promise<void>((resolve) => {
      this.server.listen(0, () => resolve());
    });
  }

  get url(): string {
    return `http://localhost:${(this.server.address() as any).port}`;
  }

  async stop(): Promise<void> {
    this.server.close();
  }
}
```

## Output
- Comprehensive test suite with ≥90% coverage
- Unit tests for all components
- Integration tests for MCP proxy
- Security tests for validation rules
- Performance benchmarks
- Test fixtures and mocks

## Related Skills
- `project-setup` - Initial test configuration
- `security-review` - Security-focused test cases
- `policy-engine` - Test policy evaluation
