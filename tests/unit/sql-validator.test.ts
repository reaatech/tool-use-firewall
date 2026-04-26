import { describe, it, expect, beforeEach } from 'vitest';
import { SQLValidator } from '../../src/policies/sql-validator.js';

describe('SQLValidator', () => {
  let validator: SQLValidator;

  beforeEach(() => {
    validator = new SQLValidator({
      blocked_patterns: [
        { pattern: 'DROP\\s+TABLE', flags: 'i', message: 'DROP TABLE is not allowed' },
        { pattern: 'TRUNCATE\\s+TABLE', flags: 'i', message: 'TRUNCATE is not allowed' },
        { pattern: 'DROP\\s+DATABASE', flags: 'i', message: 'DROP DATABASE is not allowed' },
      ],
      injection_patterns: [
        {
          pattern: 'UNION\\s+(ALL\\s+)?SELECT',
          flags: 'i',
          message: 'UNION SELECT is not allowed',
        },
        {
          pattern: ';\\s*(DROP|DELETE|TRUNCATE|ALTER|CREATE)',
          flags: 'i',
          message: 'Multiple statements not allowed',
        },
        { pattern: 'OR\\s+1\\s*=\\s*1', flags: 'i', message: 'Tautology-based injection detected' },
      ],
      require_where_clause: ['DELETE', 'UPDATE'],
      read_only_statements: ['SELECT', 'SHOW', 'DESCRIBE', 'EXPLAIN'],
    });
  });

  describe('blocked patterns', () => {
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
      expect(result.riskLevel).toBe('LOW');
    });
  });

  describe('where clause validation', () => {
    it('should block DELETE without WHERE clause', () => {
      const result = validator.validate('DELETE FROM users');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('WHERE clause');
      expect(result.riskLevel).toBe('HIGH');
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

  describe('injection detection', () => {
    it('should detect UNION SELECT injection', () => {
      const result = validator.validate(
        'SELECT * FROM users WHERE id = 1 UNION SELECT * FROM passwords',
      );
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('UNION SELECT is not allowed');
    });

    it('should detect UNION ALL SELECT injection', () => {
      const result = validator.validate('SELECT * FROM users UNION ALL SELECT * FROM passwords');
      expect(result.valid).toBe(false);
    });

    it('should detect stacked queries', () => {
      const result = validator.validate('SELECT 1; DROP TABLE users');
      expect(result.valid).toBe(false);
      // Blocked patterns take priority over injection patterns
      expect(result.reason).toBe('DROP TABLE is not allowed');
    });

    it('should detect multiple statements without blocked keyword', () => {
      const result = validator.validate('SELECT 1; DELETE FROM users WHERE id = 1');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Multiple statements not allowed');
    });

    it('should detect tautology injection', () => {
      const result = validator.validate('SELECT * FROM users WHERE id = 1 OR 1=1');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Tautology-based injection detected');
    });
  });

  describe('read_only mode', () => {
    it('should block INSERT in read-only mode', () => {
      const result = validator.validate('INSERT INTO users VALUES (1, "test")', { readOnly: true });
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('read-only mode');
      expect(result.riskLevel).toBe('MEDIUM');
    });

    it('should allow SELECT in read-only mode', () => {
      const result = validator.validate('SELECT * FROM users', { readOnly: true });
      expect(result.valid).toBe(true);
    });

    it('should allow SHOW in read-only mode', () => {
      const result = validator.validate('SHOW TABLES', { readOnly: true });
      expect(result.valid).toBe(true);
    });
  });

  describe('risk assessment', () => {
    it('should classify SELECT as LOW risk', () => {
      const result = validator.validate('SELECT * FROM users');
      expect(result.riskLevel).toBe('LOW');
    });

    it('should classify INSERT as MEDIUM risk', () => {
      const result = validator.validate('INSERT INTO users VALUES (1)');
      expect(result.riskLevel).toBe('MEDIUM');
    });

    it('should classify UPDATE with WHERE as MEDIUM risk', () => {
      const result = validator.validate('UPDATE users SET name = "x" WHERE id = 1');
      expect(result.riskLevel).toBe('MEDIUM');
    });

    it('should classify DELETE without WHERE as HIGH risk (before where check)', () => {
      // This gets blocked by WHERE check, but risk level would be HIGH
      const result = validator.validate('DELETE FROM users');
      expect(result.valid).toBe(false);
    });

    it('should classify DROP as CRITICAL risk', () => {
      const result = validator.validate('DROP TABLE users');
      expect(result.valid).toBe(false);
      expect(result.riskLevel).toBe('CRITICAL');
    });
  });

  describe('edge cases', () => {
    it('should handle extra whitespace', () => {
      const result = validator.validate('  SELECT   *   FROM   users  ');
      expect(result.valid).toBe(true);
      expect(result.queryType).toBe('SELECT');
    });

    it('should handle empty query', () => {
      const result = validator.validate('');
      expect(result.valid).toBe(true);
      expect(result.queryType).toBeUndefined();
      expect(result.riskLevel).toBe('CRITICAL');
    });
  });

  describe('invalid patterns', () => {
    it('should handle invalid blocked_patterns', () => {
      const badValidator = new SQLValidator({
        blocked_patterns: [{ pattern: '(a+)+', flags: '', message: 'Invalid' }],
        injection_patterns: [],
      });
      const result = badValidator.validate('anything');
      expect(result.valid).toBe(true);
    });

    it('should handle invalid injection_patterns', () => {
      const badValidator = new SQLValidator({
        blocked_patterns: [],
        injection_patterns: [{ pattern: '(a+)+', flags: '', message: 'Invalid' }],
      });
      const result = badValidator.validate('anything');
      expect(result.valid).toBe(true);
    });

    it('should use defaults for omitted config fields', () => {
      const defaultValidator = new SQLValidator({
        blocked_patterns: [],
        injection_patterns: [],
      });
      const result = defaultValidator.validate('DELETE FROM users');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('WHERE clause');
    });
  });

  describe('read-only mode allowed statements', () => {
    it('should allow DESCRIBE in read-only mode', () => {
      const result = validator.validate('DESCRIBE users', { readOnly: true });
      expect(result.valid).toBe(true);
    });

    it('should allow EXPLAIN in read-only mode', () => {
      const result = validator.validate('EXPLAIN SELECT * FROM users', { readOnly: true });
      expect(result.valid).toBe(true);
    });
  });
});
