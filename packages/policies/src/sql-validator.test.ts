import { describe, expect, it } from 'vitest';
import { SQLValidator } from './sql-validator.js';

describe('SQLValidator', () => {
  const config = {
    blocked_patterns: [{ pattern: 'DROP\\s+TABLE', message: 'DROP TABLE is not allowed' }],
    injection_patterns: [{ pattern: 'OR\\s+1\\s*=\\s*1', message: 'SQL injection detected' }],
    require_where_clause: ['DELETE', 'UPDATE'],
  };

  it('allows safe SELECT queries', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('SELECT * FROM users');
    expect(result.valid).toBe(true);
    expect(result.queryType).toBe('SELECT');
    expect(result.riskLevel).toBe('LOW');
  });

  it('blocks DROP TABLE', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('DROP TABLE users');
    expect(result.valid).toBe(false);
    expect(result.riskLevel).toBe('CRITICAL');
  });

  it('requires WHERE on DELETE', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('DELETE FROM users');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('WHERE');
  });

  it('detects SQL injection 1=1 pattern', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('SELECT * FROM users WHERE id = 1 OR 1=1');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('SQL injection detected');
    expect(result.riskLevel).toBe('HIGH');
  });

  it('read-only mode blocks write statements', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('INSERT INTO users VALUES (1)', { readOnly: true });
    expect(result.valid).toBe(false);
    expect(result.riskLevel).toBe('MEDIUM');
    expect(result.reason).toContain('read-only mode');
  });

  it('read-only mode allows SELECT', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('SELECT * FROM users', { readOnly: true });
    expect(result.valid).toBe(true);
  });

  it('risk assessment returns LOW for SELECT', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('SELECT * FROM users');
    expect(result.riskLevel).toBe('LOW');
  });

  it('risk assessment returns LOW for SHOW', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('SHOW TABLES');
    expect(result.riskLevel).toBe('LOW');
  });

  it('risk assessment returns LOW for DESCRIBE', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('DESCRIBE users');
    expect(result.riskLevel).toBe('LOW');
  });

  it('risk assessment returns LOW for EXPLAIN', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('EXPLAIN SELECT * FROM users');
    expect(result.riskLevel).toBe('LOW');
  });

  it('risk assessment returns MEDIUM for INSERT', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('INSERT INTO users VALUES (1)');
    expect(result.riskLevel).toBe('MEDIUM');
  });

  it('risk assessment returns MEDIUM for UPDATE with WHERE', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate("UPDATE users SET name = 'foo' WHERE id = 1");
    expect(result.riskLevel).toBe('MEDIUM');
  });

  it('risk assessment returns HIGH for UPDATE without WHERE', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate("UPDATE users SET name = 'foo'");
    expect(result.riskLevel).toBe('HIGH');
    expect(result.valid).toBe(false);
  });

  it('risk assessment returns HIGH for DELETE without WHERE', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('DELETE FROM users');
    expect(result.riskLevel).toBe('HIGH');
  });

  it('risk assessment returns CRITICAL for ALTER', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('ALTER TABLE users ADD COLUMN x INT');
    expect(result.riskLevel).toBe('CRITICAL');
  });

  it('risk assessment returns CRITICAL for CREATE', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('CREATE TABLE users (id INT)');
    expect(result.riskLevel).toBe('CRITICAL');
  });

  it('risk assessment returns CRITICAL for TRUNCATE', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('TRUNCATE TABLE users');
    expect(result.riskLevel).toBe('CRITICAL');
  });

  it('risk assessment returns CRITICAL for DROP', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('DROP DATABASE users');
    expect(result.riskLevel).toBe('CRITICAL');
  });

  it('getQueryType returns undefined for unknown query', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('FOO BAR');
    expect(result.queryType).toBeUndefined();
    expect(result.valid).toBe(true);
  });

  it('handles case insensitive query type', () => {
    const validator = new SQLValidator(config);
    const result = validator.validate('select * from users');
    expect(result.queryType).toBe('SELECT');
  });

  it('invalid regex pattern in blocked patterns falls back gracefully', () => {
    const invalidConfig = {
      blocked_patterns: [{ pattern: '[invalid', message: 'bad' }],
      injection_patterns: [],
    };
    const validator = new SQLValidator(invalidConfig);
    const result = validator.validate('SELECT 1');
    expect(result.valid).toBe(true);
  });

  it('invalid regex pattern in injection patterns falls back gracefully', () => {
    const invalidConfig = {
      blocked_patterns: [],
      injection_patterns: [{ pattern: '[invalid', message: 'bad' }],
    };
    const validator = new SQLValidator(invalidConfig);
    const result = validator.validate('SELECT 1');
    expect(result.valid).toBe(true);
  });

  it('risk assessment returns HIGH for UPDATE without WHERE when not required', () => {
    const customConfig = {
      blocked_patterns: [],
      injection_patterns: [],
      require_where_clause: ['DELETE'],
    };
    const validator = new SQLValidator(customConfig);
    const result = validator.validate("UPDATE users SET name = 'foo'");
    expect(result.valid).toBe(true);
    expect(result.riskLevel).toBe('HIGH');
  });

  it('risk assessment returns MEDIUM for DELETE with WHERE', () => {
    const customConfig = {
      blocked_patterns: [],
      injection_patterns: [],
      require_where_clause: ['DELETE', 'UPDATE'],
    };
    const validator = new SQLValidator(customConfig);
    const result = validator.validate('DELETE FROM users WHERE id = 1');
    expect(result.valid).toBe(true);
    expect(result.riskLevel).toBe('MEDIUM');
  });
});
