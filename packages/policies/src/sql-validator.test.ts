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
});
