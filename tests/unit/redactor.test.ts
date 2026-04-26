import { describe, it, expect } from 'vitest';
import { redact, type RedactionPattern } from '../../src/utils/redactor.js';

describe('redact', () => {
  it('should redact API keys in objects', () => {
    const result = redact({ api_key: 'secret123', name: 'test' });
    expect(result).toEqual({ api_key: '[REDACTED]', name: 'test' });
  });

  it('should redact Bearer tokens in strings', () => {
    const result = redact({ headers: { Authorization: 'Bearer abc.def.ghi' } });
    expect(JSON.stringify(result)).toContain('Bearer [REDACTED]');
  });

  it('should redact emails', () => {
    const result = redact({ email: 'user@example.com' });
    expect(JSON.stringify(result)).toContain('[EMAIL_REDACTED]');
  });

  it('should return null/undefined unchanged', () => {
    expect(redact(null)).toBe(null);
    expect(redact(undefined)).toBe(undefined);
  });

  it('should handle primitives', () => {
    expect(redact('plain string')).toBe('plain string');
    expect(redact(42)).toBe(42);
  });

  it('should support custom patterns', () => {
    const custom: RedactionPattern[] = [
      { name: 'ssn', pattern: /\d{3}-\d{2}-\d{4}/g, replacement: '[SSN_REDACTED]' },
    ];
    const result = redact({ ssn: '123-45-6789' }, custom);
    expect(JSON.stringify(result)).toContain('[SSN_REDACTED]');
  });

  it('should handle arrays', () => {
    const result = redact([{ password: 'secret' }, { token: 'abc' }]);
    const str = JSON.stringify(result);
    expect(str).toContain('[REDACTED]');
  });

  it('should handle circular objects', () => {
    const obj: Record<string, unknown> = { name: 'test' };
    obj.self = obj;
    const result = redact(obj);
    expect(result).toBeDefined();
    expect(typeof result).toBe('string');
  });

  it('should handle patterns that break JSON structure', () => {
    const custom = [
      { name: 'break_json', pattern: /"value":\s*"[^"]*"/g, replacement: '"value": broken' },
    ];
    const result = redact({ value: 'test' }, custom);
    expect(result).toBeDefined();
    expect(typeof result).toBe('string');
    expect(result).toContain('broken');
  });

  it('redacts the bypass_token, private_key, and client_secret keys', () => {
    const obj = {
      bypass_token: 'b1',
      private_key: 'pk1',
      client_secret: 'cs1',
      credentials: 'cr1',
      refresh_token: 'rt1',
      benign: 'keep me',
    };
    const result = redact(obj) as Record<string, string>;
    expect(result.bypass_token).toBe('[REDACTED]');
    expect(result.private_key).toBe('[REDACTED]');
    expect(result.client_secret).toBe('[REDACTED]');
    expect(result.credentials).toBe('[REDACTED]');
    expect(result.refresh_token).toBe('[REDACTED]');
    expect(result.benign).toBe('keep me');
  });
});
