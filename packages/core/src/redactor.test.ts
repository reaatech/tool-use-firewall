import { describe, it, expect } from 'vitest';
import { redact, DEFAULT_REDACTION_PATTERNS } from './redactor.js';

describe('redact', () => {
  it('returns null/undefined as-is', () => {
    expect(redact(null)).toBeNull();
    expect(redact(undefined)).toBeUndefined();
  });

  it('redacts API keys from JSON', () => {
    const input = { api_key: 'sk-1234567890abcdef', name: 'test' };
    const result = redact(input) as Record<string, unknown>;
    expect(result.api_key).toBe('[REDACTED]');
  });

  it('redacts bearer tokens', () => {
    const input = { auth: 'Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdA.token' };
    const result = JSON.stringify(redact(input));
    expect(result).not.toContain('eyJhbGciOiJIUzI1NiJ9');
    expect(result).toContain('[REDACTED]');
  });

  it('handles non-serializable values', () => {
    const circular: Record<string, unknown> = { a: 1 };
    circular.self = circular;
    expect(() => redact(circular)).not.toThrow();
  });
});
