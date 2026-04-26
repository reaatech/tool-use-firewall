import { describe, it, expect } from 'vitest';
import { isSafeRegex, safeRegExp, UnsafeRegexError } from '../../src/utils/safe-regex.js';

describe('isSafeRegex', () => {
  it('should accept safe patterns', () => {
    expect(isSafeRegex('hello')).toBe(true);
    expect(isSafeRegex('^test$')).toBe(true);
    expect(isSafeRegex('\\d+')).toBe(true);
    expect(isSafeRegex('[a-z]+')).toBe(true);
  });

  it('should reject empty patterns', () => {
    expect(isSafeRegex('')).toBe(false);
  });

  it('should reject overly long patterns', () => {
    expect(isSafeRegex('a'.repeat(5001))).toBe(false);
  });

  it('should reject nested quantifiers', () => {
    expect(isSafeRegex('(a+)+')).toBe(false);
    expect(isSafeRegex('(a*)*')).toBe(false);
    expect(isSafeRegex('(a+)*')).toBe(false);
  });

  it('should allow optional groups', () => {
    expect(isSafeRegex('(ALL\\s+)?SELECT')).toBe(true);
    expect(isSafeRegex('(foo)?')).toBe(true);
  });

  it('should reject deep nesting', () => {
    expect(isSafeRegex('(((((((((((a)))))))))))')).toBe(false);
  });

  it('should reject repeated quantifiers', () => {
    expect(isSafeRegex('a**')).toBe(false);
    expect(isSafeRegex('a++')).toBe(false);
  });
});

describe('safeRegExp', () => {
  it('should compile safe patterns', () => {
    const regex = safeRegExp('hello', 'i');
    expect(regex.test('HELLO')).toBe(true);
  });

  it('should throw UnsafeRegexError for dangerous patterns', () => {
    expect(() => safeRegExp('(a+)+')).toThrow(UnsafeRegexError);
  });

  it('should throw UnsafeRegexError for invalid syntax', () => {
    expect(() => safeRegExp('(unclosed')).toThrow(UnsafeRegexError);
  });
});
