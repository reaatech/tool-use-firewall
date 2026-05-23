import { describe, expect, it } from 'vitest';
import { globToRegex, isSafeRegex, safeRegExp, UnsafeRegexError } from './safe-regex.js';

describe('isSafeRegex', () => {
  it('accepts simple patterns', () => {
    expect(isSafeRegex('hello')).toBe(true);
    expect(isSafeRegex('\\d+')).toBe(true);
    expect(isSafeRegex('^foo.*bar$')).toBe(true);
  });

  it('rejects nested quantifiers', () => {
    expect(isSafeRegex('(a+)+')).toBe(false);
    expect(isSafeRegex('(a*)*')).toBe(false);
  });

  it('rejects empty patterns', () => {
    expect(isSafeRegex('')).toBe(false);
  });

  it('rejects extremely long patterns', () => {
    expect(isSafeRegex('a'.repeat(5001))).toBe(false);
  });
});

describe('safeRegExp', () => {
  it('compiles safe patterns', () => {
    const re = safeRegExp('hello', 'i');
    expect(re.test('HELLO')).toBe(true);
  });

  it('throws on unsafe patterns', () => {
    expect(() => safeRegExp('(a+)+')).toThrow(UnsafeRegexError);
  });
});

describe('globToRegex', () => {
  it('converts simple globs', () => {
    const re = globToRegex('db.exec*');
    expect(re.test('db.execute')).toBe(true);
    expect(re.test('db.exec')).toBe(true);
    expect(re.test('other')).toBe(false);
  });
});
