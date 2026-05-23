export class UnsafeRegexError extends Error {
  constructor(pattern: string) {
    super(`Potentially unsafe regex pattern rejected: ${pattern}`);
    this.name = 'UnsafeRegexError';
  }
}

export function isSafeRegex(pattern: string): boolean {
  if (!pattern || pattern.length === 0) return false;
  if (pattern.length > 5000) return false;

  const nestedQuantifier = /\([^)]*[*+?]\)[*+]/;
  if (nestedQuantifier.test(pattern)) return false;

  const ambiguousAlt = /\([^)]*\|[^)]*[*+?][^)]*\)[*+]/;
  if (ambiguousAlt.test(pattern)) return false;

  let depth = 0;
  let maxDepth = 0;
  for (const char of pattern) {
    if (char === '(') {
      depth++;
      maxDepth = Math.max(maxDepth, depth);
    } else if (char === ')') {
      depth--;
    }
  }
  if (maxDepth > 10) return false;

  const repeatedQuantifier = /([*+?])\1+/;
  if (repeatedQuantifier.test(pattern)) return false;

  return true;
}

export function safeRegExp(pattern: string, flags?: string): RegExp {
  if (!isSafeRegex(pattern)) {
    throw new UnsafeRegexError(pattern);
  }
  try {
    return new RegExp(pattern, flags);
  } catch (error) {
    throw new UnsafeRegexError(
      `${pattern} — invalid syntax: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export function globToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*');
  return safeRegExp(`^${escaped}$`);
}
