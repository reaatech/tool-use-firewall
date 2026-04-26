/**
 * Validates that a regex pattern is safe from ReDoS (Regular Expression Denial of Service).
 * Rejects patterns with catastrophic backtracking risks.
 */

export class UnsafeRegexError extends Error {
  constructor(pattern: string) {
    super(`Potentially unsafe regex pattern rejected: ${pattern}`);
    this.name = 'UnsafeRegexError';
  }
}

/**
 * Check if a regex pattern is potentially unsafe.
 * This uses structural heuristics to detect common ReDoS patterns.
 */
export function isSafeRegex(pattern: string): boolean {
  // Reject empty patterns
  if (!pattern || pattern.length === 0) return false;

  // Reject extremely long patterns
  if (pattern.length > 5000) return false;

  // Detect nested quantifiers: (a+)+, (a*)*, (a+)*, (a*)+
  // These are the most common catastrophic backtracking patterns.
  // We only flag * or + on the outside; ? (optional) is generally safe.
  const nestedQuantifier = /\([^)]*[*+?]\)[*+]/;
  if (nestedQuantifier.test(pattern)) return false;

  // Detect ambiguous alternation inside quantified groups: (a|a*)+
  // Again, only flag * or + on the outside.
  const ambiguousAlt = /\([^)]*\|[^)]*[*+?][^)]*\)[*+]/;
  if (ambiguousAlt.test(pattern)) return false;

  // Detect excessive nesting depth
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

  // Detect repeated + or * quantifiers without intermediate literals
  const repeatedQuantifier = /([*+?])\1+/;
  if (repeatedQuantifier.test(pattern)) return false;

  return true;
}

/**
 * Compile a regex pattern safely. Throws UnsafeRegexError if the pattern is dangerous.
 */
export function safeRegExp(pattern: string, flags?: string): RegExp {
  if (!isSafeRegex(pattern)) {
    throw new UnsafeRegexError(pattern);
  }
  try {
    // eslint-disable-next-line security/detect-non-literal-regexp
    return new RegExp(pattern, flags);
  } catch (error) {
    throw new UnsafeRegexError(
      `${pattern} — invalid syntax: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Compile a glob pattern (supporting only `*` as a wildcard) into an anchored
 * regex. All other regex metacharacters in the input are escaped so that
 * patterns like `db.exec*` only match the literal `db.exec` prefix.
 */
export function globToRegex(pattern: string): RegExp {
  // Escape every regex metachar except `*`, then turn `*` into `.*`.
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*');
  return safeRegExp(`^${escaped}$`);
}
