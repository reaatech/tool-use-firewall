/**
 * Redacts sensitive data from audit events and API responses.
 * Implements pattern-based redaction to prevent PII/secret leakage.
 */

export interface RedactionPattern {
  name: string;
  pattern: RegExp;
  replacement: string;
}

export const DEFAULT_REDACTION_PATTERNS: RedactionPattern[] = [
  {
    // Common secret-bearing key names — kept broad on purpose.
    name: 'secret_key',
    pattern:
      /"(api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|bypass[_-]?token|token|password|passwd|secret|client[_-]?secret|private[_-]?key|credentials?|auth)"\s*:\s*"[^"]*"/gi,
    replacement: '"$1": "[REDACTED]"',
  },
  {
    name: 'bearer_token',
    pattern: /Bearer\s+[a-zA-Z0-9_\-.]+/g,
    replacement: 'Bearer [REDACTED]',
  },
  {
    name: 'email',
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    replacement: '[EMAIL_REDACTED]',
  },
];

/**
 * Deep-redact an arbitrary value by serializing to JSON, applying patterns,
 * and parsing back. Falls back to string replacement for non-JSON values.
 */
export function redact(value: unknown, customPatterns?: RedactionPattern[]): unknown {
  if (value === undefined || value === null) return value;

  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    // Circular or non-serializable — coerce to string
    serialized = String(value);
  }

  const patterns = customPatterns ?? DEFAULT_REDACTION_PATTERNS;
  for (const p of patterns) {
    serialized = serialized.replace(p.pattern, p.replacement);
  }

  try {
    return JSON.parse(serialized);
  } catch {
    // If replacement broke JSON structure, return the redacted string
    return serialized;
  }
}
