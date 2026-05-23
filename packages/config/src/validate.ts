import { ValidationError, isSafeRegex } from '@reaatech/tool-use-firewall-core';
import { loadPolicyConfig } from './load.js';
import type { PolicyConfig } from './schema.js';

export interface PolicyValidationResult {
  /** True when the policy parsed, matched the schema, and every regex is safe. */
  valid: boolean;
  /** Fatal problems that make the policy unusable. */
  errors: string[];
  /** Non-fatal observations worth surfacing (e.g. a policy that allows everything). */
  warnings: string[];
}

interface NamedPattern {
  /** Human-readable location, e.g. `validation.rules[0].patterns[1]`. */
  location: string;
  pattern: string;
  flags?: string;
}

/** Collect every regex pattern referenced anywhere in a policy, tagged with
 * where it came from so validation errors can point at the offending rule. */
function collectPatterns(config: PolicyConfig): NamedPattern[] {
  const out: NamedPattern[] = [];

  config.validation?.rules?.forEach((rule, ri) => {
    rule.patterns?.forEach((p, pi) => {
      out.push({ location: `validation.rules[${ri}:${rule.id}].patterns[${pi}]`, ...p });
    });
  });

  config.rules?.forEach((rule, ri) => {
    rule.conditions?.forEach((c, ci) => {
      if (c.pattern) {
        out.push({
          location: `rules[${ri}:${rule.id}].conditions[${ci}]`,
          pattern: c.pattern,
          flags: c.flags,
        });
      }
    });
    rule.conditionGroups?.forEach((group, gi) => {
      for (const key of ['allOf', 'anyOf'] as const) {
        group[key]?.forEach((c, ci) => {
          if (c.pattern) {
            out.push({
              location: `rules[${ri}:${rule.id}].conditionGroups[${gi}].${key}[${ci}]`,
              pattern: c.pattern,
              flags: c.flags,
            });
          }
        });
      }
    });
  });

  config.read_only_exceptions?.forEach((exc, ei) => {
    exc.conditions.forEach((c, ci) => {
      out.push({
        location: `read_only_exceptions[${ei}].conditions[${ci}]`,
        pattern: c.pattern,
        flags: c.flags,
      });
    });
  });

  config.secret_scan?.patterns?.forEach((p, pi) => {
    out.push({
      location: `secret_scan.patterns[${pi}:${p.name}]`,
      pattern: p.pattern,
      flags: p.flags,
    });
  });

  config.audit?.redaction?.patterns?.forEach((p, pi) => {
    out.push({ location: `audit.redaction.patterns[${pi}:${p.name}]`, pattern: p.pattern });
  });

  return out;
}

/** Validate a policy file without starting the proxy: parses YAML, checks it
 * against the schema, then verifies every regex pattern is both compilable and
 * safe from catastrophic backtracking (ReDoS). Suitable for use as a CI gate. */
export function validatePolicyFile(path: string): PolicyValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  let config: PolicyConfig;
  try {
    config = loadPolicyConfig(path);
  } catch (error) {
    if (error instanceof ValidationError) {
      errors.push(error.message);
    } else {
      errors.push(error instanceof Error ? error.message : String(error));
    }
    return { valid: false, errors, warnings };
  }

  for (const { location, pattern, flags } of collectPatterns(config)) {
    if (!isSafeRegex(pattern)) {
      errors.push(`${location}: unsafe regex (possible ReDoS): ${pattern}`);
      continue;
    }
    try {
      new RegExp(pattern, flags);
    } catch (error) {
      errors.push(
        `${location}: invalid regex ${JSON.stringify(pattern)}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  if (config.settings?.default_action === 'allow' && config.rules.length === 0) {
    warnings.push(
      'settings.default_action is "allow" with no rules — every tool call will be permitted.',
    );
  }

  return { valid: errors.length === 0, errors, warnings };
}
