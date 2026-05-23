import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { validatePolicyFile } from './validate.js';

const dir = mkdtempSync(join(tmpdir(), 'tuf-validate-'));
let counter = 0;

function policyFile(yaml: string): string {
  const path = join(dir, `policy-${counter++}.yaml`);
  writeFileSync(path, yaml, 'utf-8');
  return path;
}

afterEach(() => {
  // files accumulate in the temp dir; the OS cleans it up
});

describe('validatePolicyFile', () => {
  it('accepts a well-formed policy', () => {
    const path = policyFile(`
version: "1.0"
settings:
  default_action: block
rules:
  - id: allow_read
    type: allow
    tools: ["file_read"]
    conditions:
      - argument: path
        pattern: "^/safe/"
        flags: "i"
`);
    const result = validatePolicyFile(path);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it('flags an unsafe (ReDoS) regex with its location', () => {
    const path = policyFile(`
version: "1.0"
rules:
  - id: bad_rule
    type: block
    conditions:
      - argument: q
        pattern: "(a+)+$"
`);
    const result = validatePolicyFile(path);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('bad_rule') && /redos/i.test(e))).toBe(true);
  });

  it('flags an invalid regex in a validation rule', () => {
    const path = policyFile(`
version: "1.0"
validation:
  rules:
    - id: regex_rule
      argument: q
      patterns:
        - pattern: "([unclosed"
          message: nope
`);
    const result = validatePolicyFile(path);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('validation.rules') && e.includes('invalid'))).toBe(
      true,
    );
  });

  it('reports schema violations as errors', () => {
    const path = policyFile(`
version: "1.0"
rules:
  - id: ""
    type: not_a_real_type
`);
    const result = validatePolicyFile(path);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('warns when default_action is allow with no rules', () => {
    const path = policyFile(`
version: "1.0"
settings:
  default_action: allow
`);
    const result = validatePolicyFile(path);
    expect(result.valid).toBe(true);
    expect(result.warnings.some((w) => w.includes('allow'))).toBe(true);
  });

  it('errors on a missing file', () => {
    const result = validatePolicyFile(join(dir, 'does-not-exist.yaml'));
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });
});
