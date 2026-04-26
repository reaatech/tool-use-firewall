import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFileSync, mkdtempSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadPolicyConfig } from '../../src/config/index.js';
import { ValidationError } from '../../src/utils/errors.js';

describe('loadPolicyConfig', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'firewall-test-'));
  });

  afterEach(() => {
    rmdirSync(tempDir, { recursive: true });
  });

  it('should load and validate a valid policy file', () => {
    const path = join(tempDir, 'policy.yaml');
    writeFileSync(
      path,
      `
version: "1.0"
settings:
  read_only: true
  default_action: block
rate_limits:
  global:
    requests_per_minute: 60
    burst_capacity: 10
`,
    );

    const config = loadPolicyConfig(path);
    expect(config.version).toBe('1.0');
    expect(config.settings?.read_only).toBe(true);
    expect(config.settings?.default_action).toBe('block');
    expect(config.rate_limits?.global?.requests_per_minute).toBe(60);
  });

  it('should apply defaults for missing fields', () => {
    const path = join(tempDir, 'minimal.yaml');
    writeFileSync(path, '{}\n');

    const config = loadPolicyConfig(path);
    expect(config.version).toBe('1.0');
    expect(config.settings?.default_action).toBe('block');
    expect(config.settings?.read_only).toBe(false);
  });

  it('should throw ValidationError for invalid YAML', () => {
    const path = join(tempDir, 'invalid.yaml');
    writeFileSync(path, 'not: valid: yaml: [\n');

    expect(() => loadPolicyConfig(path)).toThrow(ValidationError);
  });

  it('should throw ValidationError for non-existent file', () => {
    expect(() => loadPolicyConfig(join(tempDir, 'missing.yaml'))).toThrow(ValidationError);
  });

  it('should throw ValidationError for invalid schema', () => {
    const path = join(tempDir, 'bad-schema.yaml');
    writeFileSync(
      path,
      `
settings:
  default_action: invalid_action
`,
    );

    expect(() => loadPolicyConfig(path)).toThrow(ValidationError);
  });
});
