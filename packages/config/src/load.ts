import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ValidationError } from '@reaatech/tool-use-firewall-core';
import { parse } from 'yaml';
import { type PolicyConfig, policyConfigSchema } from './schema.js';

const KNOWN_VERSIONS = new Set(['1.0']);

/** Load and validate a policy configuration from a YAML file.
 *
 * @example
 * ```ts
 * const config = loadPolicyConfig('./policies/default.yaml');
 * console.log(config.settings.read_only); // false
 * ```
 */
export function loadPolicyConfig(path: string): PolicyConfig {
  const absolutePath = resolve(path);
  let content: string;

  try {
    content = readFileSync(absolutePath, 'utf-8');
  } catch (error) {
    throw new ValidationError({
      message: `Failed to read policy file: ${absolutePath}`,
      details: { error: error instanceof Error ? error.message : String(error) },
    });
  }

  let raw: unknown;
  try {
    raw = parse(content);
  } catch (error) {
    throw new ValidationError({
      message: `Failed to parse policy YAML: ${absolutePath}`,
      details: { error: error instanceof Error ? error.message : String(error) },
    });
  }

  const result = policyConfigSchema.safeParse(raw);
  if (!result.success) {
    throw new ValidationError({
      message: `Invalid policy configuration: ${result.error.message}`,
      details: { issues: result.error.issues },
    });
  }

  if (!KNOWN_VERSIONS.has(result.data.version)) {
    throw new ValidationError({
      message: `Unsupported policy config version: ${result.data.version}. Expected one of: ${Array.from(KNOWN_VERSIONS).join(', ')}`,
      details: { version: result.data.version, supported: Array.from(KNOWN_VERSIONS) },
    });
  }

  return result.data;
}
