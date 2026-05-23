import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse } from 'yaml';
import { policyConfigSchema, type PolicyConfig } from './schema.js';
import { ValidationError } from '@reaatech/tool-use-firewall-core';

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

  return result.data;
}
