import { describe, expect, it, vi } from 'vitest';

vi.mock('./load.js', () => ({
  loadPolicyConfig: vi.fn(),
}));

import { loadPolicyConfig } from './load.js';
import { validatePolicyFile } from './validate.js';

describe('validatePolicyFile generic error catch', () => {
  it('handles non-ValidationError from loadPolicyConfig', () => {
    vi.mocked(loadPolicyConfig).mockImplementation(() => {
      throw new Error('unexpected error from loader');
    });
    const result = validatePolicyFile('any-path.yaml');
    expect(result.valid).toBe(false);
    expect(result.errors).toEqual(['unexpected error from loader']);
  });
});
