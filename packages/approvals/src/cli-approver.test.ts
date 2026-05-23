import { describe, expect, it } from 'vitest';
import { CLIApprover } from './cli-approver.js';

describe('CLIApprover', () => {
  it('can be instantiated', () => {
    const approver = new CLIApprover();
    expect(approver).toBeInstanceOf(CLIApprover);
  });
});
