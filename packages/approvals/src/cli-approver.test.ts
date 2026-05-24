import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it } from 'vitest';
import { CLIApprover } from './cli-approver.js';

function makeRequest() {
  return {
    id: 'appr_1',
    context: createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    }),
    status: 'PENDING' as const,
    createdAt: 0,
    expiresAt: 9999999999999,
    requiredApprovers: ['default'],
    approvals: [],
    denials: [],
    minApprovals: 1,
  };
}

describe('CLIApprover', () => {
  it('can be instantiated', () => {
    const approver = new CLIApprover();
    expect(approver).toBeInstanceOf(CLIApprover);
  });

  it('notify does not throw', async () => {
    const approver = new CLIApprover();
    await expect(approver.notify(makeRequest())).resolves.toBeUndefined();
  });

  it('notify with custom prompt', async () => {
    const approver = new CLIApprover({ prompt: 'Custom prompt' });
    await expect(approver.notify(makeRequest())).resolves.toBeUndefined();
  });
});
