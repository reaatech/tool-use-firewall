import { describe, it, expect, vi } from 'vitest';
import { WebhookApprover } from './webhook-approver.js';

describe('WebhookApprover', () => {
  it('handles notify without throwing', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'));
    const approver = new WebhookApprover({ url: 'http://example.com/approve' });
    const request = {
      id: 'appr_1',
      context: { requestId: '1', sessionId: 's1', method: 'tools/call', toolName: 'test', receivedAt: 0, metadata: new Map() },
      status: 'PENDING' as const,
      createdAt: 0,
      expiresAt: 9999999999999,
      requiredApprovers: ['admin'],
      approvals: [],
      denials: [],
      minApprovals: 1,
    };
    await expect(approver.notify(request)).resolves.toBeUndefined();
    vi.restoreAllMocks();
  });
});
