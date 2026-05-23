import { describe, it, expect } from 'vitest';
import { ApprovalWorkflow } from './workflow.js';
import { createRequestContext } from '@reaatech/tool-use-firewall-core';

describe('ApprovalWorkflow', () => {
  it('creates pending approval', async () => {
    const workflow = new ApprovalWorkflow({ default_timeout_ms: 60000, max_pending_approvals: 1000 });
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call', toolName: 'dangerous_tool' });
    try {
      await workflow.requestApproval(ctx);
    } catch (e: unknown) {
      const err = e as { approvalId: string };
      expect(err.approvalId).toBeDefined();
    }
  });

  it('approves a pending request', async () => {
    const workflow = new ApprovalWorkflow({ required_for: [{ tools: ['dangerous_tool'], approvers: ['admin'], min_approvals: 1 }], default_timeout_ms: 60000, max_pending_approvals: 1000 });
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call', toolName: 'dangerous_tool' });
    try {
      await workflow.requestApproval(ctx);
    } catch (e: unknown) {
      const err = e as { approvalId: string };
      const result = await workflow.approve(err.approvalId, 'approver1', 'admin');
      expect(result.success).toBe(true);
      expect(result.status).toBe('APPROVED');
    }
  });
});
