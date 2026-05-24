import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApprovalWorkflow } from './workflow.js';

function makeCtx(toolName = 'dangerous_tool') {
  return createRequestContext({
    requestId: '1',
    sessionId: 's1',
    method: 'tools/call',
    toolName,
  });
}

function makeConfig(overrides: Record<string, unknown> = {}) {
  return {
    required_for: [{ tools: ['dangerous_tool'], approvers: ['admin'], min_approvals: 1 }],
    default_timeout_ms: 60000,
    max_pending_approvals: 1000,
    ...overrides,
  };
}

describe('ApprovalWorkflow', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('creates pending approval', async () => {
    const workflow = new ApprovalWorkflow(makeConfig());
    const id = await workflow.requestApproval(makeCtx());
    expect(id).toBeDefined();
    expect(typeof id).toBe('string');
    expect(id.startsWith('appr_')).toBe(true);
  });

  it('approves a pending request (full path)', async () => {
    const workflow = new ApprovalWorkflow(makeConfig());
    const id = await workflow.requestApproval(makeCtx());
    const result = await workflow.approve(id, 'approver1', 'admin');
    expect(result.success).toBe(true);
    expect(result.status).toBe('APPROVED');
  });

  it('stop clears cleanup interval', () => {
    const spy = vi.spyOn(globalThis, 'clearInterval');
    const workflow = new ApprovalWorkflow(makeConfig());
    workflow.stop();
    expect(spy).toHaveBeenCalledOnce();
    workflow.stop();
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('requestApproval succeeds without matching rule', async () => {
    const workflow = new ApprovalWorkflow({
      required_for: [{ tools: ['other_tool'], approvers: ['admin'], min_approvals: 1 }],
      default_timeout_ms: 60000,
    });
    const id = await workflow.requestApproval(makeCtx());
    expect(id).toBeDefined();
  });

  it('requestApproval matches rule without tools filter', async () => {
    const mockNotifier = { notify: vi.fn() };
    const groups = new Map([['default', mockNotifier]]);
    const workflow = new ApprovalWorkflow(
      { required_for: [{ approvers: ['default'], min_approvals: 1 }] },
      groups,
    );
    await workflow.requestApproval(makeCtx());
    expect(mockNotifier.notify).toHaveBeenCalled();
  });

  it('requestApproval calls notify on approvers', async () => {
    const mockNotifier = { notify: vi.fn() };
    const groups = new Map([['admin', mockNotifier]]);
    const workflow = new ApprovalWorkflow(makeConfig(), groups);
    await workflow.requestApproval(makeCtx('dangerous_tool'));
    expect(mockNotifier.notify).toHaveBeenCalled();
  });

  it('partial approval with multi-min_approvals returns PENDING', async () => {
    const workflow = new ApprovalWorkflow({
      required_for: [
        { tools: ['dangerous_tool'], approvers: ['admin', 'manager'], min_approvals: 2 },
      ],
      default_timeout_ms: 60000,
    });
    const id = await workflow.requestApproval(makeCtx());
    const result = await workflow.approve(id, 'alice', 'admin');
    expect(result.success).toBe(true);
    expect(result.status).toBe('PENDING');
    expect(result.pendingApprovers).toEqual(['manager']);
  });

  it('isFullyApproved with min_approvals=2 requires two approvals', async () => {
    const workflow = new ApprovalWorkflow({
      required_for: [
        { tools: ['dangerous_tool'], approvers: ['admin', 'manager'], min_approvals: 2 },
      ],
      default_timeout_ms: 60000,
    });
    const id = await workflow.requestApproval(makeCtx());
    await workflow.approve(id, 'alice', 'admin');
    const result = await workflow.approve(id, 'bob', 'manager');
    expect(result.status).toBe('APPROVED');
  });

  it('approve returns error for invalid approval ID', async () => {
    const workflow = new ApprovalWorkflow(makeConfig());
    const result = await workflow.approve('nonexistent', 'approver1', 'admin');
    expect(result.success).toBe(false);
    expect(result.reason).toBe('Invalid or expired approval request');
  });

  it('approve returns error for unauthorized group', async () => {
    const workflow = new ApprovalWorkflow(makeConfig());
    const id = await workflow.requestApproval(makeCtx());
    const result = await workflow.approve(id, 'alice', 'unauthorized_group');
    expect(result.success).toBe(false);
    expect(result.reason).toBe('Approver not authorized for this request');
  });

  it('approve returns error when group already approved', async () => {
    const workflow = new ApprovalWorkflow({
      required_for: [
        { tools: ['dangerous_tool'], approvers: ['admin', 'manager'], min_approvals: 2 },
      ],
      default_timeout_ms: 60000,
    });
    const id = await workflow.requestApproval(makeCtx());
    await workflow.approve(id, 'alice', 'admin');
    const result = await workflow.approve(id, 'bob', 'admin');
    expect(result.success).toBe(false);
    expect(result.reason).toBe('Already approved by this group');
  });

  it('deny a pending request', async () => {
    const workflow = new ApprovalWorkflow(makeConfig());
    const id = await workflow.requestApproval(makeCtx());
    const result = await workflow.deny(id, 'approver1', 'admin', 'Not safe');
    expect(result.success).toBe(true);
    expect(result.status).toBe('DENIED');
    expect(result.reason).toBe('Not safe');
    expect(workflow.getStatus(id)).toBeUndefined();
  });

  it('deny returns error for invalid ID', async () => {
    const workflow = new ApprovalWorkflow(makeConfig());
    const result = await workflow.deny('nonexistent', 'alice', 'admin');
    expect(result.success).toBe(false);
    expect(result.reason).toBe('Invalid or expired approval request');
  });

  it('deny returns error for unauthorized group', async () => {
    const workflow = new ApprovalWorkflow(makeConfig());
    const id = await workflow.requestApproval(makeCtx());
    const result = await workflow.deny(id, 'alice', 'unauthorized_group');
    expect(result.success).toBe(false);
    expect(result.reason).toBe('Approver not authorized for this request');
  });

  it('getStatus returns the approval request', async () => {
    const workflow = new ApprovalWorkflow(makeConfig());
    const id = await workflow.requestApproval(makeCtx());
    const status = workflow.getStatus(id);
    expect(status).toBeDefined();
    expect(status?.id).toBe(id);
    expect(status?.status).toBe('PENDING');
  });

  it('getStatus returns undefined for unknown ID', () => {
    const workflow = new ApprovalWorkflow(makeConfig());
    expect(workflow.getStatus('nonexistent')).toBeUndefined();
  });

  it('listPending returns pending requests', async () => {
    const workflow = new ApprovalWorkflow(makeConfig());
    await workflow.requestApproval(makeCtx('tool1'));
    await workflow.requestApproval(makeCtx('tool2'));
    expect(workflow.listPending()).toHaveLength(2);
  });

  it('listPending excludes approved requests', async () => {
    const workflow = new ApprovalWorkflow(makeConfig());
    const id = await workflow.requestApproval(makeCtx());
    await workflow.approve(id, 'approver1', 'admin');
    expect(workflow.listPending()).toHaveLength(0);
  });

  it('cleanupExpired removes expired requests', async () => {
    const workflow = new ApprovalWorkflow({ default_timeout_ms: -999999 });
    const id = await workflow.requestApproval(makeCtx());
    expect(workflow.getStatus(id)).toBeDefined();
    (workflow as unknown as { cleanupExpired(): void }).cleanupExpired();
    expect(workflow.getStatus(id)).toBeUndefined();
  });

  it('enforces max pending approvals by evicting oldest', async () => {
    const workflow = new ApprovalWorkflow({ max_pending_approvals: 2, default_timeout_ms: 60000 });
    const id1 = await workflow.requestApproval(makeCtx('tool1'));
    const id2 = await workflow.requestApproval(makeCtx('tool2'));
    const id3 = await workflow.requestApproval(makeCtx('tool3'));
    expect(workflow.getStatus(id1)).toBeUndefined();
    expect(workflow.getStatus(id2)).toBeDefined();
    expect(workflow.getStatus(id3)).toBeDefined();
  });

  it('handles oldestId being undefined when evicting from empty map', async () => {
    const workflow = new ApprovalWorkflow({ max_pending_approvals: 0, default_timeout_ms: 60000 });
    const id = await workflow.requestApproval(makeCtx());
    expect(id).toBeDefined();
    expect(workflow.getStatus(id)).toBeDefined();
  });

  it('cleanupExpired keeps non-expired requests', async () => {
    const workflow = new ApprovalWorkflow({ default_timeout_ms: 60000 });
    const id = await workflow.requestApproval(makeCtx());
    (workflow as unknown as { cleanupExpired(): void }).cleanupExpired();
    expect(workflow.getStatus(id)).toBeDefined();
  });

  it('handles approver notification failure gracefully', async () => {
    const failingApprover = { notify: vi.fn().mockRejectedValue(new Error('fail')) };
    const groups = new Map([['admin', failingApprover]]);
    const workflow = new ApprovalWorkflow(makeConfig(), groups);
    await expect(workflow.requestApproval(makeCtx())).resolves.toBeDefined();
    expect(failingApprover.notify).toHaveBeenCalled();
  });
});
