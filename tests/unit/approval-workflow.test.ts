import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ApprovalWorkflow } from '../../src/approvals/workflow.js';
import { createRequestContext } from '../../src/middleware/context.js';
import { ApprovalRequiredError } from '../../src/utils/errors.js';
import type { ApprovalConfig } from '../../src/config/schema.js';
import type { RequestContext } from '../../src/middleware/context.js';

async function requestApprovalId(workflow: ApprovalWorkflow, ctx: RequestContext): Promise<string> {
  try {
    await workflow.requestApproval(ctx);
  } catch (error) {
    return (error as ApprovalRequiredError).approvalId;
  }
  throw new Error('Expected approval to be required');
}

describe('ApprovalWorkflow', () => {
  let workflow: ApprovalWorkflow;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    workflow.stop();
  });

  const createWorkflow = (config: Partial<ApprovalConfig> = {}) => {
    return new ApprovalWorkflow({
      default_timeout_ms: 300000,
      max_pending_approvals: 1000,
      required_for: [
        {
          tools: ['database_execute'],
          approvers: ['security-team'],
          min_approvals: 1,
        },
        {
          tools: ['file_write'],
          approvers: ['ops-team', 'security-team'],
          min_approvals: 2,
        },
      ],
      ...config,
    });
  };

  describe('requestApproval', () => {
    it('should throw ApprovalRequiredError with approvalId', async () => {
      workflow = createWorkflow();
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'database_execute',
        arguments: { query: 'DROP TABLE users' },
      });

      await expect(workflow.requestApproval(ctx)).rejects.toThrow(ApprovalRequiredError);
      try {
        await workflow.requestApproval(ctx);
      } catch (error) {
        expect(error).toBeInstanceOf(ApprovalRequiredError);
        expect((error as ApprovalRequiredError).approvalId).toBeDefined();
      }
    });

    it('should store pending approval', async () => {
      workflow = createWorkflow();
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'database_execute',
        arguments: { query: 'DROP TABLE users' },
      });

      try {
        await workflow.requestApproval(ctx);
      } catch (error) {
        const approvalId = (error as ApprovalRequiredError).approvalId;
        const pending = workflow.getStatus(approvalId);
        expect(pending).toBeDefined();
        expect(pending?.status).toBe('PENDING');
        expect(pending?.requiredApprovers).toEqual(['security-team']);
      }
    });
  });

  describe('approve', () => {
    it('should approve with single approver', async () => {
      workflow = createWorkflow();
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'database_execute',
        arguments: { query: 'DROP TABLE users' },
      });

      const approvalId = await requestApprovalId(workflow, ctx);

      const result = await workflow.approve(approvalId, 'user1', 'security-team');
      expect(result.success).toBe(true);
      expect(result.status).toBe('APPROVED');
    });

    it('should require multiple approvals for multi-approver rules', async () => {
      workflow = createWorkflow();
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'file_write',
        arguments: { path: '/etc/passwd' },
      });

      const approvalId = await requestApprovalId(workflow, ctx);

      const first = await workflow.approve(approvalId, 'user1', 'ops-team');
      expect(first.success).toBe(true);
      expect(first.status).toBe('PENDING');
      expect(first.pendingApprovers).toContain('security-team');

      const second = await workflow.approve(approvalId, 'user2', 'security-team');
      expect(second.success).toBe(true);
      expect(second.status).toBe('APPROVED');
    });

    it('should reject approval from unauthorized group', async () => {
      workflow = createWorkflow();
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'database_execute',
        arguments: { query: 'DROP TABLE users' },
      });

      const approvalId = await requestApprovalId(workflow, ctx);

      const result = await workflow.approve(approvalId, 'user1', 'unauthorized-group');
      expect(result.success).toBe(false);
    });

    it('should reject duplicate approval from same group', async () => {
      // Use file_write which requires 2 approvers, so first approval keeps it pending
      workflow = createWorkflow();
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'file_write',
        arguments: { path: '/etc/passwd' },
      });

      const approvalId = await requestApprovalId(workflow, ctx);

      await workflow.approve(approvalId, 'user1', 'ops-team');
      const result = await workflow.approve(approvalId, 'user2', 'ops-team');
      expect(result.success).toBe(false);
      expect(result.reason).toContain('Already approved');
    });
  });

  describe('deny', () => {
    it('should deny a pending request', async () => {
      workflow = createWorkflow();
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'database_execute',
        arguments: { query: 'DROP TABLE users' },
      });

      const approvalId = await requestApprovalId(workflow, ctx);

      const result = await workflow.deny(approvalId, 'user1', 'security-team', 'Too dangerous');
      expect(result.success).toBe(true);
      expect(result.status).toBe('DENIED');
      expect(result.reason).toBe('Too dangerous');
    });

    it('should reject denial from unauthorized group', async () => {
      workflow = createWorkflow();
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'database_execute',
        arguments: { query: 'DROP TABLE users' },
      });

      const approvalId = await requestApprovalId(workflow, ctx);

      const result = await workflow.deny(approvalId, 'user1', 'unauthorized-group');
      expect(result.success).toBe(false);
    });
  });

  describe('expiry', () => {
    it('should expire old approvals', async () => {
      workflow = createWorkflow({ default_timeout_ms: 60000 });
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'database_execute',
        arguments: { query: 'DROP TABLE users' },
      });

      const approvalId = await requestApprovalId(workflow, ctx);

      // Advance time past expiry
      vi.advanceTimersByTime(61000);
      // Trigger cleanup
      vi.advanceTimersByTime(60000);

      const pending = workflow.getStatus(approvalId);
      expect(pending).toBeUndefined();
    });
  });

  describe('listPending', () => {
    it('should list only pending approvals', async () => {
      workflow = createWorkflow();

      const ctx1 = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'database_execute',
        arguments: { query: 'DROP TABLE users' },
      });

      const ctx2 = createRequestContext({
        requestId: 'r2',
        sessionId: 's2',
        method: 'tools/call',
        toolName: 'database_execute',
        arguments: { query: 'DELETE FROM users' },
      });

      const id1 = await requestApprovalId(workflow, ctx1);
      const id2 = await requestApprovalId(workflow, ctx2);

      const pending = workflow.listPending();
      expect(pending).toHaveLength(2);

      // Approve one
      await workflow.approve(id1, 'user1', 'security-team');

      const pendingAfter = workflow.listPending();
      expect(pendingAfter).toHaveLength(1);
      expect(pendingAfter[0]?.id).toBe(id2);
    });
  });

  describe('capacity limit', () => {
    it('should evict oldest approval when at capacity', async () => {
      workflow = createWorkflow({ max_pending_approvals: 2 });

      for (let i = 0; i < 3; i++) {
        const ctx = createRequestContext({
          requestId: `r${i}`,
          sessionId: 's1',
          method: 'tools/call',
          toolName: 'database_execute',
          arguments: { query: 'DROP TABLE users' },
        });
        try {
          await workflow.requestApproval(ctx);
        } catch {
          /* ignore */
        }
      }

      const pending = workflow.listPending();
      expect(pending).toHaveLength(2);
    });
  });

  describe('defaults', () => {
    it('should use defaults with empty config', async () => {
      workflow = new ApprovalWorkflow({} as ApprovalConfig);
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'any_tool',
      });
      await expect(workflow.requestApproval(ctx)).rejects.toThrow(ApprovalRequiredError);
    });
  });

  describe('notify errors', () => {
    it('should handle approver group notify throwing', async () => {
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
      const throwingGroup = {
        notify: vi.fn().mockRejectedValue(new Error('Notify failed')),
      };
      workflow = new ApprovalWorkflow(
        {
          default_timeout_ms: 300000,
          max_pending_approvals: 1000,
          required_for: [
            { tools: ['database_execute'], approvers: ['security-team'], min_approvals: 1 },
          ],
        },
        new Map([['security-team', throwingGroup]]),
      );
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'database_execute',
      });
      try {
        await workflow.requestApproval(ctx);
      } catch (error) {
        expect(error).toBeInstanceOf(ApprovalRequiredError);
      }
      expect(throwingGroup.notify).toHaveBeenCalled();
      const output = stderrSpy.mock.calls.map((c) => c[0] as string).join('');
      expect(output).toContain('Approver notification failed');
      stderrSpy.mockRestore();
    });
  });

  describe('cleanupExpired', () => {
    it('should not cleanup non-expired approvals', async () => {
      workflow = createWorkflow({ default_timeout_ms: 120000 });
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'database_execute',
      });
      const id = await requestApprovalId(workflow, ctx);

      vi.advanceTimersByTime(60000);

      expect(workflow.getStatus(id)).toBeDefined();
    });
  });
});
