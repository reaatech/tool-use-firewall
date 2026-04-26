import { randomUUID } from 'node:crypto';
import type { ApprovalRequest, ApprovalResult, ApproverGroup } from './types.js';
import type { RequestContext } from '../middleware/context.js';
import { ApprovalRequiredError } from '../utils/errors.js';
import type { ApprovalConfig } from '../config/schema.js';
import { Logger } from '../utils/logger.js';

/**
 * Manages human-in-the-loop approval workflows.
 * Supports multi-level approval chains with timeout handling.
 * Implements bounded storage to prevent memory exhaustion.
 */
export class ApprovalWorkflow {
  private pendingApprovals = new Map<string, ApprovalRequest>();
  private approverGroups = new Map<string, ApproverGroup>();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;
  private readonly defaultTimeoutMs: number;
  private readonly maxPendingApprovals: number;

  constructor(
    private readonly config: ApprovalConfig,
    approverGroups: Map<string, ApproverGroup> = new Map(),
  ) {
    this.defaultTimeoutMs = config.default_timeout_ms ?? 300000;
    this.maxPendingApprovals = config.max_pending_approvals ?? 1000;
    this.approverGroups = approverGroups;

    // Cleanup expired approvals every 60 seconds
    this.cleanupInterval = setInterval(() => this.cleanupExpired(), 60000);
  }

  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Request approval for a tool invocation.
   * Throws ApprovalRequiredError with the approval ID.
   */
  async requestApproval(context: RequestContext): Promise<never> {
    const approvalId = this.generateId();
    const rule = this.findMatchingRule(context);

    const requiredApprovers = rule?.approvers ?? ['default'];
    const minApprovals = rule?.min_approvals ?? requiredApprovers.length;

    const request: ApprovalRequest = {
      id: approvalId,
      context,
      status: 'PENDING',
      createdAt: Date.now(),
      expiresAt: Date.now() + this.defaultTimeoutMs,
      requiredApprovers,
      approvals: [],
      denials: [],
      minApprovals,
    };

    // Evict oldest pending approval if at capacity
    if (this.pendingApprovals.size >= this.maxPendingApprovals) {
      const oldestId = this.pendingApprovals.keys().next().value;
      if (oldestId) {
        this.pendingApprovals.delete(oldestId);
      }
    }

    this.pendingApprovals.set(approvalId, request);
    await this.notifyApprovers(request);

    throw new ApprovalRequiredError({
      message: `Operation requires approval from: ${requiredApprovers.join(', ')}`,
      requestId: context.requestId,
      approvalId,
      details: {
        expiresAt: request.expiresAt,
        requiredApprovers,
      },
    });
  }

  /**
   * Approve a pending request.
   */
  async approve(
    approvalId: string,
    approverId: string,
    approverGroup: string,
    comment?: string,
  ): Promise<ApprovalResult> {
    const request = this.pendingApprovals.get(approvalId);
    if (!request || request.status !== 'PENDING') {
      return { success: false, reason: 'Invalid or expired approval request' };
    }

    if (!request.requiredApprovers.includes(approverGroup)) {
      return { success: false, reason: 'Approver not authorized for this request' };
    }

    if (request.approvals.some((a) => a.approverGroup === approverGroup)) {
      return { success: false, reason: 'Already approved by this group' };
    }

    request.approvals.push({
      approverId,
      approverGroup,
      timestamp: Date.now(),
      comment,
    });

    if (this.isFullyApproved(request)) {
      request.status = 'APPROVED';
      this.pendingApprovals.delete(approvalId);
      return { success: true, status: 'APPROVED' };
    }

    return {
      success: true,
      status: 'PENDING',
      pendingApprovers: this.getPendingApproverGroups(request),
    };
  }

  /**
   * Deny a pending request.
   */
  async deny(
    approvalId: string,
    approverId: string,
    approverGroup: string,
    reason?: string,
  ): Promise<ApprovalResult> {
    const request = this.pendingApprovals.get(approvalId);
    if (!request || request.status !== 'PENDING') {
      return { success: false, reason: 'Invalid or expired approval request' };
    }

    if (!request.requiredApprovers.includes(approverGroup)) {
      return { success: false, reason: 'Approver not authorized for this request' };
    }

    request.status = 'DENIED';
    request.denials.push({
      approverId,
      approverGroup,
      timestamp: Date.now(),
      reason,
    });

    this.pendingApprovals.delete(approvalId);
    return { success: true, status: 'DENIED', reason };
  }

  /**
   * Get the status of an approval request.
   */
  getStatus(approvalId: string): ApprovalRequest | undefined {
    return this.pendingApprovals.get(approvalId);
  }

  /**
   * List all pending approvals.
   */
  listPending(): ApprovalRequest[] {
    return Array.from(this.pendingApprovals.values()).filter((r) => r.status === 'PENDING');
  }

  private findMatchingRule(context: RequestContext) {
    const rules = this.config.required_for ?? [];
    for (const rule of rules) {
      if (!rule.tools || (context.toolName && rule.tools.includes(context.toolName))) {
        return rule;
      }
    }
    return undefined;
  }

  private isFullyApproved(request: ApprovalRequest): boolean {
    const approvedGroups = new Set(request.approvals.map((a) => a.approverGroup));
    const requiredApproved = request.requiredApprovers.filter((g) => approvedGroups.has(g));
    return requiredApproved.length >= request.minApprovals;
  }

  private getPendingApproverGroups(request: ApprovalRequest): string[] {
    const approvedGroups = new Set(request.approvals.map((a) => a.approverGroup));
    return request.requiredApprovers.filter((g) => !approvedGroups.has(g));
  }

  private async notifyApprovers(request: ApprovalRequest): Promise<void> {
    const pendingGroups = this.getPendingApproverGroups(request);
    const results = await Promise.allSettled(
      pendingGroups.map(async (group) => {
        const approver = this.approverGroups.get(group);
        if (approver) {
          await approver.notify(request);
        }
      }),
    );
    const logger = new Logger('ApprovalWorkflow');
    // Log failures but don't throw — approval request is already recorded
    for (const result of results) {
      if (result.status === 'rejected') {
        logger.error('Approver notification failed', { reason: String(result.reason) });
      }
    }
  }

  private cleanupExpired(): void {
    const now = Date.now();
    for (const [id, request] of this.pendingApprovals.entries()) {
      if (request.expiresAt < now) {
        request.status = 'EXPIRED';
        this.pendingApprovals.delete(id);
      }
    }
  }

  private generateId(): string {
    return `appr_${randomUUID()}`;
  }
}
