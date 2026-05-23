import type { RequestContext } from '@reaatech/tool-use-firewall-core';

export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED';

export interface ApprovalRequest {
  id: string;
  context: RequestContext;
  status: ApprovalStatus;
  createdAt: number;
  expiresAt: number;
  requiredApprovers: string[];
  approvals: Approval[];
  denials: Denial[];
  minApprovals: number;
}

export interface Approval {
  approverId: string;
  approverGroup: string;
  timestamp: number;
  comment?: string;
}

export interface Denial {
  approverId: string;
  approverGroup: string;
  timestamp: number;
  reason?: string;
}

export interface ApprovalResult {
  success: boolean;
  status?: ApprovalStatus;
  pendingApprovers?: string[];
  reason?: string;
}

export interface ApproverGroup {
  notify(request: ApprovalRequest): Promise<void>;
}
