# Skill: Approval Workflow

## Description
Set up human-in-the-loop approvals for the tool-use-firewall. This skill enables requiring human approval for high-risk operations before they are executed, providing multiple approval interfaces and multi-level approval chains.

## When to Use
- Requiring approval for destructive database operations
- Implementing multi-level approval for sensitive actions
- Setting up emergency break-glass procedures
- Creating audit trails for approved operations
- Integrating with external approval systems

## Capabilities
- Multiple approval interfaces (CLI, webhook, Slack)
- Multi-level approval chains
- Timeout handling
- Approval token generation
- Emergency override (break-glass)
- Approval status tracking

## Approval Configuration

```yaml
# policy.yaml
approvals:
  # Default timeout for approvals (5 minutes)
  default_timeout_ms: 300000
  
  # Maximum pending approvals before oldest are evicted (prevents memory exhaustion)
  max_pending_approvals: 1000
  
  # Operations requiring approval
  required_for:
    # Database operations
    - tools: ["database_execute"]
      conditions:
        - argument: "query"
          matches: "(DROP|DELETE|TRUNCATE|ALTER|CREATE)"
          flags: "i"
      approvers: ["security-team"]
      min_approvals: 1
      
    # File system operations in sensitive directories
    - tools: ["file_write"]
      conditions:
        - argument: "path"
          matches: "^/etc/|^/var/|^/usr/|^/opt/"
      approvers: ["ops-team", "security-team"]
      min_approvals: 2
      
    # Shell command execution
    - tools: ["shell_exec"]
      conditions:
        - argument: "command"
          matches: "sudo|rm -rf|chmod|chown|mkfs"
          flags: "i"
      approvers: ["ops-team"]
      min_approvals: 1
      
    # Any operation above cost threshold
    - cost_threshold: 10.00
      approvers: ["finance-team"]
      min_approvals: 1
  
  # Approver groups
  approver_groups:
    security-team:
      type: "webhook"
      url: "https://security.company.com/api/approvals"
      api_key_env: "SECURITY_API_KEY"
      
    ops-team:
      type: "slack"
      channel: "#ops-approvals"
      bot_token_env: "SLACK_BOT_TOKEN"
      
    finance-team:
      type: "email"
      recipients: ["finance@company.com"]
      smtp_env: "SMTP_CONFIG"
  
  # Emergency override (break-glass)
  emergency_override:
    enabled: true
    requires_approval: true  # Still needs post-incident review
    audit_level: "FULL"
    token_env: "BREAK_GLASS_TOKEN"
```

## Implementation

### Approval Workflow Manager
```typescript
// src/policies/approval-workflow.ts
export interface ApprovalRequest {
  id: string;
  context: RequestContext;
  status: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED';
  createdAt: number;
  expiresAt: number;
  requiredApprovers: string[];
  approvals: Approval[];
  denials: Denial[];
}

export interface Approval {
  approverId: string;
  approverGroup: string;
  timestamp: number;
  comment?: string;
}

export class ApprovalWorkflow {
  private pendingApprovals: Map<string, ApprovalRequest> = new Map();
  private approverGroups: Map<string, ApproverGroup> = new Map();
  private config: ApprovalConfig;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;
  private readonly maxPendingApprovals: number;

  constructor(config: ApprovalConfig) {
    this.config = config;
    this.maxPendingApprovals = config.max_pending_approvals || 1000;
    this.approverGroups = this.initializeApproverGroups(config.approver_groups);
    
    // Cleanup expired approvals periodically
    this.cleanupInterval = setInterval(() => this.cleanupExpired(), 60000);
  }

  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  async requestApproval(context: RequestContext): Promise<ApprovalResult> {
    const approvalId = generateUUID();
    const requiredApprovers = this.determineRequiredApprovers(context);
    
    const request: ApprovalRequest = {
      id: approvalId,
      context,
      status: 'PENDING',
      createdAt: Date.now(),
      expiresAt: Date.now() + this.config.default_timeout_ms,
      requiredApprovers,
      approvals: [],
      denials: [],
    };
    
    // Evict oldest pending approval if at capacity to prevent unbounded growth
    if (this.pendingApprovals.size >= this.maxPendingApprovals) {
      const oldestId = this.pendingApprovals.keys().next().value;
      if (oldestId) {
        this.pendingApprovals.delete(oldestId);
      }
    }

    this.pendingApprovals.set(approvalId, request);
    
    // Notify all required approvers
    await this.notifyApprovers(request);
    
    return {
      action: 'APPROVAL_REQUIRED',
      approvalId,
      message: `Operation requires approval from: ${requiredApprovers.join(', ')}`,
      expiresAt: request.expiresAt,
    };
  }

  async approve(
    approvalId: string, 
    approverId: string, 
    approverGroup: string,
    comment?: string
  ): Promise<ApprovalStatus> {
    const request = this.pendingApprovals.get(approvalId);
    if (!request || request.status !== 'PENDING') {
      return { success: false, reason: 'Invalid or expired approval request' };
    }
    
    // Check if this approver is in the required list
    if (!request.requiredApprovers.includes(approverGroup)) {
      return { success: false, reason: 'Approver not authorized for this request' };
    }
    
    // Check if already approved by this group
    if (request.approvals.some(a => a.approverGroup === approverGroup)) {
      return { success: false, reason: 'Already approved by this group' };
    }
    
    // Add approval
    request.approvals.push({
      approverId,
      approverGroup,
      timestamp: Date.now(),
      comment,
    });
    
    // Check if we have enough approvals
    if (this.isFullyApproved(request)) {
      request.status = 'APPROVED';
      this.pendingApprovals.delete(approvalId);
      return { success: true, status: 'APPROVED' };
    }
    
    return { success: true, status: 'PENDING', pendingApprovals: this.getPendingApproverGroups(request) };
  }

  async deny(
    approvalId: string, 
    approverId: string, 
    approverGroup: string,
    reason?: string
  ): Promise<ApprovalStatus> {
    const request = this.pendingApprovals.get(approvalId);
    if (!request || request.status !== 'PENDING') {
      return { success: false, reason: 'Invalid or expired approval request' };
    }
    
    // Any denial from a required group denies the request
    if (request.requiredApprovers.includes(approverGroup)) {
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
    
    return { success: false, reason: 'Approver not authorized for this request' };
  }

  private isFullyApproved(request: ApprovalRequest): boolean {
    const approvedGroups = new Set(request.approvals.map(a => a.approverGroup));
    return request.requiredApprovers.every(group => approvedGroups.has(group));
  }

  private getPendingApproverGroups(request: ApprovalRequest): string[] {
    const approvedGroups = new Set(request.approvals.map(a => a.approverGroup));
    return request.requiredApprovers.filter(group => !approvedGroups.has(group));
  }

  private async notifyApprovers(request: ApprovalRequest): Promise<void> {
    const pendingGroups = this.getPendingApproverGroups(request);
    
    await Promise.all(
      pendingGroups.map(async (group) => {
        const approver = this.approverGroups.get(group);
        if (approver) {
          await approver.notify(request);
        }
      })
    );
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
}
```

### Webhook Approver
```typescript
// src/policies/approvers/webhook-approver.ts
export class WebhookApprover implements ApproverGroup {
  private url: string;
  private apiKey: string;

  constructor(config: WebhookApproverConfig) {
    this.url = config.url;
    this.apiKey = process.env[config.api_key_env] || '';
  }

  async notify(request: ApprovalRequest): Promise<void> {
    await fetch(this.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        event: 'approval_requested',
        approval_id: request.id,
        tool_name: request.context.toolName,
        arguments: request.context.arguments,
        requested_by: request.context.agentId,
        expires_at: new Date(request.expiresAt).toISOString(),
        approval_url: `${this.url}/approve/${request.id}`,
      }),
    });
  }
}
```

### Slack Approver
```typescript
// src/policies/approvers/slack-approver.ts
export class SlackApprover implements ApproverGroup {
  private channel: string;
  private botToken: string;

  constructor(config: SlackApproverConfig) {
    this.channel = config.channel;
    this.botToken = process.env[config.bot_token_env] || '';
  }

  async notify(request: ApprovalRequest): Promise<void> {
    const message = {
      channel: this.channel,
      text: `🔒 Approval Required for ${request.context.toolName}`,
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Tool:* ${request.context.toolName}\n*Agent:* ${request.context.agentId}\n*Expires:* ${new Date(request.expiresAt).toISOString()}`
          }
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: '```' + JSON.stringify(request.context.arguments, null, 2) + '```'
          }
        },
        {
          type: 'actions',
          elements: [
            {
              type: 'button',
              text: { type: 'plain_text', text: '✅ Approve' },
              value: `approve:${request.id}`,
              action_id: 'approve'
            },
            {
              type: 'button',
              text: { type: 'plain_text', text: '❌ Deny' },
              value: `deny:${request.id}`,
              action_id: 'deny',
              style: { danger: true }
            }
          ]
        }
      ]
    };

    await fetch('https://slack.com/api/chat.postMessage', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.botToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(message),
    });
  }
}
```

### Emergency Override (Break-Glass)
```typescript
// src/policies/emergency-override.ts
export class EmergencyOverride {
  private enabled: boolean;
  private token: string;
  private auditLogger: AuditLogger;

  constructor(config: EmergencyOverrideConfig, auditLogger: AuditLogger) {
    this.enabled = config.enabled;
    this.token = process.env[config.token_env] || '';
    this.auditLogger = auditLogger;
  }

  async validate(token: string, context: RequestContext): Promise<boolean> {
    if (!this.enabled) return false;
    if (token !== this.token) return false;
    
    // Log the emergency override
    await this.auditLogger.log({
      type: 'EMERGENCY_OVERRIDE',
      sessionId: context.sessionId,
      toolName: context.toolName,
      arguments: context.arguments,
      decision: 'ALLOW',
      metadata: {
        override_type: 'break_glass',
        timestamp: new Date().toISOString(),
      },
      latency: 0,
    });
    
    return true;
  }
}
```

## Approval Status Codes

| Status | Description |
|--------|-------------|
| `PENDING` | Waiting for approvals |
| `APPROVED` | All required approvals received |
| `DENIED` | At least one required approver denied |
| `EXPIRED` | Approval timeout exceeded |

## Error Responses

### Approval Required
```json
{
  "error": {
    "code": "APPROVAL_REQUIRED",
    "message": "Operation requires human approval",
    "details": {
      "approval_id": "appr_abc123",
      "required_approvers": ["security-team"],
      "expires_at": "2026-04-22T06:30:00.000Z",
      "status_url": "/api/v1/approvals/appr_abc123"
    }
  }
}
```

### Approval Expired
```json
{
  "error": {
    "code": "APPROVAL_EXPIRED",
    "message": "Approval request has expired",
    "details": {
      "approval_id": "appr_abc123",
      "expired_at": "2026-04-22T06:30:00.000Z"
    }
  }
}
```

## Testing

### Unit Tests
```typescript
describe('ApprovalWorkflow', () => {
  let workflow: ApprovalWorkflow;

  beforeEach(() => {
    workflow = new ApprovalWorkflow({
      default_timeout_ms: 300000,
      approver_groups: {
        'security-team': { type: 'webhook', url: 'http://test.com' }
      }
    });
  });

  it('should create approval request', async () => {
    const result = await workflow.requestApproval({
      sessionId: 'test',
      toolName: 'database_execute',
      arguments: { query: 'DROP TABLE users' }
    });

    expect(result.action).toBe('APPROVAL_REQUIRED');
    expect(result.approvalId).toBeDefined();
  });

  it('should approve when all required approvers approve', async () => {
    const request = await workflow.requestApproval({
      sessionId: 'test',
      toolName: 'database_execute',
      arguments: { query: 'DROP TABLE users' }
    });

    const approval = await workflow.approve(
      request.approvalId,
      'user1',
      'security-team'
    );

    expect(approval.success).toBe(true);
    expect(approval.status).toBe('APPROVED');
  });

  it('should deny when any required approver denies', async () => {
    const request = await workflow.requestApproval({
      sessionId: 'test',
      toolName: 'database_execute',
      arguments: { query: 'DROP TABLE users' }
    });

    const denial = await workflow.deny(
      request.approvalId,
      'user1',
      'security-team',
      'Too dangerous'
    );

    expect(denial.success).toBe(true);
    expect(denial.status).toBe('DENIED');
  });
});
```

## Output
- Complete approval workflow system
- Multiple approval interfaces
- Multi-level approval support
- Emergency override capabilities
- Comprehensive audit trail

## Related Skills
- `policy-engine` - Integrate approval requirements
- `audit-logger` - Log approval events
- `security-review` - Review approval patterns
