# Architecture: tool-use-firewall

## System Overview

The **tool-use-firewall** is an MCP (Model Context Protocol) proxy server that intercepts all communication between AI agents and upstream MCP servers. It enforces security policies, validates arguments, manages rate limits, tracks costs, and provides human-in-the-loop approval workflows.

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   AI Agent      │────▶│   tool-use-firewall  │────▶│  Upstream MCP   │
│   (Claude,      │     │   (Policy Engine)    │     │  Server         │
│   GPT, etc.)    │◀────│                      │◀────│  (Database,     │
└─────────────────┘     └──────────────────────┘     │   Filesystem,   │
                                                      │   Network, etc.) │
                                                      └─────────────────┘
```

---

## Core Architecture Principles

1. **Zero Trust**: Every tool call is treated as potentially dangerous until validated
2. **Defense in Depth**: Multiple layers of validation and enforcement
3. **Fail Secure**: On error, deny access rather than allow it
4. **Audit Everything**: Complete traceability for every action
5. **Performance Matters**: Minimal latency overhead (<10ms for pass-through)

---

## Request Context

Every incoming request is wrapped in a `RequestContext` that flows through the entire pipeline:

```typescript
// src/middleware/context.ts
export interface RequestContext {
  // Request identity
  requestId: string;        // UUID for this specific request
  sessionId: string;        // Agent session identifier
  agentId?: string;         // Optional agent identifier

  // MCP protocol info
  method: string;           // e.g., "tools/call", "tools/list"
  toolName?: string;        // Present for tools/call
  arguments?: Record<string, unknown>;  // Present for tools/call
  resourceUri?: string;     // Present for resources/read

  // Timing
  receivedAt: number;       // Date.now() when request arrived

  // Mutable state during pipeline execution
  metadata: Map<string, unknown>;
}
```

---

## Component Architecture

### 1. Transport Layer

The transport layer handles communication with both the AI agent (downstream) and the upstream MCP server.

**MCP is stdio-first.** The current implementation spawns the upstream MCP
server as a child process and proxies JSON-RPC over stdin/stdout (see
`src/server.ts`). HTTP/SSE and WebSocket transports are on the roadmap but not
yet implemented.

#### Supported Transports
- **Stdio** (implemented): Spawns the upstream MCP server as a child process and
  proxies JSON-RPC messages over stdin/stdout.
- **HTTP/SSE** (planned).
- **WebSocket** (planned).

#### MCP Protocol Proxying

The firewall is a full MCP protocol proxy. It does not merely proxy `tools/call`; it must handle the complete MCP lifecycle:

| MCP Method | Proxy Behavior |
|------------|----------------|
| `initialize` | Pass through with capability negotiation |
| `tools/list` | Pass through; cache tool schema for validation context |
| `tools/call` | **Intercept** — run full interceptor pipeline |
| `resources/list` | Pass through (optionally filter by policy) |
| `resources/read` | Pass through (optionally validate URI patterns) |
| `resources/subscribe` | Pass through |
| `prompts/list` | Pass through |
| `prompts/get` | Pass through |
| `sampling/createMessage` | Pass through (or block if disallowed) |
| `notifications/*` | Pass through bidirectionally |

The `tools/list` response is cached so the firewall knows available tool names and schemas for validation and logging. All other methods are passed through transparently, though future phases may add URI validation for resources.

```typescript
// src/server.ts
export class MCPProxyServer {
  async handleMessage(message: JSONRPCMessage): Promise<void> {
    switch (message.method) {
      case 'tools/call':
        return this.handleToolCall(message);
      case 'tools/list':
        const tools = await this.forwardToUpstream(message);
        this.toolCache.update(tools);
        return tools;
      default:
        return this.forwardToUpstream(message);
    }
  }
}
```

### 2. Interceptor Pipeline

The interceptor pipeline is the heart of the firewall. Every tool call passes through a series of specialized middlewares in strict order:

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Request    │───▶│    Rate      │───▶│    Cost      │───▶│  Argument    │
│   Parser     │    │   Limiter    │    │   Tracker    │    │  Validator   │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
                                                                  │
                                                                  ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Audit      │◀───│   Approval   │◀───│   Read-Only  │◀───│   Custom     │
│   Logger     │    │   Workflow   │    │    Check     │    │   Rules      │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
                                                                  │
                                                                  ▼
                                                           ┌──────────────┐
                                                           │   Upstream   │
                                                           │    MCP       │
                                                           │   Server     │
                                                           └──────────────┘
```

**Pipeline stages (in order):**
1. **Rate Limiter** — Prevents abuse (global, per-tool, per-session)
2. **Cost Tracker** — Enforces session budgets
3. **Argument Validator** — Schema and regex validation on arguments
4. **Custom Rules Engine** — YAML-defined allow/block/approval rules
5. **Read-Only Check** — Blocks write operations when enabled
6. **Approval Workflow** — Human-in-the-loop for high-risk operations
7. **Audit Logger** — Records the final decision and forwards/returns

Each middleware can return `CONTINUE`, `BLOCK`, or `APPROVAL_REQUIRED`. On `BLOCK`, the pipeline short-circuits and returns an error. On `APPROVAL_REQUIRED`, execution pauses until approved.

```typescript
// src/middleware/interceptor.ts
export class InterceptorPipeline {
  private middlewares: Middleware[] = [];
  
  async process(context: RequestContext): Promise<ToolResponse> {
    for (const middleware of this.middlewares) {
      const result = await middleware.execute(context);
      if (result.action === 'BLOCK') {
        return this.createBlockResponse(context, result.reason);
      }
      if (result.action === 'APPROVAL_REQUIRED') {
        return await this.handleApproval(context, result);
      }
    }
    
    // All checks passed, forward to upstream
    const response = await this.forwardToUpstream(context);
    await this.audit('ALLOWED', context, response);
    return response;
  }
}
```

### 3. Policy Engine

The policy engine evaluates all configured rules against incoming requests.

```typescript
// src/policies/engine.ts
export interface Policy {
  id: string;
  name: string;
  description?: string;
  rules: Rule[];
  defaults: DefaultBehavior;
}

export interface Rule {
  id: string;
  type: RuleType;
  tools?: string[];        // Tool name patterns
  conditions: Condition[];
  action: RuleAction;
  priority: number;
}

export class PolicyEngine {
  async evaluate(context: RequestContext, policy: Policy): Promise<EvaluationResult> {
    const applicableRules = this.getApplicableRules(context, policy);
    
    for (const rule of applicableRules.sort((a, b) => b.priority - a.priority)) {
      const matches = await this.evaluateConditions(rule.conditions, context);
      if (matches) {
        return { action: rule.action, rule };
      }
    }
    
    return { action: policy.defaults.action };
  }
}
```

### 4. Rate Limiter

Token bucket algorithm implementation for rate limiting.

```typescript
// src/policies/rate-limit.ts
export class TokenBucketRateLimiter {
  private buckets: Map<string, TokenBucket> = new Map();
  
  async checkLimit(key: string, cost: number = 1): Promise<RateLimitResult> {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = new TokenBucket({
        capacity: this.config.capacity,
        refillRate: this.config.refillRate
      });
      this.buckets.set(key, bucket);
    }
    
    return bucket.consume(cost);
  }
}
```

### 5. Cost Tracker

Tracks and enforces cost budgets per session.

```typescript
// src/policies/cost-tracker.ts
export class CostTracker {
  private sessions: Map<string, SessionCost> = new Map();
  
  async trackCost(sessionId: string, toolName: string, args: unknown): Promise<CostEstimate> {
    const estimate = await this.estimateCost(toolName, args);
    const session = this.getOrCreateSession(sessionId);
    
    if (session.totalCost + estimate.cost > session.budget) {
      return { ...estimate, approved: false, reason: 'BUDGET_EXCEEDED' };
    }
    
    session.totalCost += estimate.cost;
    return { ...estimate, approved: true };
  }
}
```

### 6. Argument Validator

Validates tool arguments against security rules.

```typescript
// src/policies/validator.ts
export class ArgumentValidator {
  private validators: Map<string, ValidatorFn> = new Map();
  
  constructor() {
    this.registerDefaultValidators();
  }
  
  private registerDefaultValidators() {
    // SQL injection prevention
    this.validators.set('sql_safe', (value: string) => {
      const dangerousPatterns = [
        /DROP\s+TABLE/i,
        /DELETE\s+FROM\s+\w+\s*;$/i,  // DELETE without WHERE
        /TRUNCATE/i,
        /;\s*DROP/i,
        /UNION\s+SELECT/i,
        /OR\s+1\s*=\s*1/i,
      ];
      
      for (const pattern of dangerousPatterns) {
        if (pattern.test(value)) {
          return { valid: false, reason: `Blocked by pattern: ${pattern.source}` };
        }
      }
      return { valid: true };
    });
    
    // Command injection prevention
    this.validators.set('shell_safe', (value: string) => {
      const dangerousChars = [';', '&&', '||', '|', '`', '$(', '${'];
      for (const char of dangerousChars) {
        if (value.includes(char)) {
          return { valid: false, reason: `Contains dangerous character sequence: ${char}` };
        }
      }
      return { valid: true };
    });
  }
  
  async validate(toolName: string, args: Record<string, unknown>, rules: ValidationRule[]): Promise<ValidationResult> {
    for (const rule of rules) {
      if (this.matchesTool(toolName, rule.tools)) {
        const value = this.extractArgValue(args, rule.argument);
        const result = await rule.validator(value);
        if (!result.valid) {
          return { valid: false, reason: result.reason, rule: rule.id };
        }
      }
    }
    return { valid: true };
  }
}
```

### 7. Approval Workflow

Manages human-in-the-loop approval processes. See `src/approvals/workflow.ts`
for the full implementation; the snippet below is illustrative.

```typescript
// Illustrative — see src/approvals/workflow.ts
export class ApprovalWorkflow {
  private pendingApprovals: Map<string, PendingApproval> = new Map();
  
  async requestApproval(context: RequestContext): Promise<ApprovalResult> {
    const approvalId = generateUUID();
    const pending: PendingApproval = {
      id: approvalId,
      context,
      createdAt: Date.now(),
      expiresAt: Date.now() + this.config.timeoutMs,
      status: 'PENDING',
      approvers: this.determineApprovers(context),
    };
    
    this.pendingApprovals.set(approvalId, pending);
    
    // Notify approvers
    await this.notifyApprovers(pending);
    
    return {
      action: 'APPROVAL_REQUIRED',
      approvalId,
      message: pending.context.toolName + ' requires approval',
    };
  }
  
  async approve(approvalId: string, approverId: string, comment?: string): Promise<boolean> {
    const pending = this.pendingApprovals.get(approvalId);
    if (!pending || pending.status !== 'PENDING') {
      return false;
    }
    
    pending.approvals.push({ approverId, comment, timestamp: Date.now() });
    
    if (this.isFullyApproved(pending)) {
      pending.status = 'APPROVED';
      return true;
    }
    
    return false;
  }
}
```

### 8. Audit Logger

Comprehensive logging of all activities. See `src/audit/index.ts` for the
full implementation; the snippet below is illustrative.

```typescript
// Illustrative — see src/audit/index.ts
export class AuditLogger {
  async log(event: AuditEvent): Promise<void> {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      eventId: generateUUID(),
      type: event.type,
      sessionId: event.sessionId,
      agentId: event.agentId,
      toolName: event.toolName,
      arguments: this.redactSensitive(event.arguments),
      response: this.redactSensitive(event.response),
      policyDecision: event.decision,
      blockedBy: event.blockedBy,
      approvalId: event.approvalId,
      latency: event.latency,
      metadata: event.metadata,
    };
    
    // Write to structured log
    this.logger.info(entry, 'audit_event');
    
    // Write to persistent storage
    await this.storage.write(entry);
    
    // Send to SIEM if configured
    if (this.siem) {
      await this.siem.send(entry);
    }
  }
}
```

---

## Data Flow

### Request Flow

```
1. AI Agent sends MCP request (e.g., tools/call, tools/list, resources/read)
        │
        ▼
2. Transport layer receives and parses request
        │
        ▼
3. Create RequestContext with:
   - Session ID
   - Agent ID  
   - Method, tool name, arguments, resource URI
   - Timestamp
   - Request ID (UUID)
        │
        ▼
4a. Non-tool methods (tools/list, resources/*, prompts/*)
    ├── Pass through directly to upstream
    └── Return upstream response to agent
        │
        ▼
4b. tools/call enters interceptor pipeline
    ├── Rate Limiter checks if request is within limits
    │   ├── If exceeded → BLOCK with rate limit error
    │   └── If OK → Continue
    ├── Cost Tracker estimates and validates cost
    │   ├── If budget exceeded → BLOCK or request approval
    │   └── If OK → Continue
    ├── Argument Validator checks arguments
    │   ├── If validation fails → BLOCK with reason
    │   └── If OK → Continue
    ├── Custom Rules Engine evaluates YAML rules
    │   ├── If BLOCK rule matches → BLOCK
    │   ├── If APPROVAL_REQUIRED rule matches → Request approval
    │   └── If ALLOW rule matches → Continue
    ├── Read-Only Mode check
    │   ├── If write operation in read-only mode → BLOCK
    │   └── If OK → Continue
    ├── Approval Workflow (if triggered)
    │   ├── If denied or expired → BLOCK
    │   └── If approved → Continue
    └── Forward to upstream MCP server
        │
        ▼
5. Receive response from upstream
        │
        ▼
6. Audit Logger records complete request/response
        │
        ▼
7. Return response to AI Agent
```

### Approval Flow

```
1. Policy Engine determines approval required
        │
        ▼
2. Create PendingApproval record
        │
        ▼
3. Notify approvers via configured channels:
   ├── CLI prompt (local)
   ├── HTTP webhook (external system)
   └── Email/Slack (if configured)
        │
        ▼
4. Wait for approval (with timeout)
        │
   ┌────┴────┐
   ▼         ▼
5a. Approve    5b. Deny / Timeout
   │            │
   ▼            ▼
6a. Execute    6b. Return denial
   tool        response
   │            │
   ▼            ▼
7a. Audit      7b. Audit
   approved       denied
```

---

## Configuration Schema

### Policy YAML Structure

```yaml
# policy.yaml
version: "1.0"

# Global settings
settings:
  read_only: false
  default_action: "BLOCK"  # BLOCK or ALLOW
  audit_level: "FULL"      # NONE, SUMMARY, FULL
  
# Rate limiting
rate_limits:
  global:
    requests_per_minute: 60
    burst_capacity: 10
  per_tool:
    "database_execute":
      requests_per_minute: 10
    "file_write":
      requests_per_minute: 30

# Cost management
cost:
  session_budget: 100.00  # USD
  tool_costs:
    "database_execute": 1.00
    "file_write": 0.10
    "api_call": 0.05
  budget_action: "BLOCK"  # BLOCK or WARN

# Validation rules
validation:
  rules:
    - id: "sql_safe"
      tools: ["database_execute"]
      argument: "query"
      type: "regex"
      patterns:
        - pattern: "DROP\\s+TABLE"
          flags: "i"
          message: "DROP TABLE is not allowed"
        - pattern: "DELETE\\s+FROM\\s+\\w+\\s*$"
          flags: "i"  
          message: "DELETE without WHERE clause is not allowed"
        - pattern: "TRUNCATE"
          flags: "i"
          message: "TRUNCATE is not allowed"
    
    - id: "shell_safe"
      tools: ["shell_exec"]
      argument: "command"
      type: "regex"
      patterns:
        - pattern: "[;&|`$]"
          message: "Shell metacharacters are not allowed"

# Approval requirements
approvals:
  required_for:
    - tools: ["database_execute"]
      conditions:
        - argument: "query"
          matches: "(DROP|DELETE|TRUNCATE|ALTER)"
          flags: "i"
    - tools: ["file_write"]
      conditions:
        - argument: "path"
          matches: "^/etc/|^/var/|^/usr/"
  
  approvers:
    - type: "webhook"
      url: "https://approval-system.company.com/approve"
      timeout_ms: 300000  # 5 minutes
    - type: "slack"
      channel: "#security-approvals"

# Read-only mode exceptions
read_only_exceptions:
  - tools: ["database_execute"]
    conditions:
      - argument: "query"
        matches: "^SELECT\\s+"
        flags: "i"

# Audit configuration
audit:
  output:
    - type: "file"
      path: "/var/log/tool-firewall/audit.log"
      rotation: "daily"
      retention_days: 90
    - type: "siem"
      endpoint: "https://siem.company.com/api/events"
      api_key_env: "SIEM_API_KEY"
  
  redaction:
    patterns:
      - "password"
      - "secret"
      - "token"
      - "api_key"
      - "\\d{3}-\\d{2}-\\d{4}"  # SSN
      - "\\d{16}"                # Credit card
```

---

## Security Considerations

### 1. Input Sanitization
- All arguments are validated before forwarding
- SQL injection patterns are blocked at the regex level
- Command injection vectors are eliminated

### 2. Principle of Least Privilege
- Default deny policy
- Explicit allow rules required for dangerous operations
- Human approval for high-risk actions

### 3. Defense in Depth
- Multiple validation layers
- Rate limiting prevents abuse
- Cost tracking prevents runaway operations

### 4. Audit and Accountability
- Every action is logged with full context
- Tamper-evident logs (optional hash chaining)
- Complete request/response capture

### 5. Fail Secure
- On configuration error → deny all
- On validation error → deny
- On upstream error → log and deny

---

## Performance Considerations

### Latency Targets
| Operation | Target Latency |
|-----------|----------------|
| Pass-through (no rules) | < 5ms |
| Single rule evaluation | < 1ms |
| Full pipeline (all rules) | < 10ms |
| Approval workflow | < 100ms (async) |

### Optimization Strategies
1. **Rule Caching**: Compile and cache regex patterns
2. **Parallel Evaluation**: Evaluate independent rules concurrently
3. **Connection Pooling**: Reuse upstream connections
4. **Request Batching**: Batch audit log writes

---

## Deployment Architecture

### Single Node Deployment

```
┌─────────────────────────────────────────────────────┐
│                    Host Machine                      │
│  ┌─────────────────────────────────────────────────┐ │
│  │              tool-use-firewall                   │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐           │ │
│  │  │ Transport│ │ Policy  │ │ Audit   │           │ │
│  │  │ Layer   │ │ Engine  │ │ Logger  │           │ │
│  │  └─────────┘ └─────────┘ └─────────┘           │ │
│  │                                                 │ │
│  │  ┌─────────────────────────────────────────┐   │ │
│  │  │         Upstream MCP Server             │   │ │
│  │  │    (Database / Filesystem / Network)    │   │ │
│  │  └─────────────────────────────────────────┘   │ │
│  └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

### Distributed Deployment

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   AI Agent  │     │   AI Agent  │     │   AI Agent  │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────┐
│              Load Balancer                           │
└─────────────────────────┬───────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
   │  Firewall   │ │  Firewall   │ │  Firewall   │
   │  Instance 1 │ │  Instance 2 │ │  Instance 3 │
   └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
          │               │               │
          └───────────────┼───────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
   │   MCP       │ │   MCP       │ │   MCP       │
   │  Server 1   │ │  Server 2   │ │  Server 3   │
   └─────────────┘ └─────────────┘ └─────────────┘
```

---

## API Reference

### Configuration API

```typescript
// Runtime configuration updates
POST /api/v1/config/reload
POST /api/v1/config/validate

// Policy management
GET  /api/v1/policies
POST /api/v1/policies
PUT  /api/v1/policies/:id
DELETE /api/v1/policies/:id
```

### Approval API

```typescript
// Pending approvals
GET  /api/v1/approvals/pending
GET  /api/v1/approvals/:id

// Approval actions
POST /api/v1/approvals/:id/approve
POST /api/v1/approvals/:id/deny

// Webhook callbacks
POST /api/v1/webhooks/approval-callback
```

### Audit API

```typescript
// Query audit logs
GET  /api/v1/audit/events?sessionId=xxx&toolName=xxx
GET  /api/v1/audit/events/:id

// Export audit data
GET  /api/v1/audit/export?format=json&startDate=xxx&endDate=xxx
```

### Metrics API

```typescript
// Prometheus metrics
GET  /metrics

// Health check
GET  /health
GET  /ready
```

---

## Error Handling

### Error Categories

| Category | HTTP Status | Description |
|----------|-------------|-------------|
| Validation Error | 400 | Request failed validation |
| Rate Limited | 429 | Rate limit exceeded |
| Budget Exceeded | 402 | Cost budget exceeded |
| Approval Required | 403 | Human approval needed |
| Policy Blocked | 403 | Blocked by policy rule |
| Internal Error | 500 | Firewall internal error |
| Upstream Error | 502 | Upstream server error |

### Error Response Format

```json
{
  "error": {
    "code": "POLICY_BLOCKED",
    "message": "Tool call blocked by policy rule",
    "details": {
      "rule_id": "sql_safe",
      "rule_name": "SQL Safety Check",
      "tool_name": "database_execute",
      "reason": "Query contains DROP TABLE pattern"
    },
    "request_id": "req_abc123",
    "timestamp": "2026-04-22T06:00:00.000Z"
  }
}
```

---

## Resource Management

All stateful components that store per-session or per-request data must implement eviction to prevent memory exhaustion in long-running deployments.

### Eviction Patterns

```typescript
// Pattern 1: TTL-based eviction (for session state)
class SessionStateManager {
  private sessions = new Map<string, SessionState>();
  private lastAccessed = new Map<string, number>();
  private readonly ttlMs: number;
  private readonly maxSize: number;

  getSession(id: string): SessionState {
    this.evictStale();
    // ... get or create
    this.lastAccessed.set(id, Date.now());
    return session;
  }

  private evictStale(): void {
    if (this.sessions.size < this.maxSize) return;
    const now = Date.now();
    for (const [id, lastAccess] of this.lastAccessed.entries()) {
      if (now - lastAccess > this.ttlMs) {
        this.sessions.delete(id);
        this.lastAccessed.delete(id);
      }
    }
  }
}

// Pattern 2: FIFO eviction with capacity limit (for approval queue)
class ApprovalQueue {
  private pending = new Map<string, ApprovalRequest>();
  private readonly maxSize: number;

  add(request: ApprovalRequest): void {
    if (this.pending.size >= this.maxSize) {
      const oldest = this.pending.keys().next().value;
      this.pending.delete(oldest);
    }
    this.pending.set(request.id, request);
  }
}

// Pattern 3: Periodic cleanup with disposers
class PeriodicCleaner {
  private intervalId: ReturnType<typeof setInterval> | null = null;

  start(cleanupFn: () => void, ms: number): void {
    this.intervalId = setInterval(cleanupFn, ms);
  }

  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }
}
```

### Components Requiring Eviction

| Component | State Store | Eviction Strategy |
|-----------|-------------|-------------------|
| Rate Limiter | `sessionLimiters` Map | TTL + capacity limit |
| Approval Workflow | `pendingApprovals` Map | FIFO capacity limit + timeout |
| Cost Tracker | `sessions` Map | TTL + capacity limit |
| Token Bucket | In-memory tokens | N/A (bounded by number of buckets) |
| Audit Logger | SIEM batch queue | Flush on size + periodic flush |

---

## Testing Strategy

### Unit Tests
- Policy engine rule evaluation
- Rate limiter token bucket algorithm
- Argument validator patterns
- Cost tracker calculations

### Integration Tests
- End-to-end request flow
- Multi-rule evaluation
- Approval workflow
- Upstream server communication

### Security Tests
- SQL injection pattern bypass attempts
- Rate limit bypass attempts
- Policy configuration tampering
- Audit log integrity

### Performance Tests
- High throughput scenarios
- Concurrent request handling
- Memory leak detection
- Latency benchmarks

---

## Conclusion

The tool-use-firewall architecture is designed to be:

- **Secure**: Multiple layers of validation and enforcement
- **Performant**: Minimal latency overhead with optimized pipelines
- **Extensible**: Plugin-based middleware architecture
- **Observable**: Comprehensive audit logging and metrics
- **Enterprise-Ready**: Production-grade reliability and deployment options

This architecture provides the foundation for a robust security layer that every enterprise deploying AI agents needs.
