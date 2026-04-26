# Skill: Audit Logger

## Description
Configure audit logging and compliance for the tool-use-firewall. The audit logger captures complete request/response data, provides structured logging, and supports integration with SIEM systems and log aggregation platforms.

## When to Use
- Implementing compliance requirements
- Setting up security monitoring
- Creating audit trails for tool usage
- Investigating security incidents
- Meeting regulatory requirements (SOC2, ISO27001, etc.)

## Capabilities
- Full request/response capture
- Structured JSON logging
- Sensitive data redaction
- SIEM integration
- Log rotation and retention
- Real-time alerting

## Audit Configuration

```yaml
# policy.yaml
audit:
  # Logging level
  level: "FULL"  # NONE, SUMMARY, FULL
  
  # Output destinations
  output:
    # File-based logging
    - type: "file"
      path: "/var/log/tool-firewall/audit.log"
      format: "json"
      rotation: "daily"
      max_files: 90
      compress: true
      
    # SIEM integration
    - type: "siem"
      endpoint: "https://siem.company.com/api/events"
      api_key_env: "SIEM_API_KEY"
      batch_size: 100
      flush_interval_ms: 5000
      
    # stdout for development
    - type: "stdout"
      format: "json"
      colorize: false
  
  # Sensitive data redaction
  redaction:
    enabled: true
    patterns:
      - name: "password"
        pattern: "password"
        replacement: "[REDACTED]"
      - name: "token"
        pattern: "(?i)(api[_-]?key|token|secret|auth)"
        replacement: "[REDACTED]"
      - name: "ssn"
        pattern: "\\d{3}-\\d{2}-\\d{4}"
        replacement: "XXX-XX-XXXX"
      - name: "credit_card"
        pattern: "\\d{13,19}"
        replacement: "[CREDIT_CARD]"
      - name: "email"
        pattern: "[\\w.-]+@[\\w.-]+\\.[a-zA-Z]{2,}"
        replacement: "[EMAIL]"
  
  # What to log
  log_events:
    - "REQUEST_RECEIVED"
    - "REQUEST_BLOCKED"
    - "REQUEST_ALLOWED"
    - "APPROVAL_REQUESTED"
    - "APPROVAL_GRANTED"
    - "APPROVAL_DENIED"
    - "RATE_LIMIT_EXCEEDED"
    - "POLICY_VIOLATION"
    - "CONFIG_CHANGED"
    - "ERROR"
```

## Implementation

### Audit Logger
```typescript
// src/audit/audit-logger.ts
export interface AuditEntry {
  timestamp: string;
  eventId: string;
  type: AuditEventType;
  sessionId: string;
  agentId?: string;
  toolName: string;
  arguments?: Record<string, unknown>;
  response?: unknown;
  policyDecision: 'ALLOW' | 'BLOCK' | 'APPROVAL_REQUIRED';
  blockedBy?: string;
  approvalId?: string;
  latency: number;
  metadata?: Record<string, unknown>;
}

export class AuditLogger {
  private outputs: AuditOutput[] = [];
  private redactor: DataRedactor;
  private eventQueue: AuditEntry[] = [];

  constructor(config: AuditConfig) {
    this.redactor = new DataRedactor(config.redaction);
    this.outputs = config.output.map(o => this.createOutput(o));
  }

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

    // Write to all configured outputs
    await Promise.all(
      this.outputs.map(output => output.write(entry))
    );
  }

  private redactSensitive(data: unknown): unknown {
    if (!data) return data;
    const json = JSON.stringify(data);
    return JSON.parse(this.redactor.redact(json));
  }

  private createOutput(config: OutputConfig): AuditOutput {
    switch (config.type) {
      case 'file':
        return new FileOutput(config);
      case 'siem':
        return new SIEMOutput(config);
      case 'stdout':
        return new StdoutOutput(config);
      default:
        throw new Error(`Unknown output type: ${config.type}`);
    }
  }
}
```

### File Output with Rotation
```typescript
// src/audit/outputs/file-output.ts
export class FileOutput implements AuditOutput {
  private path: string;
  private stream: fs.WriteStream;
  private rotation: RotationConfig;
  private currentSize: number = 0;

  constructor(config: FileOutputConfig) {
    this.path = config.path;
    this.rotation = {
      maxFiles: config.max_files || 30,
      rotate: config.rotation || 'daily',
      compress: config.compress ?? true,
    };
    
    this.stream = fs.createWriteStream(this.path, { flags: 'a' });
    this.currentSize = fs.existsSync(this.path) ? (fs.statSync(this.path)?.size || 0) : 0;
  }

  async write(entry: AuditEntry): Promise<void> {
    const line = JSON.stringify(entry) + '\n';
    
    // Check if rotation is needed
    if (this.needsRotation()) {
      await this.rotate();
    }
    
    this.stream.write(line);
    this.currentSize += Buffer.byteLength(line);
  }

  private needsRotation(): boolean {
    const now = new Date();
    
    if (this.rotation.rotate === 'daily') {
      return this.isNewDay();
    }
    
    if (this.rotation.rotate === 'size') {
      return this.currentSize > 100 * 1024 * 1024; // 100MB
    }
    
    return false;
  }

  private async rotate(): Promise<void> {
    this.stream.end();
    
    const timestamp = new Date().toISOString().split('T')[0];
    const oldPath = this.path;
    const newPath = `${this.path}.${timestamp}`;
    
    fs.renameSync(oldPath, newPath);
    
    if (this.rotation.compress) {
      await this.compress(newPath);
    }
    
    // Clean up old files
    await this.cleanupOldFiles();
    
    this.stream = fs.createWriteStream(this.path, { flags: 'a' });
    this.currentSize = 0;
  }

  private async cleanupOldFiles(): Promise<void> {
    const files = await fs.promises.readdir(path.dirname(this.path));
    const auditFiles = files
      .filter(f => f.startsWith(path.basename(this.path)))
      .sort()
      .reverse();
    
    // Keep only maxFiles
    for (let i = this.rotation.maxFiles; i < auditFiles.length; i++) {
      await fs.promises.unlink(path.join(path.dirname(this.path), auditFiles[i]));
    }
  }
}
```

### SIEM Integration
```typescript
// src/audit/outputs/siem-output.ts
export class SIEMOutput implements AuditOutput {
  private endpoint: string;
  private apiKey: string;
  private batchSize: number;
  private flushInterval: number;
  private queue: AuditEntry[] = [];

  constructor(config: SIEMOutputConfig) {
    this.endpoint = config.endpoint;
    this.apiKey = process.env[config.api_key_env] || '';
    this.batchSize = config.batch_size || 100;
    this.flushInterval = config.flush_interval_ms || 5000;
    
    // Auto-flush
    setInterval(() => this.flush(), this.flushInterval);
  }

  async write(entry: AuditEntry): Promise<void> {
    this.queue.push(entry);
    
    if (this.queue.length >= this.batchSize) {
      await this.flush();
    }
  }

  private async flush(): Promise<void> {
    if (this.queue.length === 0) return;
    
    const batch = this.queue.splice(0, this.batchSize);
    
    try {
      await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          events: batch,
          source: 'tool-use-firewall',
          timestamp: new Date().toISOString(),
        }),
      });
    } catch (error) {
      // Re-queue on failure
      this.queue.unshift(...batch);
      console.error('Failed to send events to SIEM:', error);
    }
  }
}
```

## Audit Event Types

| Event Type | Description | When Triggered |
|------------|-------------|----------------|
| `REQUEST_RECEIVED` | Tool call received | Every incoming request |
| `REQUEST_ALLOWED` | Tool call permitted | After all checks pass |
| `REQUEST_BLOCKED` | Tool call denied | When any check fails |
| `APPROVAL_REQUESTED` | Human approval needed | When approval rule matches |
| `APPROVAL_GRANTED` | Approval given | When approver approves |
| `APPROVAL_DENIED` | Approval rejected | When approver denies |
| `RATE_LIMIT_EXCEEDED` | Rate limit hit | When rate limit exceeded |
| `POLICY_VIOLATION` | Policy rule violated | When policy blocks request |
| `CONFIG_CHANGED` | Configuration updated | When policy is reloaded |
| `ERROR` | System error | On internal errors |

## Example Audit Entry

```json
{
  "timestamp": "2026-04-22T06:00:00.000Z",
  "eventId": "evt_abc123def456",
  "type": "REQUEST_BLOCKED",
  "sessionId": "sess_xyz789",
  "agentId": "agent_claude_001",
  "toolName": "database_execute",
  "arguments": {
    "query": "DROP TABLE [REDACTED]"
  },
  "response": null,
  "policyDecision": "BLOCK",
  "blockedBy": "sql_safe",
  "approvalId": null,
  "latency": 2.5,
  "metadata": {
    "rule_id": "sql_safe",
    "rule_name": "SQL Safety Check",
    "query_type": "DROP",
    "risk_level": "CRITICAL"
  }
}
```

## Testing

### Unit Tests
```typescript
describe('AuditLogger', () => {
  it('should redact sensitive data', async () => {
    const logger = new AuditLogger({
      output: [{ type: 'stdout' }],
      redaction: {
        enabled: true,
        patterns: [{ name: 'password', pattern: 'password', replacement: '[REDACTED]' }]
      }
    });
    
    const entry = await logger.log({
      type: 'REQUEST_ALLOWED',
      sessionId: 'test',
      toolName: 'test',
      arguments: { password: 'secret123' },
      decision: 'ALLOW',
      latency: 1
    });
    
    expect(entry.arguments.password).toBe('[REDACTED]');
  });

  it('should generate unique event IDs', async () => {
    const logger = new AuditLogger({
      output: [{ type: 'stdout' }]
    });
    
    const entry1 = await logger.log({ type: 'REQUEST_ALLOWED', sessionId: 'test', toolName: 'test', decision: 'ALLOW', latency: 1 });
    const entry2 = await logger.log({ type: 'REQUEST_ALLOWED', sessionId: 'test', toolName: 'test', decision: 'ALLOW', latency: 1 });
    
    expect(entry1.eventId).not.toBe(entry2.eventId);
  });
});
```

## Output
- Comprehensive audit logging
- Multiple output destinations
- Sensitive data redaction
- Log rotation and retention
- SIEM integration
- Structured JSON format

## Related Skills
- `policy-engine` - Log policy decisions
- `approval-workflow` - Log approval events
- `security-review` - Review audit trails
