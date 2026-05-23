import type { AuditConfig } from '@reaatech/tool-use-firewall-config';
import {
  DEFAULT_REDACTION_PATTERNS,
  Logger,
  type RedactionPattern,
  redact,
  safeRegExp,
} from '@reaatech/tool-use-firewall-core';

export type AuditDecision = 'ALLOW' | 'BLOCK' | 'APPROVAL_REQUIRED';

export interface AuditEvent {
  type: string;
  sessionId: string;
  toolName?: string;
  arguments?: Record<string, unknown>;
  response?: unknown;
  decision: AuditDecision;
  blockedBy?: string;
  approvalId?: string;
  latency: number;
  metadata?: Record<string, unknown>;
}

export interface AuditLoggerOptions {
  config?: AuditConfig;
  silent?: boolean;
}

export class AuditLogger {
  private readonly silent: boolean;
  private readonly level: 'none' | 'summary' | 'full';
  private readonly redactionEnabled: boolean;
  private readonly redactionPatterns?: RedactionPattern[];
  private readonly logger: Logger;

  constructor(options: AuditLoggerOptions = {}) {
    const config = options.config;
    this.silent = options.silent ?? process.env.NODE_ENV === 'test';
    this.level = config?.level ?? 'full';

    const redactionCfg = config?.redaction;
    this.redactionEnabled = redactionCfg?.enabled ?? true;
    if (redactionCfg?.patterns && redactionCfg.patterns.length > 0) {
      const custom = redactionCfg.patterns.map((p) => ({
        name: p.name,
        pattern: safeRegExp(p.pattern, 'g'),
        replacement: p.replacement,
      }));
      this.redactionPatterns = [...DEFAULT_REDACTION_PATTERNS, ...custom];
    }

    let filePath: string | undefined;
    for (const out of config?.output ?? []) {
      if (out.type === 'stdout') {
        throw new Error(
          'audit.output.type "stdout" is not allowed: stdout is reserved for the MCP JSON-RPC stream',
        );
      }
      if (out.type === 'file') {
        if (!out.path) throw new Error('audit.output[file] requires a `path`');
        filePath = out.path;
      }
    }
    this.logger = new Logger('AuditLogger', filePath);
  }

  async log(event: AuditEvent): Promise<void> {
    if (this.silent) return;
    if (this.level === 'none') return;

    const emitted: AuditEvent =
      this.level === 'summary'
        ? {
            type: event.type,
            sessionId: event.sessionId,
            toolName: event.toolName,
            decision: event.decision,
            blockedBy: event.blockedBy,
            approvalId: event.approvalId,
            latency: event.latency,
          }
        : event;

    const safeEvent = this.redactionEnabled ? redact(emitted, this.redactionPatterns) : emitted;
    this.logger.info('audit_event', safeEvent as unknown as Record<string, unknown>);
  }
}
