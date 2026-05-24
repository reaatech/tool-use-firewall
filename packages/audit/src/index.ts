import { type WriteStream, createWriteStream } from 'node:fs';
import type { AuditConfig } from '@reaatech/tool-use-firewall-config';
import {
  DEFAULT_REDACTION_PATTERNS,
  Logger,
  type RedactionPattern,
  redact,
  safeRegExp,
} from '@reaatech/tool-use-firewall-core';

/** Abort an in-flight sidecar HTTP delivery after this long so a slow or
 * unreachable aggregator never blocks audit logging indefinitely. */
const SIDECAR_TIMEOUT_MS = 5000;

interface SidecarHttpTarget {
  endpoint: string;
  apiKey?: string;
}

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
  private readonly sidecarHttpTargets: SidecarHttpTarget[] = [];
  private readonly sidecarStreams: WriteStream[] = [];

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
      if (out.type === 'sidecar') {
        if (!out.endpoint && !out.path) {
          throw new Error('audit.output[sidecar] requires an `endpoint` URL and/or a `path`');
        }
        if (out.endpoint) {
          const apiKey = out.api_key_env ? process.env[out.api_key_env] : undefined;
          this.sidecarHttpTargets.push({ endpoint: out.endpoint, apiKey });
        }
        if (out.path) {
          this.sidecarStreams.push(createWriteStream(out.path, { flags: 'a' }));
        }
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

    if (this.sidecarHttpTargets.length > 0 || this.sidecarStreams.length > 0) {
      this.forwardToSidecars(safeEvent);
    }
  }

  /** Best-effort delivery of an audit event to each configured sidecar — an
   * HTTP aggregator/SIEM endpoint, a local file, or both. Failures are logged
   * to stderr and never propagate, so a downed aggregator (or a write error)
   * cannot break the proxy or add latency to the request that produced the
   * event. */
  private forwardToSidecars(event: unknown): void {
    const body = JSON.stringify(event);

    for (const stream of this.sidecarStreams) {
      stream.write(`${body}\n`, (error) => {
        if (error) {
          this.logger.error('audit sidecar file write failed', {
            path: stream.path.toString(),
            error: error.message,
          });
        }
      });
    }

    for (const target of this.sidecarHttpTargets) {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (target.apiKey) {
        headers.Authorization = `Bearer ${target.apiKey}`;
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), SIDECAR_TIMEOUT_MS);
      fetch(target.endpoint, { method: 'POST', headers, body, signal: controller.signal })
        .then((res) => {
          if (!res.ok) {
            this.logger.error('audit sidecar returned a non-2xx response', {
              endpoint: target.endpoint,
              status: res.status,
            });
          }
        })
        .catch((error) => {
          this.logger.error('audit sidecar delivery failed', {
            endpoint: target.endpoint,
            error: error instanceof Error ? error.message : String(error),
          });
        })
        .finally(() => clearTimeout(timeout));
    }
  }
}
