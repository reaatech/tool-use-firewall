import type { AuditConfig } from '@reaatech/tool-use-firewall-config';
import {
  DEFAULT_REDACTION_PATTERNS,
  Logger,
  type RedactionPattern,
  redact,
  safeRegExp,
} from '@reaatech/tool-use-firewall-core';
import { RotatingFileSink } from './file-sink.js';

export { type FileSinkOptions, RotatingFileSink } from './file-sink.js';

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
  private readonly logger = new Logger('AuditLogger');
  private readonly sidecarHttpTargets: SidecarHttpTarget[] = [];
  private readonly fileSinks: RotatingFileSink[] = [];

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

    const onError = (msg: string, meta: Record<string, unknown>) => this.logger.error(msg, meta);

    for (const out of config?.output ?? []) {
      if (out.type === 'stdout') {
        throw new Error(
          'audit.output.type "stdout" is not allowed: stdout is reserved for the MCP JSON-RPC stream',
        );
      }
      // `file` and `sidecar` share one local-file writer; `file` is simply a
      // local-only sink, while `sidecar` may also forward over HTTP.
      if (out.type === 'file') {
        if (!out.path) throw new Error('audit.output[file] requires a `path`');
        this.fileSinks.push(this.makeFileSink(out.path, out, onError));
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
          this.fileSinks.push(this.makeFileSink(out.path, out, onError));
        }
      }
    }
  }

  private makeFileSink(
    path: string,
    out: {
      rotation?: 'daily' | 'size';
      max_files?: number;
      max_size_bytes?: number;
      compress?: boolean;
    },
    onError: (msg: string, meta: Record<string, unknown>) => void,
  ): RotatingFileSink {
    return new RotatingFileSink(path, {
      rotation: out.rotation,
      maxFiles: out.max_files,
      maxSizeBytes: out.max_size_bytes,
      compress: out.compress,
      onError,
    });
  }

  /** Flush and close all file sinks. Call on shutdown; HTTP delivery is
   * fire-and-forget and needs no teardown. */
  close(): void {
    for (const sink of this.fileSinks) {
      sink.close();
    }
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

    const body = JSON.stringify(safeEvent);
    for (const sink of this.fileSinks) {
      sink.write(`${body}\n`);
    }

    if (this.sidecarHttpTargets.length > 0) {
      this.forwardToHttp(body);
    }
  }

  /** Best-effort HTTP delivery of an audit event to each configured aggregator/
   * SIEM endpoint. Fire-and-forget: failures are logged to stderr and never
   * propagate, so a downed aggregator cannot break the proxy or add latency to
   * the request that produced the event. */
  private forwardToHttp(body: string): void {
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
