import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { watch } from 'node:fs';
import type { Server as HttpServer } from 'node:http';
import { createServer } from 'node:http';
import { createInterface } from 'node:readline';
import {
  ApprovalWorkflow,
  type ApproverGroup,
  createApprovalApi,
} from '@reaatech/tool-use-firewall-approvals';
import { SlackApprover } from '@reaatech/tool-use-firewall-approvals';
import { DiscordApprover } from '@reaatech/tool-use-firewall-approvals';
import { AuditLogger } from '@reaatech/tool-use-firewall-audit';
import {
  type ApproverGroupConfig,
  type PolicyConfig,
  type UpstreamBackend,
  loadPolicyConfig,
} from '@reaatech/tool-use-firewall-config';
import {
  ApprovalRequiredError,
  FirewallError,
  Logger,
  RateLimitError,
  type RequestContext,
  createRequestContext,
  redact,
} from '@reaatech/tool-use-firewall-core';
import {
  AnomalyDetector,
  ArgumentValidator,
  CostTracker,
  PolicyEngine,
  RateLimiter,
  ReadOnlyCheck,
  SchemaValidator,
  SecretScanner,
} from '@reaatech/tool-use-firewall-policies';
import { z } from 'zod';
import { InterceptorPipeline } from './interceptor.js';

const MAX_SESSION_ID_LENGTH = 128;
const MAX_PENDING_RESPONSES = 10000;
const MAX_MESSAGE_SIZE_BYTES = 10 * 1024 * 1024;

const jsonRpcMessageSchema = z.object({
  jsonrpc: z.literal('2.0').optional(),
  id: z.union([z.string(), z.number(), z.null()]).optional(),
  method: z.string().optional(),
  params: z.record(z.string(), z.unknown()).optional(),
  result: z.unknown().optional(),
  error: z.unknown().optional(),
});

interface ServerOptions {
  policyPath: string;
  upstreamCommand?: string;
  upstreamArgs?: string[];
  approvalPort?: number;
}

interface UpstreamConnection {
  process: ChildProcess;
  backend: UpstreamBackend;
}

interface Metrics {
  requestsTotal: number;
  blocksTotal: number;
  approvalsTotal: number;
  errorsTotal: number;
  upstreamLatencyMs: number[];
  startTime: number;
}

/** Proxy server that sits between an AI agent and upstream MCP servers.
 *
 * Supports stdio and HTTP transport, multi-upstream routing, policy hot-reload,
 * dry-run mode, schema validation, secret scanning, and anomaly detection.
 *
 * @example
 * ```ts
 * const server = new MCPProxyServer({
 *   policyPath: './policies/default.yaml',
 *   upstreamCommand: 'node',
 *   upstreamArgs: ['./my-mcp-server.js'],
 *   approvalPort: 3001,
 * });
 * await server.start();
 * ```
 */
export class MCPProxyServer {
  private upstreamConnections: UpstreamConnection[] = [];
  private policyConfig?: PolicyConfig;
  private pipeline = new InterceptorPipeline();
  private auditLogger: AuditLogger = new AuditLogger();
  private approvalWorkflow?: ApprovalWorkflow;
  private approvalServer?: HttpServer;
  private httpServer?: HttpServer;
  private metricsServer?: HttpServer;
  private pendingResponses = new Map<number | string, (value: unknown) => void>();
  private messageId = 0;
  private logger = new Logger('MCPProxyServer');
  private schemaValidator?: SchemaValidator;
  private policyWatcher?: ReturnType<typeof watch>;
  private metrics: Metrics = {
    requestsTotal: 0,
    blocksTotal: 0,
    approvalsTotal: 0,
    errorsTotal: 0,
    upstreamLatencyMs: [],
    startTime: Date.now(),
  };

  constructor(private readonly options: ServerOptions) {}

  async start(): Promise<void> {
    this.policyConfig = loadPolicyConfig(this.options.policyPath);
    this.auditLogger = new AuditLogger({ config: this.policyConfig.audit });
    this.buildPipeline(this.policyConfig);
    this.startPolicyWatcher();
    this.startApprovalServer(this.policyConfig);
    await this.startUpstreams(this.policyConfig);
    this.startMetricsServer(this.policyConfig);
    this.startHttpTransport(this.policyConfig);
    this.startStdioListener();
  }

  async stop(): Promise<void> {
    for (const conn of this.upstreamConnections) {
      if (!conn.process.killed) {
        conn.process.kill('SIGTERM');
      }
    }
    this.approvalWorkflow?.stop();
    if (this.approvalServer) {
      await new Promise<void>((resolve) => this.approvalServer?.close(() => resolve()));
    }
    if (this.httpServer) {
      await new Promise<void>((resolve) => this.httpServer?.close(() => resolve()));
    }
    if (this.metricsServer) {
      await new Promise<void>((resolve) => this.metricsServer?.close(() => resolve()));
    }
    if (this.policyWatcher) {
      this.policyWatcher.close();
    }
  }

  getStats(): Record<string, unknown> {
    const latencies = this.metrics.upstreamLatencyMs;
    const avgLatency =
      latencies.length > 0 ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0;
    return {
      uptime: (Date.now() - this.metrics.startTime) / 1000,
      requestsTotal: this.metrics.requestsTotal,
      blocksTotal: this.metrics.blocksTotal,
      approvalsTotal: this.metrics.approvalsTotal,
      errorsTotal: this.metrics.errorsTotal,
      averageLatencyMs: Math.round(avgLatency),
      upstreamsConnected: this.upstreamConnections.filter((c) => !c.process.killed).length,
    };
  }

  private reloadPolicy(): void {
    if (!this.options.policyPath) return;
    try {
      this.policyConfig = loadPolicyConfig(this.options.policyPath);
      this.pipeline = new InterceptorPipeline();
      this.buildPipeline(this.policyConfig);
      this.logger.info('Policy hot-reloaded');
    } catch (error) {
      this.logger.error('Failed to reload policy', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  private startPolicyWatcher(): void {
    try {
      this.policyWatcher = watch(this.options.policyPath, () => {
        this.reloadPolicy();
      });
      this.policyWatcher.unref();
    } catch {
      // watch not supported on this platform
    }
  }

  private buildPipeline(config: PolicyConfig): void {
    const isDryRun = config.settings?.dry_run ?? false;

    if (config.rate_limits) {
      this.pipeline.register(new RateLimiter(config.rate_limits));
    }
    if (config.cost) {
      this.pipeline.register(new CostTracker(config.cost));
    }

    if (config.secret_scan?.enabled) {
      this.pipeline.register(
        new SecretScanner({
          enabled: true,
          patterns: (config.secret_scan.patterns ?? undefined) as
            | Array<{ name: string; pattern: string; flags?: string }>
            | undefined,
        }),
      );
    }

    if (config.validation?.rules) {
      this.pipeline.register(new ArgumentValidator(config.validation.rules));
    }

    if (config.validation?.schema_validation?.enabled) {
      this.schemaValidator = new SchemaValidator({
        enabled: true,
        strict: config.validation.schema_validation.strict,
      });
      this.pipeline.register(this.schemaValidator);
    }

    const engine = new PolicyEngine(config);

    if (isDryRun) {
      this.pipeline.register({
        execute: async (ctx: RequestContext) => {
          const result = await engine.evaluate(ctx);
          const wouldBlock = result.action !== 'ALLOW';
          if (wouldBlock) {
            this.logger.info('DRY RUN: would block', {
              toolName: ctx.toolName,
              action: result.action,
              reason: result.reason,
            });
          }
          return { action: 'CONTINUE', metadata: { dryRun: true, wouldBlock } };
        },
      });
    } else {
      this.pipeline.register({
        execute: async (ctx: RequestContext) => {
          const result = await engine.evaluate(ctx);
          if (result.action === 'BLOCK') {
            return { action: 'BLOCK', reason: result.reason ?? 'Blocked by policy' };
          }
          if (result.action === 'APPROVAL_REQUIRED') {
            return { action: 'APPROVAL_REQUIRED', reason: result.reason ?? 'Approval required' };
          }
          return { action: 'CONTINUE' };
        },
      });
    }

    this.pipeline.register(
      new ReadOnlyCheck({
        enabled: config.settings?.read_only ?? false,
        exceptions: config.read_only_exceptions,
        bypassTokenEnv:
          config.emergency_override?.enabled === true
            ? config.emergency_override?.token_env
            : undefined,
      }),
    );

    if (config.anomaly_detection?.enabled) {
      this.pipeline.register(new AnomalyDetector(config.anomaly_detection));
    }

    if (config.approvals) {
      this.approvalWorkflow = new ApprovalWorkflow(
        config.approvals,
        this.buildApproverGroups(config),
      );
    }
  }

  private buildApproverGroups(config: PolicyConfig): Map<string, ApproverGroup> {
    const groups = new Map<string, ApproverGroup>();
    if (config.approvals?.approver_groups) {
      for (const [name, groupConfig] of Object.entries(config.approvals.approver_groups)) {
        const gc = groupConfig as ApproverGroupConfig;
        if (gc.type === 'slack') {
          groups.set(name, new SlackApprover(gc));
        } else if (gc.type === 'discord') {
          groups.set(name, new DiscordApprover(gc));
        }
      }
    }
    return groups;
  }

  private startMetricsServer(config: PolicyConfig): void {
    if (!config.metrics?.enabled) return;
    const port = config.metrics.port ?? 9090;
    const host = config.metrics.bind_host ?? '127.0.0.1';

    this.metricsServer = createServer((_req, res) => {
      const latencies = this.metrics.upstreamLatencyMs;
      const avgLat =
        latencies.length > 0 ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0;

      const body = [
        '# HELP firewall_requests_total Total tool call requests',
        '# TYPE firewall_requests_total counter',
        `firewall_requests_total ${this.metrics.requestsTotal}`,
        '# HELP firewall_blocks_total Total blocked requests',
        '# TYPE firewall_blocks_total counter',
        `firewall_blocks_total ${this.metrics.blocksTotal}`,
        '# HELP firewall_approvals_total Total approval requests',
        '# TYPE firewall_approvals_total counter',
        `firewall_approvals_total ${this.metrics.approvalsTotal}`,
        '# HELP firewall_errors_total Total internal errors',
        '# TYPE firewall_errors_total counter',
        `firewall_errors_total ${this.metrics.errorsTotal}`,
        '# HELP firewall_upstream_latency_ms Average upstream latency in ms',
        '# TYPE firewall_upstream_latency_ms gauge',
        `firewall_upstream_latency_ms ${avgLat}`,
        '# HELP firewall_uptime_seconds Process uptime',
        '# TYPE firewall_uptime_seconds gauge',
        `firewall_uptime_seconds ${(Date.now() - this.metrics.startTime) / 1000}`,
        '',
      ].join('\n');

      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(body);
    });

    this.metricsServer.listen(port, host, () => {
      this.logger.info(`Metrics server listening on ${host}:${port}`);
    });
  }

  private startHttpTransport(config: PolicyConfig): void {
    if (!config.transports?.http?.enabled) return;
    const port = config.transports.http.port ?? 3000;
    const host = config.transports.http.bind_host ?? '127.0.0.1';

    this.httpServer = createServer(async (req, res) => {
      if (req.method === 'POST') {
        let body = '';
        req.on('data', (chunk) => {
          body += chunk.toString();
        });
        req.on('end', async () => {
          try {
            const line = body.trim();
            const response = await this.processMessage(line);
            if (response) {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify(response));
            } else {
              res.writeHead(204);
              res.end();
            }
          } catch {
            res.writeHead(500);
            res.end(JSON.stringify({ error: 'Internal error' }));
          }
        });
      } else if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', ...this.getStats() }));
      } else {
        res.writeHead(405);
        res.end('Method Not Allowed');
      }
    });

    this.httpServer.listen(port, host, () => {
      this.logger.info(`HTTP transport listening on ${host}:${port}`);
    });
  }

  private startApprovalServer(config: PolicyConfig): void {
    if (!config.approvals || !this.options.approvalPort) {
      return;
    }
    if (!this.approvalWorkflow) {
      throw new Error('Approval workflow not initialized');
    }
    if (!config.approval_api) {
      throw new Error(
        'Approval API requires `approval_api.token_env` in the policy when --approval-port is set',
      );
    }
    const tokenEnv = config.approval_api.token_env;
    const apiKey = process.env[tokenEnv];
    if (!apiKey || apiKey.length === 0) {
      throw new Error(
        `Approval API token env var \`${tokenEnv}\` is not set; refusing to start unauthenticated`,
      );
    }
    const bindHost = config.approval_api.bind_host;
    const app = createApprovalApi(this.approvalWorkflow, apiKey, {
      getStats: () => this.getStats(),
    });
    this.approvalServer = app.listen(this.options.approvalPort, bindHost, () => {
      this.logger.info(`Approval API listening on ${bindHost}:${this.options.approvalPort}`);
    });
  }

  private async startUpstreams(config: PolicyConfig): Promise<void> {
    const backends = config.upstreams;

    if (backends && backends.length > 0) {
      for (const backend of backends) {
        const env = backend.env
          ? {
              ...process.env,
              ...Object.fromEntries(Object.entries(backend.env).map(([k, v]) => [k, String(v)])),
            }
          : process.env;
        const proc = spawn(backend.command, backend.args ?? [], {
          stdio: ['pipe', 'pipe', 'pipe'],
          env: env as Record<string, string>,
        });

        proc.on('error', (error) => {
          this.logger.error(`Upstream ${backend.name} spawn error`, { error: error.message });
        });

        proc.stderr?.on('data', (data) => {
          this.logger.error(`[${backend.name} stderr]`, { data: data.toString() });
        });

        proc.on('exit', (code) => {
          this.logger.error(`Upstream ${backend.name} exited with code ${code}`);
        });

        const stdout = proc.stdout;
        if (!stdout) return;
        const rl = createInterface({ input: stdout });
        rl.on('line', (line) => {
          this.handleUpstreamMessage(line, backend.name);
        });

        this.upstreamConnections.push({ process: proc, backend });
      }
      return;
    }

    if (this.options.upstreamCommand) {
      const proc = spawn(this.options.upstreamCommand, this.options.upstreamArgs ?? [], {
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      proc.on('error', (error) => {
        this.logger.error('Upstream spawn error', { error: error.message });
      });

      proc.stderr?.on('data', (data) => {
        this.logger.error('[upstream stderr]', { data: data.toString() });
      });

      proc.on('exit', (code) => {
        this.logger.error(`Upstream process exited with code ${code}`);
      });

      const stdout = proc.stdout;
      if (!stdout) return;
      const rl = createInterface({ input: stdout });
      rl.on('line', (line) => {
        this.handleUpstreamMessage(line);
      });

      this.upstreamConnections.push({
        process: proc,
        backend: {
          name: 'default',
          command: this.options.upstreamCommand,
          args: this.options.upstreamArgs,
        },
      });
    }
  }

  private getUpstreamForTool(toolName: string): UpstreamConnection | undefined {
    if (this.upstreamConnections.length <= 1) {
      return this.upstreamConnections[0];
    }

    for (const conn of this.upstreamConnections) {
      const patterns = conn.backend.tool_patterns;
      if (patterns && patterns.length > 0) {
        for (const pattern of patterns) {
          if (
            pattern === toolName ||
            (pattern.includes('*') && this.globMatch(pattern, toolName))
          ) {
            return conn;
          }
        }
      }
    }

    return this.upstreamConnections.find(
      (c) => !c.backend.tool_patterns || c.backend.tool_patterns.length === 0,
    );
  }

  private globMatch(pattern: string, value: string): boolean {
    const regexStr = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    try {
      return new RegExp(`^${regexStr}$`).test(value);
    } catch {
      return pattern === value;
    }
  }

  private startStdioListener(): void {
    createInterface({ input: process.stdin }).on('line', (line) => {
      this.handleDownstreamMessage(line).catch((error) => {
        this.logger.error('Unhandled downstream error', {
          error: error instanceof Error ? error.message : String(error),
        });
      });
    });
  }

  private handleUpstreamMessage(line: string, _upstreamName?: string): void {
    let rawMessage: unknown;
    try {
      rawMessage = JSON.parse(line);
    } catch {
      this.logger.error('Failed to parse upstream message');
      return;
    }

    const parseResult = jsonRpcMessageSchema.safeParse(rawMessage);
    if (!parseResult.success) {
      this.logger.error('Invalid upstream JSON-RPC message');
      return;
    }
    const message = parseResult.data;
    const id = message.id;

    if (id !== undefined && id !== null && this.pendingResponses.has(id)) {
      const resolve = this.pendingResponses.get(id);
      this.pendingResponses.delete(id);
      if (resolve) {
        resolve(message);
      }
    } else if (message.result && message.id === undefined) {
      if (
        message.result &&
        typeof message.result === 'object' &&
        (message.result as Record<string, unknown>).tools
      ) {
        const tools = (message.result as Record<string, unknown>).tools;
        if (Array.isArray(tools) && this.schemaValidator) {
          this.schemaValidator.updateSchemas(
            tools as Array<{ name: string; description?: string; inputSchema: unknown }>,
          );
        }
      }
      this.sendToAgent(message);
    } else {
      this.sendToAgent(message);
    }
  }

  private async handleDownstreamMessage(line: string): Promise<void> {
    const response = await this.processMessage(line);
    if (response) {
      this.sendToAgent(response);
    }
  }

  private processMessage(line: string): Promise<unknown | null> {
    return new Promise((resolve) => {
      if (Buffer.byteLength(line, 'utf8') > MAX_MESSAGE_SIZE_BYTES) {
        this.sendErrorResponse(null, -32700, 'Message too large');
        resolve(null);
        return;
      }

      let rawMessage: unknown;
      try {
        rawMessage = JSON.parse(line);
      } catch {
        this.sendErrorResponse(null, -32700, 'Parse error');
        resolve(null);
        return;
      }

      const parseResult = jsonRpcMessageSchema.safeParse(rawMessage);
      if (!parseResult.success) {
        this.sendErrorResponse(null, -32600, 'Invalid Request');
        resolve(null);
        return;
      }
      const message = parseResult.data;
      const method = message.method;
      const id = message.id;

      if (method !== 'tools/call') {
        this.forwardToUpstream(line);
        resolve(null);
        return;
      }

      const params = message.params ?? {};
      const toolName = String(params.name ?? '');
      const rawSessionId =
        params._meta && typeof params._meta === 'object' && params._meta !== null
          ? String((params._meta as Record<string, unknown>).sessionId ?? 'default')
          : 'default';

      const sessionId =
        rawSessionId.length > MAX_SESSION_ID_LENGTH
          ? rawSessionId.slice(0, MAX_SESSION_ID_LENGTH)
          : rawSessionId;

      const context = createRequestContext({
        requestId: this.generateRequestId(),
        sessionId,
        method: 'tools/call',
        toolName,
        arguments: (params.arguments as Record<string, unknown>) ?? {},
      });

      if (params._meta && typeof params._meta === 'object' && params._meta !== null) {
        const meta = params._meta as Record<string, unknown>;
        if (meta.bypass_token) {
          context.metadata.set('bypass_token', meta.bypass_token);
        }
      }

      const startTime = Date.now();
      this.metrics.requestsTotal++;

      this.pipeline
        .process(context)
        .then(async (result) => {
          if (!result.allowed) {
            if (result.action === 'APPROVAL_REQUIRED' && this.approvalWorkflow) {
              const approvalId = await this.approvalWorkflow.requestApproval(context);
              this.metrics.approvalsTotal++;
              await this.auditLogger.log({
                type: 'APPROVAL_REQUESTED',
                sessionId: context.sessionId,
                toolName: context.toolName,
                arguments: redact(context.arguments) as Record<string, unknown> | undefined,
                decision: 'APPROVAL_REQUIRED',
                approvalId,
                latency: Date.now() - startTime,
                metadata: redact(result.metadata) as Record<string, unknown> | undefined,
              });
              this.metrics.upstreamLatencyMs.push(Date.now() - startTime);
              this.sendErrorResponse(id, -32000, result.reason ?? 'Approval required', {
                request_id: context.requestId,
                approval_id: approvalId,
              });
              resolve(null);
              return;
            }

            this.metrics.blocksTotal++;
            await this.auditLogger.log({
              type: 'REQUEST_BLOCKED',
              sessionId: context.sessionId,
              toolName: context.toolName,
              arguments: redact(context.arguments) as Record<string, unknown> | undefined,
              decision: 'BLOCK',
              blockedBy: result.reason,
              latency: Date.now() - startTime,
              metadata: redact(result.metadata) as Record<string, unknown> | undefined,
            });

            this.metrics.upstreamLatencyMs.push(Date.now() - startTime);
            this.sendErrorResponse(id, -32000, result.reason ?? 'Blocked by policy');
            resolve(null);
            return;
          }

          const upstream = this.getUpstreamForTool(context.toolName ?? '');
          if (!upstream) {
            this.sendErrorResponse(id, -32000, 'No upstream configured for this tool');
            resolve(null);
            return;
          }

          const upstreamResponse = await this.forwardToUpstreamAndWait(line, id, upstream.process);

          await this.auditLogger.log({
            type: 'REQUEST_ALLOWED',
            sessionId: context.sessionId,
            toolName: context.toolName,
            arguments: redact(context.arguments) as Record<string, unknown> | undefined,
            response: redact(upstreamResponse),
            decision: 'ALLOW',
            latency: Date.now() - startTime,
            metadata: redact(result.metadata) as Record<string, unknown> | undefined,
          });

          this.metrics.upstreamLatencyMs.push(Date.now() - startTime);
          if (this.policyConfig) {
            const engine = new PolicyEngine(this.policyConfig);
            engine.recordSafeCall(context);
          }

          resolve(upstreamResponse);
        })
        .catch(async (error) => {
          const fwError =
            error instanceof FirewallError
              ? error
              : new FirewallError({
                  code: 'INTERNAL_ERROR',
                  message: error instanceof Error ? error.message : 'Internal error',
                  requestId: context.requestId,
                });

          const isApproval = fwError instanceof ApprovalRequiredError;
          this.metrics.errorsTotal++;
          await this.auditLogger.log({
            type: isApproval ? 'APPROVAL_REQUESTED' : 'ERROR',
            sessionId: context.sessionId,
            toolName: context.toolName,
            arguments: redact(context.arguments) as Record<string, unknown> | undefined,
            decision: isApproval ? 'APPROVAL_REQUIRED' : 'BLOCK',
            approvalId: isApproval ? fwError.approvalId : undefined,
            latency: Date.now() - startTime,
            metadata: { error: fwError.message, code: fwError.code },
          });

          const errorData: Record<string, unknown> = { request_id: context.requestId };
          if (fwError instanceof RateLimitError) {
            errorData.retry_after_ms = fwError.retryAfterMs;
          }
          if (isApproval) {
            errorData.approval_id = fwError.approvalId;
          }

          this.metrics.upstreamLatencyMs.push(Date.now() - startTime);
          this.sendErrorResponse(id, -32000, fwError.message, errorData);
          resolve(null);
        });
    });
  }

  private forwardToUpstream(line: string): void {
    for (const conn of this.upstreamConnections) {
      if (!conn.process?.stdin) continue;
      try {
        conn.process.stdin.write(`${line}\n`);
      } catch {
        // ignore write errors
      }
    }
  }

  private forwardToUpstreamAndWait(
    line: string,
    originalId: number | string | null | undefined,
    upstreamProcess: ChildProcess,
  ): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (this.pendingResponses.size >= MAX_PENDING_RESPONSES) {
        reject(new Error('Too many pending requests'));
        return;
      }

      const id = ++this.messageId;
      const timeout = setTimeout(() => {
        this.pendingResponses.delete(id);
        reject(new Error('Upstream timeout'));
      }, 30000);

      let originalMsg: Record<string, unknown>;
      try {
        originalMsg = JSON.parse(line);
      } catch {
        clearTimeout(timeout);
        reject(new Error('Invalid JSON'));
        return;
      }
      const msg = { ...originalMsg, id };

      this.pendingResponses.set(id, (value: unknown) => {
        clearTimeout(timeout);
        if (value && typeof value === 'object') {
          (value as Record<string, unknown>).id = originalId ?? null;
        }
        resolve(value);
      });

      try {
        upstreamProcess.stdin?.write(`${JSON.stringify(msg)}\n`);
      } catch (error) {
        clearTimeout(timeout);
        this.pendingResponses.delete(id);
        reject(
          new Error(
            `Failed to forward request: ${error instanceof Error ? error.message : String(error)}`,
          ),
        );
      }
    });
  }

  private sendToAgent(message: unknown): void {
    try {
      process.stdout.write(`${JSON.stringify(message)}\n`);
    } catch (error) {
      this.logger.error('Failed to write to agent stdout', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  private sendErrorResponse(
    id: number | string | null | undefined,
    code: number,
    message: string,
    data?: Record<string, unknown>,
  ): void {
    const response = {
      jsonrpc: '2.0',
      id: id ?? null,
      error: { code, message, data },
    };
    this.sendToAgent(response);
  }

  private generateRequestId(): string {
    return `req_${randomUUID()}`;
  }
}
