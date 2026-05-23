import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createInterface } from 'node:readline';
import { z } from 'zod';
import type { Server as HttpServer } from 'node:http';
import {
  createRequestContext,
  type RequestContext,
  ApprovalRequiredError,
  FirewallError,
  RateLimitError,
  Logger,
  redact,
} from '@reaatech/tool-use-firewall-core';
import { loadPolicyConfig, type PolicyConfig } from '@reaatech/tool-use-firewall-config';
import {
  PolicyEngine,
  RateLimiter,
  CostTracker,
  ArgumentValidator,
  ReadOnlyCheck,
} from '@reaatech/tool-use-firewall-policies';
import { AuditLogger } from '@reaatech/tool-use-firewall-audit';
import { ApprovalWorkflow, createApprovalApi } from '@reaatech/tool-use-firewall-approvals';
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
  upstreamCommand: string;
  upstreamArgs?: string[];
  approvalPort?: number;
}

export class MCPProxyServer {
  private upstreamProcess?: ChildProcess;
  private policyConfig?: PolicyConfig;
  private pipeline = new InterceptorPipeline();
  private auditLogger: AuditLogger = new AuditLogger();
  private approvalWorkflow?: ApprovalWorkflow;
  private approvalServer?: HttpServer;
  private pendingResponses = new Map<number | string, (value: unknown) => void>();
  private messageId = 0;
  private logger = new Logger('MCPProxyServer');

  constructor(private readonly options: ServerOptions) {}

  async start(): Promise<void> {
    this.policyConfig = loadPolicyConfig(this.options.policyPath);
    this.auditLogger = new AuditLogger({ config: this.policyConfig.audit });
    this.buildPipeline(this.policyConfig);
    this.startApprovalServer(this.policyConfig);
    this.startUpstream();
    this.startStdioListener();
  }

  async stop(): Promise<void> {
    if (this.upstreamProcess && !this.upstreamProcess.killed) {
      const proc = this.upstreamProcess;
      proc.kill('SIGTERM');
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          if (!proc.killed) proc.kill('SIGKILL');
          resolve();
        }, 2000);
        proc.once('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    this.approvalWorkflow?.stop();
    if (this.approvalServer) {
      await new Promise<void>((resolve) => this.approvalServer?.close(() => resolve()));
    }
  }

  private buildPipeline(config: PolicyConfig): void {
    if (config.rate_limits) {
      this.pipeline.register(new RateLimiter(config.rate_limits));
    }
    if (config.cost) {
      this.pipeline.register(new CostTracker(config.cost));
    }
    if (config.validation?.rules) {
      this.pipeline.register(new ArgumentValidator(config.validation.rules));
    }

    const engine = new PolicyEngine(config);
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

    this.pipeline.register(
      new ReadOnlyCheck({
        enabled: config.settings?.read_only ?? false,
        exceptions: config.read_only_exceptions,
        bypassTokenEnv: config.emergency_override?.token_env,
      }),
    );

    if (config.approvals) {
      this.approvalWorkflow = new ApprovalWorkflow(config.approvals);
    }
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
    const app = createApprovalApi(this.approvalWorkflow, apiKey);
    this.approvalServer = app.listen(this.options.approvalPort, bindHost, () => {
      this.logger.info(`Approval API listening on ${bindHost}:${this.options.approvalPort}`);
    });
  }

  private startUpstream(): void {
    const proc = spawn(this.options.upstreamCommand, this.options.upstreamArgs ?? [], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.upstreamProcess = proc;

    proc.on('error', (error) => {
      this.logger.error('Upstream spawn error', { error: error.message });
    });

    const stdout = proc.stdout;
    if (stdout) {
      createInterface({ input: stdout }).on('line', (line) => {
        this.handleUpstreamMessage(line);
      });
    }

    proc.stderr?.on('data', (data) => {
      this.logger.error('[upstream stderr]', { data: data.toString() });
    });

    proc.on('exit', (code) => {
      this.logger.error(`Upstream process exited with code ${code}`);
    });
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

  private async handleDownstreamMessage(line: string): Promise<void> {
    if (Buffer.byteLength(line, 'utf8') > MAX_MESSAGE_SIZE_BYTES) {
      this.sendErrorResponse(null, -32700, 'Message too large');
      return;
    }

    let rawMessage: unknown;
    try {
      rawMessage = JSON.parse(line);
    } catch {
      this.sendErrorResponse(null, -32700, 'Parse error');
      return;
    }

    const parseResult = jsonRpcMessageSchema.safeParse(rawMessage);
    if (!parseResult.success) {
      this.sendErrorResponse(null, -32600, 'Invalid Request');
      return;
    }
    const message = parseResult.data;
    const method = message.method;
    const id = message.id;

    if (method !== 'tools/call') {
      this.forwardToUpstream(line);
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
    try {
      const result = await this.pipeline.process(context);

      if (!result.allowed) {
        if (result.action === 'APPROVAL_REQUIRED' && this.approvalWorkflow) {
          await this.approvalWorkflow.requestApproval(context);
        }

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

        this.sendErrorResponse(id, -32000, result.reason ?? 'Blocked by policy');
        return;
      }

      const upstreamResponse = await this.forwardToUpstreamAndWait(line, id);

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

      this.sendToAgent(upstreamResponse);
    } catch (error) {
      const fwError =
        error instanceof FirewallError
          ? error
          : new FirewallError({
              code: 'INTERNAL_ERROR',
              message: error instanceof Error ? error.message : 'Internal error',
              requestId: context.requestId,
            });

      const isApproval = fwError instanceof ApprovalRequiredError;
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

      this.sendErrorResponse(id, -32000, fwError.message, errorData);
    }
  }

  private handleUpstreamMessage(line: string): void {
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
    } else {
      this.sendToAgent(message);
    }
  }

  private forwardToUpstream(line: string): void {
    if (!this.upstreamProcess?.stdin) return;
    try {
      this.upstreamProcess.stdin.write(line + '\n');
    } catch (error) {
      this.logger.error('Failed to write to upstream stdin', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  private forwardToUpstreamAndWait(
    line: string,
    originalId: number | string | null | undefined,
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

      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(line);
      } catch {
        clearTimeout(timeout);
        reject(new Error('Invalid JSON'));
        return;
      }
      msg.id = id;
      const modifiedLine = JSON.stringify(msg);

      this.pendingResponses.set(id, (value: unknown) => {
        clearTimeout(timeout);
        if (value && typeof value === 'object') {
          (value as Record<string, unknown>).id = originalId ?? null;
        }
        resolve(value);
      });

      try {
        this.upstreamProcess?.stdin?.write(modifiedLine + '\n');
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
      process.stdout.write(JSON.stringify(message) + '\n');
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
