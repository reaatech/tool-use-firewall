export interface RequestContext {
  readonly requestId: string;
  readonly sessionId: string;
  readonly agentId?: string;
  readonly method: string;
  readonly toolName?: string;
  readonly arguments?: Record<string, unknown>;
  readonly resourceUri?: string;
  readonly receivedAt: number;
  readonly metadata: Map<string, unknown>;
}

export function createRequestContext(params: {
  requestId: string;
  sessionId: string;
  agentId?: string;
  method: string;
  toolName?: string;
  arguments?: Record<string, unknown>;
  resourceUri?: string;
}): RequestContext {
  return {
    ...params,
    receivedAt: Date.now(),
    metadata: new Map(),
  };
}

export type MiddlewareAction = 'CONTINUE' | 'BLOCK' | 'APPROVAL_REQUIRED';

export interface MiddlewareResult {
  action: MiddlewareAction;
  reason?: string;
  metadata?: Record<string, unknown>;
}

export interface Middleware {
  execute(context: RequestContext): Promise<MiddlewareResult>;
}

export interface InterceptorResponse {
  allowed: boolean;
  action: MiddlewareAction;
  reason?: string;
  metadata?: Record<string, unknown>;
}
