/**
 * RequestContext encapsulates all information about an incoming MCP request
 * as it flows through the interceptor pipeline.
 */

export interface RequestContext {
  /** Unique identifier for this specific request */
  readonly requestId: string;

  /** Agent session identifier */
  readonly sessionId: string;

  /** Optional agent identifier */
  readonly agentId?: string;

  /** MCP method name, e.g. "tools/call", "tools/list" */
  readonly method: string;

  /** Tool name, present for tools/call */
  readonly toolName?: string;

  /** Tool arguments, present for tools/call */
  readonly arguments?: Record<string, unknown>;

  /** Resource URI, present for resources/read */
  readonly resourceUri?: string;

  /** Timestamp (ms) when the request was received */
  readonly receivedAt: number;

  /** Mutable metadata storage for middleware communication */
  readonly metadata: Map<string, unknown>;
}

/**
 * Create a new RequestContext from raw MCP request parameters.
 */
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
