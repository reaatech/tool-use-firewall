import type { RequestContext } from './context.js';

/**
 * Possible actions a middleware can return.
 */
export type MiddlewareAction = 'CONTINUE' | 'BLOCK' | 'APPROVAL_REQUIRED';

/**
 * Result from executing a middleware.
 */
export interface MiddlewareResult {
  action: MiddlewareAction;
  reason?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Middleware interface for the interceptor pipeline.
 */
export interface Middleware {
  execute(context: RequestContext): Promise<MiddlewareResult>;
}

/**
 * Response returned when a request is blocked or requires approval.
 */
export interface InterceptorResponse {
  allowed: boolean;
  action: MiddlewareAction;
  reason?: string;
  metadata?: Record<string, unknown>;
}

/**
 * The interceptor pipeline executes a series of middlewares in order.
 * Each middleware can allow the request to continue, block it, or require approval.
 */
export class InterceptorPipeline {
  private middlewares: Middleware[] = [];

  register(middleware: Middleware): void {
    this.middlewares.push(middleware);
  }

  async process(context: RequestContext): Promise<InterceptorResponse> {
    const accumulated: Record<string, unknown> = {};
    for (const middleware of this.middlewares) {
      const result = await middleware.execute(context);
      if (result.metadata) {
        Object.assign(accumulated, result.metadata);
      }
      if (result.action === 'BLOCK') {
        return {
          allowed: false,
          action: 'BLOCK',
          reason: result.reason,
          metadata: { ...accumulated },
        };
      }
      if (result.action === 'APPROVAL_REQUIRED') {
        return {
          allowed: false,
          action: 'APPROVAL_REQUIRED',
          reason: result.reason,
          metadata: { ...accumulated },
        };
      }
    }

    return {
      allowed: true,
      action: 'CONTINUE',
      metadata: Object.keys(accumulated).length > 0 ? accumulated : undefined,
    };
  }
}
