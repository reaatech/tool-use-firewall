import type { RequestContext, Middleware, InterceptorResponse } from '@reaatech/tool-use-firewall-core';

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
