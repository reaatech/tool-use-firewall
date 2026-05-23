import { timingSafeEqual } from 'node:crypto';
import type { ExceptionCondition } from '@reaatech/tool-use-firewall-config';
import type {
  Middleware,
  MiddlewareResult,
  RequestContext,
} from '@reaatech/tool-use-firewall-core';
import { PolicyViolationError, safeRegExp } from '@reaatech/tool-use-firewall-core';

interface ReadOnlyException {
  tools?: string[];
  conditions: ExceptionCondition[];
}

export class ReadOnlyCheck implements Middleware {
  private readonly enabled: boolean;
  private readonly exceptions: ReadOnlyException[];
  private readonly bypassToken?: string;

  constructor(config: {
    enabled: boolean;
    exceptions?: ReadOnlyException[];
    bypassTokenEnv?: string;
  }) {
    this.enabled = config.enabled;
    this.exceptions = config.exceptions ?? [];
    if (config.bypassTokenEnv) {
      this.bypassToken = process.env[config.bypassTokenEnv];
    }
  }

  async execute(context: RequestContext): Promise<MiddlewareResult> {
    if (!this.enabled) {
      return { action: 'CONTINUE' };
    }

    if (!context.toolName || !context.arguments) {
      return { action: 'CONTINUE' };
    }

    if (this.hasBypassToken(context)) {
      return { action: 'CONTINUE', metadata: { readOnlyBypassed: true } };
    }

    if (this.isException(context)) {
      return { action: 'CONTINUE' };
    }

    const isWrite = this.detectWriteOperation(context.toolName, context.arguments);
    if (isWrite) {
      throw new PolicyViolationError({
        message: 'Write operation blocked in read-only mode',
        requestId: context.requestId,
        details: { toolName: context.toolName, readOnly: true },
      });
    }

    return { action: 'CONTINUE' };
  }

  private hasBypassToken(context: RequestContext): boolean {
    if (!this.bypassToken) return false;
    const token = context.metadata.get('bypass_token');
    if (typeof token !== 'string') return false;

    try {
      const expected = Buffer.from(this.bypassToken, 'utf8');
      const actual = Buffer.from(token, 'utf8');
      if (expected.length !== actual.length) return false;
      return timingSafeEqual(expected, actual);
    } catch {
      return false;
    }
  }

  private isException(context: RequestContext): boolean {
    for (const exception of this.exceptions) {
      if (exception.tools && !exception.tools.includes(context.toolName ?? '')) {
        continue;
      }
      let allMatch = true;
      for (const condition of exception.conditions) {
        const value = context.arguments?.[condition.argument];
        if (typeof value !== 'string') {
          allMatch = false;
          break;
        }
        try {
          const regex = safeRegExp(condition.pattern, condition.flags ?? '');
          if (!regex.test(value)) {
            allMatch = false;
            break;
          }
        } catch {
          allMatch = false;
          break;
        }
      }
      if (allMatch) return true;
    }
    return false;
  }

  private detectWriteOperation(toolName: string, args: Record<string, unknown>): boolean {
    const writeTools = ['write', 'create', 'delete', 'update', 'insert', 'drop'];
    const normalized = toolName.toLowerCase();
    if (writeTools.some((w) => normalized.includes(w))) {
      return true;
    }

    const query = args.query;
    if (typeof query === 'string') {
      try {
        return safeRegExp('^(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE)\\s', 'i').test(
          query.trim(),
        );
      } catch {
        return true;
      }
    }

    return false;
  }
}
