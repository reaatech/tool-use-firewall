import type {
  Middleware,
  MiddlewareResult,
  RequestContext,
} from '@reaatech/tool-use-firewall-core';
import { safeRegExp } from '@reaatech/tool-use-firewall-core';

interface SecretPattern {
  name: string;
  pattern: string;
  flags?: string;
}

const DEFAULT_SECRET_PATTERNS: SecretPattern[] = [
  { name: 'github-token', pattern: 'gh[pousr]_[A-Za-z0-9_]{36,}', flags: '' },
  { name: 'aws-access-key', pattern: 'AKIA[0-9A-Z]{16}', flags: '' },
  {
    name: 'jwt',
    pattern: 'eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}',
    flags: '',
  },
  { name: 'openai-key', pattern: 'sk-[A-Za-z0-9]{32,}', flags: '' },
  {
    name: 'private-key-header',
    pattern: '-----BEGIN\\s+(?:RSA|EC|DSA|OPENSSH)\\s+PRIVATE\\s+KEY-----',
    flags: '',
  },
  { name: 'google-api-key', pattern: 'AIza[0-9A-Za-z\\-_]{35}', flags: '' },
  { name: 'slack-token', pattern: 'xox[baprs]-[0-9A-Za-z\\-]{10,}', flags: '' },
];

export class SecretScanner implements Middleware {
  private readonly patterns: SecretPattern[];
  private readonly enabled: boolean;

  constructor(config?: { enabled?: boolean; patterns?: SecretPattern[] }) {
    this.enabled = config?.enabled ?? false;
    this.patterns = config?.patterns ?? DEFAULT_SECRET_PATTERNS;
  }

  async execute(context: RequestContext): Promise<MiddlewareResult> {
    if (!this.enabled || !context.arguments) {
      return { action: 'CONTINUE' };
    }

    const findings: string[] = [];
    for (const [key, value] of Object.entries(context.arguments)) {
      if (typeof value !== 'string') continue;
      for (const sp of this.patterns) {
        try {
          const regex = safeRegExp(sp.pattern, sp.flags ?? '');
          if (regex.test(value)) {
            findings.push(`${sp.name} detected in argument '${key}'`);
          }
        } catch {
          // skip unsafe patterns
        }
      }
    }

    if (findings.length > 0) {
      return {
        action: 'CONTINUE',
        metadata: {
          secretFindings: findings,
          secretsDetected: true,
        },
      };
    }

    return { action: 'CONTINUE' };
  }
}
