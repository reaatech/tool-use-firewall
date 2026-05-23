import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it } from 'vitest';
import { ArgumentValidator } from './validator.js';

describe('ArgumentValidator', () => {
  it('passes through when no rules match', async () => {
    const validator = new ArgumentValidator([]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { query: 'SELECT 1' },
    });
    const result = await validator.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('blocks shell dangerous sequences', async () => {
    const validator = new ArgumentValidator([
      { id: 'r1', type: 'shell_safe', tools: ['shell'], argument: 'cmd' },
    ]);
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'shell',
      arguments: { cmd: 'ls; rm -rf /' },
    });
    await expect(validator.execute(ctx)).rejects.toThrow('Contains dangerous shell sequence');
  });
});
