import { describe, it, expect } from 'vitest';
import { ReadOnlyCheck } from './read-only.js';
import { createRequestContext } from '@reaatech/tool-use-firewall-core';

describe('ReadOnlyCheck', () => {
  it('passes through when disabled', async () => {
    const check = new ReadOnlyCheck({ enabled: false });
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call' });
    const result = await check.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('blocks write operations', async () => {
    const check = new ReadOnlyCheck({ enabled: true });
    const ctx = createRequestContext({ requestId: '1', sessionId: 's1', method: 'tools/call', toolName: 'delete_record', arguments: {} });
    await expect(check.execute(ctx)).rejects.toThrow('Write operation blocked');
  });
});
