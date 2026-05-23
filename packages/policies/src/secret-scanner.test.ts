import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { describe, expect, it } from 'vitest';
import { SecretScanner } from './secret-scanner.js';

describe('SecretScanner', () => {
  it('passes when disabled', async () => {
    const s = new SecretScanner({ enabled: false });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { token: 'sk-abc123def456ghi789jkl012mno345pqr678stu' },
    });
    const result = await s.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.secretsDetected).toBeUndefined();
  });

  it('detects OpenAI keys', async () => {
    const s = new SecretScanner({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { token: 'sk-abc123def456ghi789jkl012mno345pqr678stu' },
    });
    const result = await s.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.secretsDetected).toBe(true);
  });

  it('passes clean arguments', async () => {
    const s = new SecretScanner({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { name: 'hello', count: 42 },
    });
    const result = await s.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.secretsDetected).toBeUndefined();
  });
});
