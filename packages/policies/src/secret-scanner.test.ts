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

  it('skips non-string argument values', async () => {
    const s = new SecretScanner({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { num: 123, obj: { x: 1 }, arr: [1, 2] },
    });
    const result = await s.execute(ctx);
    expect(result.action).toBe('CONTINUE');
    expect(result.metadata?.secretsDetected).toBeUndefined();
  });

  it('detects GitHub tokens', async () => {
    const s = new SecretScanner({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { token: 'ghp_abcdefghijklmnopqrstuvwxyz1234567890' },
    });
    const result = await s.execute(ctx);
    expect(result.metadata?.secretsDetected).toBe(true);
  });

  it('detects AWS access keys', async () => {
    const s = new SecretScanner({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { key: 'AKIA1234567890ABCDEF' },
    });
    const result = await s.execute(ctx);
    expect(result.metadata?.secretsDetected).toBe(true);
  });

  it('detects JWTs', async () => {
    const s = new SecretScanner({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqPnd9Iy' },
    });
    const result = await s.execute(ctx);
    expect(result.metadata?.secretsDetected).toBe(true);
  });

  it('detects private keys', async () => {
    const s = new SecretScanner({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { key: '-----BEGIN RSA PRIVATE KEY-----' },
    });
    const result = await s.execute(ctx);
    expect(result.metadata?.secretsDetected).toBe(true);
  });

  it('detects Google API keys', async () => {
    const s = new SecretScanner({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { key: 'AIzaSyD6d4h5g6sdf7g8h9j0k1l2m3n4o5p6q7r8s9t0' },
    });
    const result = await s.execute(ctx);
    expect(result.metadata?.secretsDetected).toBe(true);
  });

  it('detects Slack tokens', async () => {
    const s = new SecretScanner({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { token: 'xoxb-123456789012-123456789012-abc123def456' },
    });
    const result = await s.execute(ctx);
    expect(result.metadata?.secretsDetected).toBe(true);
  });

  it('handles regex compilation failure gracefully', async () => {
    const s = new SecretScanner({
      enabled: true,
      patterns: [
        { name: 'bad-pattern', pattern: '[invalid', flags: '' },
        { name: 'good-pattern', pattern: 'test', flags: '' },
      ],
    });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { value: 'test' },
    });
    const result = await s.execute(ctx);
    expect(result.metadata?.secretsDetected).toBe(true);
  });

  it('no arguments passes through', async () => {
    const s = new SecretScanner({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    });
    const result = await s.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('default patterns when config has no patterns', async () => {
    const s = new SecretScanner({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { token: 'ghp_abcdefghijklmnopqrstuvwxyz1234567890' },
    });
    const result = await s.execute(ctx);
    expect(result.metadata?.secretsDetected).toBe(true);
  });

  it('handles config being undefined', async () => {
    const s = new SecretScanner();
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { token: 'sk-abc123def456ghi789jkl012mno345pqr678stu' },
    });
    const result = await s.execute(ctx);
    expect(result.action).toBe('CONTINUE');
  });

  it('all arguments are strings and clean', async () => {
    const s = new SecretScanner({ enabled: true });
    const ctx = createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
      arguments: { name: 'hello', greeting: 'world', type: 'test' },
    });
    const result = await s.execute(ctx);
    expect(result.metadata?.secretsDetected).toBeUndefined();
  });
});
