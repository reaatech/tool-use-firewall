import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AuditLogger } from '../../src/audit/index.js';

describe('AuditLogger', () => {
  let stderrSpy: ReturnType<typeof vi.spyOn>;
  const originalEnv = process.env.NODE_ENV;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
    process.env.NODE_ENV = originalEnv;
  });

  it('should log audit events to stderr', async () => {
    process.env.NODE_ENV = 'development';
    const logger = new AuditLogger();
    await logger.log({
      type: 'REQUEST_ALLOWED',
      sessionId: 's1',
      toolName: 'test_tool',
      arguments: { query: 'SELECT 1' },
      decision: 'ALLOW',
      latency: 10,
    });

    expect(stderrSpy).toHaveBeenCalled();
    const call = stderrSpy.mock.calls[0]?.[0] as string;
    expect(call).toContain('audit_event');
  });

  it('should not log in test environment', async () => {
    process.env.NODE_ENV = 'test';
    const logger = new AuditLogger();
    await logger.log({
      type: 'REQUEST_ALLOWED',
      sessionId: 's1',
      decision: 'ALLOW',
      latency: 10,
    });

    expect(stderrSpy).not.toHaveBeenCalled();
  });

  it('should redact sensitive data', async () => {
    process.env.NODE_ENV = 'development';
    const logger = new AuditLogger();
    await logger.log({
      type: 'REQUEST_ALLOWED',
      sessionId: 's1',
      arguments: { password: 'secret123' },
      decision: 'ALLOW',
      latency: 10,
    });

    const call = stderrSpy.mock.calls[0]?.[0] as string;
    expect(call).toContain('[REDACTED]');
    expect(call).not.toContain('secret123');
  });

  it('refuses to write audit events to stdout', () => {
    expect(
      () =>
        new AuditLogger({
          config: {
            level: 'full',
            output: [{ type: 'stdout', format: 'json' }],
          },
        }),
    ).toThrow(/stdout/);
  });

  it('honors level: none by emitting nothing', async () => {
    process.env.NODE_ENV = 'development';
    const logger = new AuditLogger({ config: { level: 'none' } });
    await logger.log({
      type: 'REQUEST_ALLOWED',
      sessionId: 's1',
      decision: 'ALLOW',
      latency: 10,
    });
    expect(stderrSpy).not.toHaveBeenCalled();
  });

  it('drops arguments/response when level is summary', async () => {
    process.env.NODE_ENV = 'development';
    const logger = new AuditLogger({ config: { level: 'summary' } });
    await logger.log({
      type: 'REQUEST_ALLOWED',
      sessionId: 's1',
      toolName: 'tool',
      arguments: { secret: 'oh-no' },
      response: { secret: 'also-oh-no' },
      decision: 'ALLOW',
      latency: 10,
    });
    const call = stderrSpy.mock.calls[0]?.[0] as string;
    expect(call).not.toContain('oh-no');
    expect(call).toContain('"toolName":"tool"');
  });

  it('skips redaction when disabled', async () => {
    process.env.NODE_ENV = 'development';
    const logger = new AuditLogger({
      config: { level: 'full', redaction: { enabled: false } },
    });
    await logger.log({
      type: 'REQUEST_ALLOWED',
      sessionId: 's1',
      arguments: { password: 'plaintext' },
      decision: 'ALLOW',
      latency: 10,
    });
    const call = stderrSpy.mock.calls[0]?.[0] as string;
    expect(call).toContain('plaintext');
  });
});
