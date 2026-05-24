import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { type AuditEvent, AuditLogger } from './index.js';

const event: AuditEvent = {
  type: 'REQUEST_BLOCKED',
  sessionId: 'sess_1',
  toolName: 'db_query',
  decision: 'BLOCK',
  latency: 12,
};

describe('AuditLogger', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('creates without throwing', () => {
    const logger = new AuditLogger({ silent: true });
    expect(logger).toBeInstanceOf(AuditLogger);
  });

  it('throws when a sidecar output has neither endpoint nor path', () => {
    expect(
      () =>
        new AuditLogger({
          silent: true,
          config: { level: 'full', output: [{ type: 'sidecar', format: 'json' }] },
        }),
    ).toThrow(/endpoint/);
  });

  it('forwards events to the sidecar endpoint as JSON', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal('fetch', fetchMock);

    const logger = new AuditLogger({
      silent: false,
      config: {
        level: 'full',
        output: [{ type: 'sidecar', format: 'json', endpoint: 'https://siem.example/ingest' }],
      },
    });

    await logger.log(event);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://siem.example/ingest');
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(init.headers.Authorization).toBeUndefined();
    expect(JSON.parse(init.body).type).toBe('REQUEST_BLOCKED');
  });

  it('attaches a Bearer token from api_key_env when set', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal('fetch', fetchMock);
    vi.stubEnv('TEST_SIEM_KEY', 'super-secret');

    const logger = new AuditLogger({
      silent: false,
      config: {
        level: 'full',
        output: [
          {
            type: 'sidecar',
            format: 'json',
            endpoint: 'https://siem.example/ingest',
            api_key_env: 'TEST_SIEM_KEY',
          },
        ],
      },
    });

    await logger.log(event);

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers.Authorization).toBe('Bearer super-secret');
  });

  it('does not throw when sidecar delivery fails', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('network down'));
    vi.stubGlobal('fetch', fetchMock);
    // The logger writes the failure to stderr; suppress it for a clean run.
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const logger = new AuditLogger({
      silent: false,
      config: {
        level: 'full',
        output: [{ type: 'sidecar', format: 'json', endpoint: 'https://siem.example/ingest' }],
      },
    });

    await expect(logger.log(event)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('does not forward when silent', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal('fetch', fetchMock);

    const logger = new AuditLogger({
      silent: true,
      config: {
        level: 'full',
        output: [{ type: 'sidecar', format: 'json', endpoint: 'https://siem.example/ingest' }],
      },
    });

    await logger.log(event);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('writes events to a sidecar file path (local fallback)', async () => {
    const path = join(mkdtempSync(join(tmpdir(), 'tuf-audit-')), 'sidecar.log');
    const logger = new AuditLogger({
      silent: false,
      config: { level: 'full', output: [{ type: 'sidecar', format: 'json', path }] },
    });

    await logger.log(event);

    const content = await waitForFile(path);
    expect(JSON.parse(content.trim()).type).toBe('REQUEST_BLOCKED');
  });

  it('supports a sidecar with both an endpoint and a path', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal('fetch', fetchMock);
    const path = join(mkdtempSync(join(tmpdir(), 'tuf-audit-')), 'sidecar.log');

    const logger = new AuditLogger({
      silent: false,
      config: {
        level: 'full',
        output: [
          { type: 'sidecar', format: 'json', endpoint: 'https://siem.example/ingest', path },
        ],
      },
    });

    await logger.log(event);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const content = await waitForFile(path);
    expect(JSON.parse(content.trim()).type).toBe('REQUEST_BLOCKED');
  });

  it('throws when output type is stdout', () => {
    expect(
      () =>
        new AuditLogger({
          silent: true,
          config: { level: 'full', output: [{ type: 'stdout', format: 'json' }] },
        }),
    ).toThrow(/stdout.*not allowed/);
  });

  it('throws when file output has no path', () => {
    expect(
      () =>
        new AuditLogger({
          silent: true,
          config: { level: 'full', output: [{ type: 'file', format: 'json' }] },
        }),
    ).toThrow(/requires a `path`/);
  });

  it('writes events to a file output', async () => {
    const path = join(mkdtempSync(join(tmpdir(), 'tuf-audit-')), 'audit.log');
    const logger = new AuditLogger({
      silent: false,
      config: { level: 'full', output: [{ type: 'file', format: 'json', path }] },
    });

    await logger.log(event);

    const content = await waitForFile(path);
    expect(JSON.parse(content.trim()).type).toBe('REQUEST_BLOCKED');
  });

  it('close() flushes and closes file sinks', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'tuf-audit-')), 'audit.log');
    const logger = new AuditLogger({
      silent: false,
      config: { level: 'full', output: [{ type: 'file', format: 'json', path }] },
    });
    expect(() => logger.close()).not.toThrow();
  });

  it('logs error when sidecar returns non-2xx response', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 500 });
    vi.stubGlobal('fetch', fetchMock);
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    const logger = new AuditLogger({
      silent: false,
      config: {
        level: 'full',
        output: [{ type: 'sidecar', format: 'json', endpoint: 'https://siem.example/ingest' }],
      },
    });

    await logger.log(event);
    await vi.waitFor(() => {
      expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('non-2xx'));
    });
  });

  it('applies custom redaction patterns', async () => {
    const path = join(mkdtempSync(join(tmpdir(), 'tuf-audit-')), 'audit.log');
    const logger = new AuditLogger({
      silent: false,
      config: {
        level: 'full',
        output: [{ type: 'file', format: 'json', path }],
        redaction: {
          enabled: true,
          patterns: [{ name: 'ssn', pattern: '\\d{3}-\\d{2}-\\d{4}', replacement: '[SSN]' }],
        },
      },
    });

    const ssnEvent: AuditEvent = {
      type: 'TEST',
      sessionId: 'sess_ssn',
      toolName: 'test',
      decision: 'ALLOW',
      latency: 0,
      arguments: { ssn: '123-45-6789' },
    };

    await logger.log(ssnEvent);

    const content = await waitForFile(path);
    expect(content).not.toContain('123-45-6789');
    expect(content).toContain('[SSN]');
  });

  it('emits slimmed events at summary level', async () => {
    const path = join(mkdtempSync(join(tmpdir(), 'tuf-audit-')), 'audit.log');
    const logger = new AuditLogger({
      silent: false,
      config: {
        level: 'summary',
        output: [{ type: 'file', format: 'json', path }],
      },
    });

    const fullEvent: AuditEvent = {
      type: 'TEST',
      sessionId: 'sess_sum',
      toolName: 'test',
      arguments: { secret: 'should-not-appear' },
      response: { data: 'should-not-appear' },
      decision: 'ALLOW',
      latency: 5,
    };

    await logger.log(fullEvent);

    const content = await waitForFile(path);
    const parsed = JSON.parse(content.trim());
    expect(parsed.type).toBe('TEST');
    expect(parsed.sessionId).toBe('sess_sum');
    expect(parsed.arguments).toBeUndefined();
    expect(parsed.response).toBeUndefined();
  });

  it('drops events at none level', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal('fetch', fetchMock);

    const logger = new AuditLogger({
      silent: false,
      config: {
        level: 'none',
        output: [{ type: 'sidecar', format: 'json', endpoint: 'https://siem.example/ingest' }],
      },
    });

    await logger.log(event);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('creates without options', () => {
    vi.stubEnv('NODE_ENV', 'test');
    const logger = new AuditLogger();
    expect(logger).toBeInstanceOf(AuditLogger);
  });

  it('handles non-Error sidecar failures', async () => {
    const fetchMock = vi.fn().mockRejectedValue('string error');
    vi.stubGlobal('fetch', fetchMock);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    const logger = new AuditLogger({
      silent: false,
      config: {
        level: 'full',
        output: [{ type: 'sidecar', format: 'json', endpoint: 'https://siem.example/ingest' }],
      },
    });

    await logger.log(event);
    await vi.waitFor(() => {
      expect(process.stderr.write).toHaveBeenCalledWith(
        expect.stringContaining('audit sidecar delivery failed'),
      );
    });
  });

  it('does not redact when redaction is disabled', async () => {
    const path = join(mkdtempSync(join(tmpdir(), 'tuf-audit-')), 'audit.log');
    const logger = new AuditLogger({
      silent: false,
      config: {
        level: 'full',
        output: [{ type: 'file', format: 'json', path }],
        redaction: { enabled: false },
      },
    });

    const sensitiveEvent: AuditEvent = {
      type: 'TEST',
      sessionId: 'sess_no_redact',
      toolName: 'test',
      decision: 'ALLOW',
      latency: 0,
      arguments: { api_key: 'should-not-be-redacted' },
    };

    await logger.log(sensitiveEvent);

    const content = await waitForFile(path);
    expect(content).toContain('api_key');
    expect(content).toContain('should-not-be-redacted');
    expect(content).not.toContain('[REDACTED]');
  });
});

/** Poll a file until it has content (the sidecar WriteStream flushes
 * asynchronously), failing the test if nothing is written in time. */
async function waitForFile(path: string, timeoutMs = 1000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const content = readFileSync(path, 'utf-8');
      if (content.length > 0) return content;
    } catch {
      // file not created yet
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`sidecar file ${path} was not written within ${timeoutMs}ms`);
}
