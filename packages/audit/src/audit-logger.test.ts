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

  it('throws when a sidecar output has no endpoint', () => {
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
});
