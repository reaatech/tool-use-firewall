import { createRequestContext } from '@reaatech/tool-use-firewall-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WebhookApprover } from './webhook-approver.js';

function makeRequest() {
  return {
    id: 'appr_1',
    context: createRequestContext({
      requestId: '1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'test',
    }),
    status: 'PENDING' as const,
    createdAt: 0,
    expiresAt: 9999999999999,
    requiredApprovers: ['admin'],
    approvals: [],
    denials: [],
    minApprovals: 1,
  };
}

describe('WebhookApprover', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('handles notify without throwing (fetch rejection)', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'));
    const approver = new WebhookApprover({ url: 'http://example.com/approve' });
    await expect(approver.notify(makeRequest())).resolves.toBeUndefined();
  });

  it('happy path: fetch returns ok', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 200 }));
    const approver = new WebhookApprover({ url: 'http://example.com/approve' });
    await expect(approver.notify(makeRequest())).resolves.toBeUndefined();
  });

  it('non-ok response does not throw', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 500 }));
    const approver = new WebhookApprover({ url: 'http://example.com/approve' });
    await expect(approver.notify(makeRequest())).resolves.toBeUndefined();
  });

  it('sets Authorization header when api_key_env is provided', async () => {
    process.env.TEST_API_KEY = 'my-secret-key';
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(null, { status: 200 }));
    const approver = new WebhookApprover({
      url: 'http://example.com/approve',
      api_key_env: 'TEST_API_KEY',
    });
    await approver.notify(makeRequest());
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer my-secret-key',
        }),
      }),
    );
    delete process.env.TEST_API_KEY;
  });

  it('does not set Authorization header without api_key_env', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(null, { status: 200 }));
    const approver = new WebhookApprover({ url: 'http://example.com/approve' });
    await approver.notify(makeRequest());
    const callArgs = fetchSpy.mock.calls[0][1] as RequestInit;
    const headers = callArgs.headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
  });

  it('handles api_key_env when env var is not set', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(null, { status: 200 }));
    const approver = new WebhookApprover({
      url: 'http://example.com/approve',
      api_key_env: 'NONEXISTENT_KEY',
    });
    await approver.notify(makeRequest());
    const callArgs = fetchSpy.mock.calls[0][1] as RequestInit;
    const headers = callArgs.headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
  });

  it('handles non-Error rejection gracefully', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue('string error');
    const approver = new WebhookApprover({ url: 'http://example.com/approve' });
    await expect(approver.notify(makeRequest())).resolves.toBeUndefined();
  });
});
