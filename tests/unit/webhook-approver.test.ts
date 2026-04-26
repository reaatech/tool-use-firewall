import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { WebhookApprover } from '../../src/approvals/webhook-approver.js';
import { createRequestContext } from '../../src/middleware/context.js';

describe('WebhookApprover', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
    } as Response);
  });

  afterEach(() => {
    fetchSpy.mockRestore();
    delete process.env.TEST_WEBHOOK_KEY;
  });

  it('should send webhook notification', async () => {
    const approver = new WebhookApprover({ url: 'https://example.com/webhook' });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
      arguments: { query: 'SELECT 1' },
    });
    const request = {
      id: 'appr_1',
      context: ctx,
      status: 'PENDING' as const,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300000,
      requiredApprovers: ['security'],
      approvals: [],
      denials: [],
      minApprovals: 1,
    };

    await approver.notify(request);
    expect(fetchSpy).toHaveBeenCalled();
    const [, init] = fetchSpy.mock.calls[0] ?? [];
    expect(init?.method).toBe('POST');
  });

  it('should include Authorization header when api_key_env is set', async () => {
    process.env.TEST_WEBHOOK_KEY = 'secret-token';
    const approver = new WebhookApprover({
      url: 'https://example.com/webhook',
      api_key_env: 'TEST_WEBHOOK_KEY',
    });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
    });
    const request = {
      id: 'appr_1',
      context: ctx,
      status: 'PENDING' as const,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300000,
      requiredApprovers: ['security'],
      approvals: [],
      denials: [],
      minApprovals: 1,
    };

    await approver.notify(request);
    const [, init] = fetchSpy.mock.calls[0] ?? [];
    const headers = init?.headers as Record<string, string>;
    expect(headers['Authorization']).toBe('Bearer secret-token');
  });

  it('should redact arguments in webhook body', async () => {
    const approver = new WebhookApprover({ url: 'https://example.com/webhook' });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
      arguments: { password: 'secret123' },
    });
    const request = {
      id: 'appr_1',
      context: ctx,
      status: 'PENDING' as const,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300000,
      requiredApprovers: ['security'],
      approvals: [],
      denials: [],
      minApprovals: 1,
    };

    await approver.notify(request);
    const [, init] = fetchSpy.mock.calls[0] ?? [];
    const body = JSON.parse(init?.body as string);
    expect(JSON.stringify(body.arguments)).toContain('[REDACTED]');
  });

  it('should handle fetch failure gracefully', async () => {
    fetchSpy.mockRejectedValue(new Error('Network error'));
    const approver = new WebhookApprover({ url: 'https://example.com/webhook' });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
    });
    const request = {
      id: 'appr_1',
      context: ctx,
      status: 'PENDING' as const,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300000,
      requiredApprovers: ['security'],
      approvals: [],
      denials: [],
      minApprovals: 1,
    };

    // Should not throw
    await expect(approver.notify(request)).resolves.toBeUndefined();
  });

  it('should handle non-OK response gracefully', async () => {
    fetchSpy.mockResolvedValue({
      ok: false,
      status: 500,
    } as Response);
    const approver = new WebhookApprover({ url: 'https://example.com/webhook' });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
    });
    const request = {
      id: 'appr_1',
      context: ctx,
      status: 'PENDING' as const,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300000,
      requiredApprovers: ['security'],
      approvals: [],
      denials: [],
      minApprovals: 1,
    };

    await expect(approver.notify(request)).resolves.toBeUndefined();
  });

  it('should use AbortSignal timeout', async () => {
    const approver = new WebhookApprover({ url: 'https://example.com/webhook' });
    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
    });
    const request = {
      id: 'appr_1',
      context: ctx,
      status: 'PENDING' as const,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300000,
      requiredApprovers: ['security'],
      approvals: [],
      denials: [],
      minApprovals: 1,
    };

    await approver.notify(request);
    const [, init] = fetchSpy.mock.calls[0] ?? [];
    expect(init?.signal).toBeDefined();
  });
});
