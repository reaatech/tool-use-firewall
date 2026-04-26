import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CLIApprover } from '../../src/approvals/cli-approver.js';
import { createRequestContext } from '../../src/middleware/context.js';

vi.mock('node:readline', () => {
  const actual = vi.importActual('node:readline');
  return {
    ...actual,
    createInterface: vi.fn(),
  };
});

import { createInterface } from 'node:readline';

describe('CLIApprover', () => {
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  it('should log notification to stderr', async () => {
    const approver = new CLIApprover();
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
    expect(stderrSpy).toHaveBeenCalled();
    const call = stderrSpy.mock.calls[0]?.[0] as string;
    expect(call).toContain('db_query');
  });

  it('should redact arguments in notification', async () => {
    const approver = new CLIApprover();
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
    const calls = stderrSpy.mock.calls.map((c) => c[0] as string).join('');
    expect(calls).toContain('[REDACTED]');
    expect(calls).not.toContain('secret123');
  });

  it('should use custom prompt', async () => {
    const approver = new CLIApprover({ prompt: 'Custom prompt' });
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
    const call = stderrSpy.mock.calls[0]?.[0] as string;
    expect(call).toContain('Custom prompt');
  });
});

describe('CLIApprover.prompt', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should approve when user answers yes', async () => {
    const mockRl = {
      question: vi.fn((_q: string, cb: (answer: string) => void) => {
        cb('y');
      }),
      close: vi.fn(),
    };
    vi.mocked(createInterface).mockReturnValue(mockRl as never);

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
    });
    const request = {
      id: 'appr_prompt_1',
      context: ctx,
      status: 'PENDING' as const,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300000,
      requiredApprovers: ['security'],
      approvals: [],
      denials: [],
      minApprovals: 1,
    };

    const result = await CLIApprover.prompt(request);
    expect(result.success).toBe(true);
    expect(result.status).toBe('APPROVED');
  });

  it('should approve when user answers yes (full word)', async () => {
    const mockRl = {
      question: vi.fn((_q: string, cb: (answer: string) => void) => {
        cb('  Yes  ');
      }),
      close: vi.fn(),
    };
    vi.mocked(createInterface).mockReturnValue(mockRl as never);

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
    });
    const request = {
      id: 'appr_prompt_2',
      context: ctx,
      status: 'PENDING' as const,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300000,
      requiredApprovers: ['security'],
      approvals: [],
      denials: [],
      minApprovals: 1,
    };

    const result = await CLIApprover.prompt(request);
    expect(result.success).toBe(true);
    expect(result.status).toBe('APPROVED');
  });

  it('should deny when user answers no', async () => {
    const mockRl = {
      question: vi.fn((_q: string, cb: (answer: string) => void) => {
        cb('n');
      }),
      close: vi.fn(),
    };
    vi.mocked(createInterface).mockReturnValue(mockRl as never);

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
    });
    const request = {
      id: 'appr_prompt_3',
      context: ctx,
      status: 'PENDING' as const,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300000,
      requiredApprovers: ['security'],
      approvals: [],
      denials: [],
      minApprovals: 1,
    };

    const result = await CLIApprover.prompt(request);
    expect(result.success).toBe(true);
    expect(result.status).toBe('DENIED');
  });

  it('should deny on unknown answer', async () => {
    const mockRl = {
      question: vi.fn((_q: string, cb: (answer: string) => void) => {
        cb('maybe');
      }),
      close: vi.fn(),
    };
    vi.mocked(createInterface).mockReturnValue(mockRl as never);

    const ctx = createRequestContext({
      requestId: 'r1',
      sessionId: 's1',
      method: 'tools/call',
      toolName: 'db_query',
    });
    const request = {
      id: 'appr_prompt_4',
      context: ctx,
      status: 'PENDING' as const,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300000,
      requiredApprovers: ['security'],
      approvals: [],
      denials: [],
      minApprovals: 1,
    };

    const result = await CLIApprover.prompt(request);
    expect(result.success).toBe(true);
    expect(result.status).toBe('DENIED');
    expect(result.reason).toBe('Denied by operator');
  });
});
