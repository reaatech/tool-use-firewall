import { describe, it, expect } from 'vitest';
import {
  FirewallError,
  PolicyViolationError,
  RateLimitError,
  ValidationError,
  BudgetExceededError,
  ApprovalRequiredError,
} from '../../src/utils/errors.js';

describe('FirewallError', () => {
  it('should create error with code and message', () => {
    const error = new FirewallError({
      code: 'TEST_ERROR',
      message: 'Something went wrong',
    });

    expect(error.code).toBe('TEST_ERROR');
    expect(error.message).toBe('Something went wrong');
    expect(error.name).toBe('FirewallError');
  });

  it('should include requestId and details', () => {
    const error = new FirewallError({
      code: 'TEST_ERROR',
      message: 'Fail',
      requestId: 'req_123',
      details: { key: 'value' },
    });

    expect(error.requestId).toBe('req_123');
    expect(error.details).toEqual({ key: 'value' });
  });

  it('should serialize to JSON', () => {
    const error = new FirewallError({
      code: 'TEST_ERROR',
      message: 'Fail',
      requestId: 'req_123',
    });

    expect(error.toJSON()).toEqual({
      error: {
        code: 'TEST_ERROR',
        message: 'Fail',
        request_id: 'req_123',
      },
    });
  });
});

describe('RateLimitError', () => {
  it('should include retryAfterMs in JSON', () => {
    const error = new RateLimitError({
      message: 'Too many requests',
      retryAfterMs: 5000,
    });

    expect(error.retryAfterMs).toBe(5000);
    expect(error.toJSON()).toEqual({
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests',
        retry_after_ms: 5000,
      },
    });
  });
});

describe('ApprovalRequiredError', () => {
  it('should include approvalId', () => {
    const error = new ApprovalRequiredError({
      message: 'Needs approval',
      approvalId: 'appr_123',
    });

    expect(error.approvalId).toBe('appr_123');
    expect(error.code).toBe('APPROVAL_REQUIRED');
  });
});

describe('Specialized errors', () => {
  it('PolicyViolationError has correct code', () => {
    const error = new PolicyViolationError({ message: 'Blocked' });
    expect(error.code).toBe('POLICY_VIOLATION');
  });

  it('ValidationError has correct code', () => {
    const error = new ValidationError({ message: 'Invalid' });
    expect(error.code).toBe('VALIDATION_ERROR');
  });

  it('BudgetExceededError has correct code', () => {
    const error = new BudgetExceededError({ message: 'Over budget' });
    expect(error.code).toBe('BUDGET_EXCEEDED');
  });
});
