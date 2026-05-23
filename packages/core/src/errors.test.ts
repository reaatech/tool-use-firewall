import { describe, it, expect } from 'vitest';
import {
  FirewallError,
  PolicyViolationError,
  RateLimitError,
  ValidationError,
  BudgetExceededError,
  ApprovalRequiredError,
} from './errors.js';

describe('FirewallError', () => {
  it('creates error with code and message', () => {
    const err = new FirewallError({ code: 'TEST', message: 'test error' });
    expect(err.code).toBe('TEST');
    expect(err.message).toBe('test error');
    expect(err.name).toBe('FirewallError');
  });

  it('serializes to JSON', () => {
    const err = new FirewallError({ code: 'TEST', message: 'test error', requestId: 'req_123' });
    const json = err.toJSON();
    expect(json).toEqual({
      error: { code: 'TEST', message: 'test error', request_id: 'req_123' },
    });
  });
});

describe('PolicyViolationError', () => {
  it('extends FirewallError with POLICY_VIOLATION code', () => {
    const err = new PolicyViolationError({ message: 'Blocked by policy', requestId: 'req_1' });
    expect(err.code).toBe('POLICY_VIOLATION');
    expect(err).toBeInstanceOf(FirewallError);
  });
});

describe('RateLimitError', () => {
  it('includes retryAfterMs in JSON', () => {
    const err = new RateLimitError({ message: 'Too fast', requestId: 'req_1', retryAfterMs: 5000 });
    const json = err.toJSON();
    expect((json.error as Record<string, unknown>).retry_after_ms).toBe(5000);
  });
});

describe('ValidationError', () => {
  it('has VALIDATION_ERROR code', () => {
    const err = new ValidationError({ message: 'Invalid input', requestId: 'req_1' });
    expect(err.code).toBe('VALIDATION_ERROR');
  });
});

describe('BudgetExceededError', () => {
  it('has BUDGET_EXCEEDED code', () => {
    const err = new BudgetExceededError({ message: 'No budget', requestId: 'req_1' });
    expect(err.code).toBe('BUDGET_EXCEEDED');
  });
});

describe('ApprovalRequiredError', () => {
  it('stores approvalId', () => {
    const err = new ApprovalRequiredError({ message: 'Needs approval', requestId: 'req_1', approvalId: 'appr_123' });
    expect(err.approvalId).toBe('appr_123');
    expect(err.code).toBe('APPROVAL_REQUIRED');
  });
});
