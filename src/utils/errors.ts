/**
 * Custom error classes for tool-use-firewall.
 * All security-related errors include context without leaking internals.
 */

export interface ErrorDetails {
  [key: string]: unknown;
}

export class FirewallError extends Error {
  readonly code: string;
  readonly requestId?: string;
  readonly details?: ErrorDetails;

  constructor(options: {
    code: string;
    message: string;
    requestId?: string;
    details?: ErrorDetails;
  }) {
    super(options.message);
    this.name = this.constructor.name;
    this.code = options.code;
    this.requestId = options.requestId;
    this.details = options.details;
    Error.captureStackTrace(this, this.constructor);
  }

  toJSON(): Record<string, unknown> {
    return {
      error: {
        code: this.code,
        message: this.message,
        request_id: this.requestId,
      },
    };
  }
}

export class PolicyViolationError extends FirewallError {
  constructor(options: { message: string; requestId?: string; details?: ErrorDetails }) {
    super({
      code: 'POLICY_VIOLATION',
      message: options.message,
      requestId: options.requestId,
      details: options.details,
    });
  }
}

export class RateLimitError extends FirewallError {
  readonly retryAfterMs: number;

  constructor(options: {
    message: string;
    requestId?: string;
    retryAfterMs: number;
    details?: ErrorDetails;
  }) {
    super({
      code: 'RATE_LIMIT_EXCEEDED',
      message: options.message,
      requestId: options.requestId,
      details: options.details,
    });
    this.retryAfterMs = options.retryAfterMs;
  }

  override toJSON(): Record<string, unknown> {
    const base = super.toJSON();
    return {
      ...base,
      error: {
        ...(base.error as Record<string, unknown>),
        retry_after_ms: this.retryAfterMs,
      },
    };
  }
}

export class ValidationError extends FirewallError {
  constructor(options: { message: string; requestId?: string; details?: ErrorDetails }) {
    super({
      code: 'VALIDATION_ERROR',
      message: options.message,
      requestId: options.requestId,
      details: options.details,
    });
  }
}

export class BudgetExceededError extends FirewallError {
  constructor(options: { message: string; requestId?: string; details?: ErrorDetails }) {
    super({
      code: 'BUDGET_EXCEEDED',
      message: options.message,
      requestId: options.requestId,
      details: options.details,
    });
  }
}

export class ApprovalRequiredError extends FirewallError {
  readonly approvalId: string;

  constructor(options: {
    message: string;
    requestId?: string;
    approvalId: string;
    details?: ErrorDetails;
  }) {
    super({
      code: 'APPROVAL_REQUIRED',
      message: options.message,
      requestId: options.requestId,
      details: options.details,
    });
    this.approvalId = options.approvalId;
  }
}
