import { describe, expect, it } from 'vitest';
import { AuditLogger } from './index.js';

describe('AuditLogger', () => {
  it('creates without throwing', () => {
    const logger = new AuditLogger({ silent: true });
    expect(logger).toBeInstanceOf(AuditLogger);
  });
});
