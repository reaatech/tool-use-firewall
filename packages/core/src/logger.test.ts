import { describe, expect, it, vi } from 'vitest';
import { Logger } from './logger.js';

describe('Logger', () => {
  it('writes to stderr', () => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const logger = new Logger('TestLogger');
    logger.info('hello');
    expect(write).toHaveBeenCalled();
    const call = write.mock.calls[0][0] as string;
    const parsed = JSON.parse(call);
    expect(parsed.level).toBe('info');
    expect(parsed.name).toBe('TestLogger');
    expect(parsed.message).toBe('hello');
    write.mockRestore();
  });

  it('includes metadata', () => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const logger = new Logger('TestLogger');
    logger.info('test', { key: 'value' });
    const call = write.mock.calls[0][0] as string;
    const parsed = JSON.parse(call);
    expect(parsed.meta).toEqual({ key: 'value' });
    write.mockRestore();
  });
});
