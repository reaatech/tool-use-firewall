import { createWriteStream } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { Logger } from './logger.js';

vi.mock('node:fs');

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

  it('logs at debug level', () => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const logger = new Logger('TestLogger');
    logger.debug('debug message');
    const call = write.mock.calls[0][0] as string;
    const parsed = JSON.parse(call);
    expect(parsed.level).toBe('debug');
    expect(parsed.message).toBe('debug message');
    write.mockRestore();
  });

  it('logs at warn level', () => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const logger = new Logger('TestLogger');
    logger.warn('warn message');
    const call = write.mock.calls[0][0] as string;
    const parsed = JSON.parse(call);
    expect(parsed.level).toBe('warn');
    expect(parsed.message).toBe('warn message');
    write.mockRestore();
  });

  it('logs at error level', () => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const logger = new Logger('TestLogger');
    logger.error('error message');
    const call = write.mock.calls[0][0] as string;
    const parsed = JSON.parse(call);
    expect(parsed.level).toBe('error');
    expect(parsed.message).toBe('error message');
    write.mockRestore();
  });

  it('writes to file stream when filePath is provided', () => {
    const mockWrite = vi.fn();
    vi.mocked(createWriteStream).mockReturnValue({ write: mockWrite } as never);
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const filePath = join(tmpdir(), 'test.log');
    const logger = new Logger('FileLogger', filePath);
    logger.info('file message');
    expect(createWriteStream).toHaveBeenCalledWith(filePath, { flags: 'a' });
    expect(mockWrite).toHaveBeenCalled();
    const fileCall = mockWrite.mock.calls[0][0] as string;
    const parsed = JSON.parse(fileCall);
    expect(parsed.name).toBe('FileLogger');
    expect(parsed.message).toBe('file message');
    write.mockRestore();
  });
});
