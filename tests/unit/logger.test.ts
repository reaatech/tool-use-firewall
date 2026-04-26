import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Logger } from '../../src/utils/logger.js';

describe('Logger', () => {
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  it('should log info to stderr', () => {
    const logger = new Logger('TestLogger');
    logger.info('hello');
    expect(stderrSpy).toHaveBeenCalled();
    const call = stderrSpy.mock.calls[0]?.[0] as string;
    const parsed = JSON.parse(call.trim());
    expect(parsed.level).toBe('info');
    expect(parsed.name).toBe('TestLogger');
    expect(parsed.message).toBe('hello');
  });

  it('should log error to stderr', () => {
    const logger = new Logger('TestLogger');
    logger.error('something went wrong', { code: 'ERR_1' });
    const call = stderrSpy.mock.calls[0]?.[0] as string;
    const parsed = JSON.parse(call.trim());
    expect(parsed.level).toBe('error');
    expect(parsed.meta).toEqual({ code: 'ERR_1' });
  });

  it('should log debug to stderr', () => {
    const logger = new Logger('TestLogger');
    logger.debug('debug msg');
    const call = stderrSpy.mock.calls[0]?.[0] as string;
    const parsed = JSON.parse(call.trim());
    expect(parsed.level).toBe('debug');
  });

  it('should log warn to stderr', () => {
    const logger = new Logger('TestLogger');
    logger.warn('warn msg');
    const call = stderrSpy.mock.calls[0]?.[0] as string;
    const parsed = JSON.parse(call.trim());
    expect(parsed.level).toBe('warn');
  });

  it('should write to file when filePath is provided', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'logger-test-'));
    const filePath = join(tmpDir, 'test.log');
    const logger = new Logger('FileLogger', filePath);
    logger.info('file message');

    // Wait for async file write
    await new Promise((resolve) => setTimeout(resolve, 50));
    const content = readFileSync(filePath, 'utf8');
    expect(content).toContain('file message');

    rmSync(tmpDir, { recursive: true, force: true });
  });
});
