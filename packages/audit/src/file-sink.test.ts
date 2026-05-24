import { existsSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { RotatingFileSink } from './file-sink.js';

function tmpFile(name = 'audit.log'): string {
  return join(mkdtempSync(join(tmpdir(), 'tuf-sink-')), name);
}

function rotatedFiles(path: string): string[] {
  const dir = join(path, '..');
  const base = basename(path);
  return readdirSync(dir).filter((f) => f.startsWith(`${base}.`) && f !== base);
}

describe('RotatingFileSink', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('appends newline-delimited lines to the file', () => {
    const path = tmpFile();
    const sink = new RotatingFileSink(path);
    sink.write('a\n');
    sink.write('b\n');
    sink.close();
    expect(readFileSync(path, 'utf-8')).toBe('a\nb\n');
  });

  it('rotates by size and keeps writing to the base file', () => {
    const path = tmpFile();
    const sink = new RotatingFileSink(path, { rotation: 'size', maxSizeBytes: 20 });
    sink.write('first-line-aaaaaaa\n'); // ~19 bytes, fits
    sink.write('second-line\n'); // would exceed 20 → rotate first
    sink.close();

    const rotated = rotatedFiles(path);
    expect(rotated).toHaveLength(1);
    expect(readFileSync(join(path, '..', rotated[0]), 'utf-8')).toBe('first-line-aaaaaaa\n');
    expect(readFileSync(path, 'utf-8')).toBe('second-line\n');
  });

  it('prunes rotated files beyond maxFiles', () => {
    const path = tmpFile();
    const sink = new RotatingFileSink(path, { rotation: 'size', maxSizeBytes: 5, maxFiles: 2 });
    for (let i = 0; i < 5; i++) {
      sink.write(`line${i}\n`);
    }
    sink.close();
    expect(rotatedFiles(path).length).toBeLessThanOrEqual(2);
  });

  it('compresses rotated files when compress is set', () => {
    const path = tmpFile();
    const sink = new RotatingFileSink(path, { rotation: 'size', maxSizeBytes: 10, compress: true });
    sink.write('alpha\n');
    sink.write('bravo\n'); // triggers rotation of "alpha"
    sink.close();

    const rotated = rotatedFiles(path);
    expect(rotated).toHaveLength(1);
    expect(rotated[0].endsWith('.gz')).toBe(true);
    const gz = readFileSync(join(path, '..', rotated[0]));
    expect(gunzipSync(gz).toString()).toBe('alpha\n');
  });

  it('rotates daily when the UTC date changes', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-05-23T23:59:00Z'));
    const path = tmpFile();
    const sink = new RotatingFileSink(path, { rotation: 'daily' });
    sink.write('day-one\n');

    vi.setSystemTime(new Date('2026-05-24T00:01:00Z'));
    sink.write('day-two\n'); // new day → rotate
    sink.close();

    expect(existsSync(`${path}.2026-05-23`)).toBe(true);
    expect(readFileSync(`${path}.2026-05-23`, 'utf-8')).toBe('day-one\n');
    expect(readFileSync(path, 'utf-8')).toBe('day-two\n');
  });

  it('reports write errors via onError instead of throwing', () => {
    const onError = vi.fn();
    const sink = new RotatingFileSink(tmpFile(), { onError });
    sink.close(); // close the fd so the next write fails with EBADF
    expect(() => sink.write('x\n')).not.toThrow();
    expect(onError).toHaveBeenCalledTimes(1);
  });
});
