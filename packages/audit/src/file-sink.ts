import {
  closeSync,
  existsSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { gzipSync } from 'node:zlib';

const DEFAULT_MAX_SIZE_BYTES = 10 * 1024 * 1024;

export interface FileSinkOptions {
  /** `daily` rotates on UTC date change; `size` rotates past `maxSizeBytes`. */
  rotation?: 'daily' | 'size';
  /** Keep at most this many rotated files; older ones are deleted. */
  maxFiles?: number;
  /** Gzip rotated files to `<name>.gz`. */
  compress?: boolean;
  /** Size threshold for `size` rotation (bytes). Defaults to 10 MiB. */
  maxSizeBytes?: number;
  /** Called on write/rotation failure; never throws back into the caller. */
  onError?: (message: string, meta: Record<string, unknown>) => void;
}

function currentDay(): string {
  return new Date().toISOString().slice(0, 10);
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Append-only writer for newline-delimited audit JSON with optional rotation.
 * Writes are synchronous (`writeSync` to a held fd) so rotation is race-free;
 * audit volume is one line per tool call, so the cost is negligible. All
 * failures are routed to `onError` and never propagate — audit logging is
 * best-effort and must not break the proxy. */
export class RotatingFileSink {
  private fd: number;
  private size: number;
  private day: string;
  private rotationSeq = 0;
  private readonly maxSizeBytes: number;

  constructor(
    private readonly path: string,
    private readonly opts: FileSinkOptions = {},
  ) {
    this.maxSizeBytes = opts.maxSizeBytes ?? DEFAULT_MAX_SIZE_BYTES;
    this.size = existsSync(path) ? statSync(path).size : 0;
    this.day = currentDay();
    this.fd = openSync(path, 'a');
  }

  write(line: string): void {
    try {
      const bytes = Buffer.byteLength(line);
      if (this.shouldRotate(bytes)) {
        this.rotate();
      }
      writeSync(this.fd, line);
      this.size += bytes;
    } catch (error) {
      this.opts.onError?.('audit sidecar file write failed', {
        path: this.path,
        error: message(error),
      });
    }
  }

  close(): void {
    try {
      closeSync(this.fd);
    } catch {
      // already closed
    }
  }

  private shouldRotate(bytes: number): boolean {
    if (this.opts.rotation === 'daily') {
      return currentDay() !== this.day;
    }
    if (this.opts.rotation === 'size') {
      return this.size > 0 && this.size + bytes > this.maxSizeBytes;
    }
    return false;
  }

  private rotate(): void {
    // Daily rotations are named for the day that just closed; size rotations
    // get a timestamp plus a monotonic sequence so back-to-back rotations in
    // the same millisecond never collide.
    this.rotationSeq += 1;
    const suffix =
      this.opts.rotation === 'daily'
        ? this.day
        : `${new Date().toISOString().replace(/[:.]/g, '-')}-${this.rotationSeq}`;
    const rotated = `${this.path}.${suffix}`;
    try {
      closeSync(this.fd);
    } catch {
      // fall through and reopen below
    }
    try {
      renameSync(this.path, rotated);
      if (this.opts.compress) {
        writeFileSync(`${rotated}.gz`, gzipSync(readFileSync(rotated)));
        unlinkSync(rotated);
      }
      this.prune();
    } catch (error) {
      this.opts.onError?.('audit sidecar file rotation failed', {
        path: this.path,
        error: message(error),
      });
    } finally {
      // Reopen regardless: on success this creates a fresh file; if the rename
      // failed we keep appending to the existing one rather than losing writes.
      this.fd = openSync(this.path, 'a');
      this.size = existsSync(this.path) ? statSync(this.path).size : 0;
      this.day = currentDay();
    }
  }

  /** Delete the oldest rotated files beyond `maxFiles` (by mtime). */
  private prune(): void {
    const max = this.opts.maxFiles;
    if (!max || max < 1) return;
    const dir = dirname(this.path);
    const base = basename(this.path);
    const rotated = readdirSync(dir)
      .filter((f) => f.startsWith(`${base}.`) && f !== base)
      .map((f) => ({ f, mtime: statSync(join(dir, f)).mtimeMs }))
      .sort((a, b) => b.mtime - a.mtime);
    for (const { f } of rotated.slice(max)) {
      try {
        unlinkSync(join(dir, f));
      } catch {
        // best-effort cleanup
      }
    }
  }
}
