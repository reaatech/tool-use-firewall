import { createWriteStream, type WriteStream } from 'node:fs';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Safe logger that always writes to stderr or a file.
 * Never writes to stdout to avoid corrupting MCP JSON-RPC streams.
 */
export class Logger {
  private fileStream?: WriteStream;

  constructor(
    private readonly name: string,
    filePath?: string,
  ) {
    if (filePath) {
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      this.fileStream = createWriteStream(filePath, { flags: 'a' });
    }
  }

  debug(message: string, meta?: Record<string, unknown>): void {
    this.log('debug', message, meta);
  }

  info(message: string, meta?: Record<string, unknown>): void {
    this.log('info', message, meta);
  }

  warn(message: string, meta?: Record<string, unknown>): void {
    this.log('warn', message, meta);
  }

  error(message: string, meta?: Record<string, unknown>): void {
    this.log('error', message, meta);
  }

  private log(level: LogLevel, message: string, meta?: Record<string, unknown>): void {
    const entry = {
      time: new Date().toISOString(),
      level,
      name: this.name,
      message,
      ...(meta ? { meta } : {}),
    };
    const line = JSON.stringify(entry);

    // Always write to stderr to avoid corrupting stdout MCP stream
    process.stderr.write(line + '\n');

    if (this.fileStream) {
      this.fileStream.write(line + '\n');
    }
  }
}
