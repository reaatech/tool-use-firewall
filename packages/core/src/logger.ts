import { createWriteStream, type WriteStream } from 'node:fs';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export class Logger {
  private fileStream?: WriteStream;

  constructor(
    private readonly name: string,
    filePath?: string,
  ) {
    if (filePath) {
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
    process.stderr.write(`${line}\n`);
    if (this.fileStream) {
      this.fileStream.write(`${line}\n`);
    }
  }
}
