import { describe, expect, it, vi } from 'vitest';
import { parseArgs, readVersion, showHelp } from './cli.js';

describe('parseArgs', () => {
  it('parses --config and --upstream', () => {
    const parsed = parseArgs(['--config', 'policy.yaml', '--upstream', 'node']);
    expect(parsed.configPath).toBe('policy.yaml');
    expect(parsed.upstreamCommand).toBe('node');
    expect(parsed.upstreamArgs).toEqual([]);
  });

  it('parses short flags -c and -u', () => {
    const parsed = parseArgs(['-c', 'policy.yaml', '-u', 'echo']);
    expect(parsed.configPath).toBe('policy.yaml');
    expect(parsed.upstreamCommand).toBe('echo');
  });

  it('collects upstream args before next firewall flag', () => {
    const parsed = parseArgs([
      '--config',
      'p.yaml',
      '--upstream',
      'node',
      'server.js',
      '--port',
      '9000',
    ]);
    expect(parsed.upstreamCommand).toBe('node');
    expect(parsed.upstreamArgs).toEqual(['server.js', '--port', '9000']);
  });

  it('stops collecting upstream args at next firewall flag', () => {
    const parsed = parseArgs(['--upstream', 'node', 'server.js', '--config', 'p.yaml']);
    expect(parsed.upstreamCommand).toBe('node');
    expect(parsed.upstreamArgs).toEqual(['server.js']);
    expect(parsed.configPath).toBe('p.yaml');
  });

  it('handles -- separator for passing args to upstream', () => {
    const parsed = parseArgs([
      '--config',
      'p.yaml',
      '--upstream',
      'node',
      '--',
      '--port',
      '9000',
      '--verbose',
    ]);
    expect(parsed.upstreamArgs).toEqual(['--port', '9000', '--verbose']);
  });

  it('parses --approval-port', () => {
    const parsed = parseArgs([
      '--config',
      'p.yaml',
      '--upstream',
      'node',
      '--approval-port',
      '8080',
    ]);
    expect(parsed.approvalPort).toBe(8080);
  });

  it('rejects --approval-port when < 1', () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() =>
      parseArgs(['--config', 'p.yaml', '--upstream', 'node', '--approval-port', '0']),
    ).toThrow('exit');
    exit.mockRestore();
    error.mockRestore();
  });

  it('rejects --approval-port when > 65535', () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() =>
      parseArgs(['--config', 'p.yaml', '--upstream', 'node', '--approval-port', '99999']),
    ).toThrow('exit');
    exit.mockRestore();
    error.mockRestore();
  });

  it('parses --validate <path> without requiring --config or --upstream', () => {
    const parsed = parseArgs(['--validate', 'policy.yaml']);
    expect(parsed.validatePath).toBe('policy.yaml');
  });

  it('rejects --validate without a path', () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => parseArgs(['--validate', '--config', 'p.yaml'])).toThrow('exit');
    exit.mockRestore();
    error.mockRestore();
  });

  it('exits when --config is missing', () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => parseArgs(['--upstream', 'node'])).toThrow('exit');
    exit.mockRestore();
    error.mockRestore();
  });

  it('exits when --upstream is missing', () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => parseArgs(['--config', 'p.yaml'])).toThrow('exit');
    exit.mockRestore();
    error.mockRestore();
  });

  it('passes unknown flags after --upstream as upstream args', () => {
    const parsed = parseArgs([
      '--config',
      'p.yaml',
      '--upstream',
      'node',
      '--unknown-flag',
      'value',
    ]);
    expect(parsed.upstreamArgs).toEqual(['--unknown-flag', 'value']);
  });

  it('handles --upstream with no additional args', () => {
    const parsed = parseArgs(['--config', 'p.yaml', '--upstream', 'node']);
    expect(parsed.upstreamArgs).toEqual([]);
  });
});

describe('readVersion', () => {
  it('returns a non-empty string', () => {
    const version = readVersion();
    expect(typeof version).toBe('string');
    expect(version.length).toBeGreaterThan(0);
  });
});

describe('showHelp', () => {
  it('writes help text to stderr', () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    showHelp();
    const output = error.mock.calls.map((c) => c[0]).join('');
    expect(output).toContain('tool-use-firewall');
    expect(output).toContain('--config');
    expect(output).toContain('--upstream');
    error.mockRestore();
  });
});
