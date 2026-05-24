import { describe, expect, it, vi } from 'vitest';
import {
  doInit,
  doValidate,
  generatePolicyYaml,
  main,
  parseArgs,
  readVersion,
  showHelp,
} from './cli.js';

const mockValidatePolicyFile = vi.hoisted(() => vi.fn());

vi.mock('@reaatech/tool-use-firewall-config', () => ({
  validatePolicyFile: mockValidatePolicyFile,
}));

vi.mock('./server.js', () => {
  class MockServer {
    start = vi.fn();
    stop = vi.fn();
  }
  return { MCPProxyServer: MockServer };
});

const cliSpawnCallbacks = vi.hoisted(() => ({}) as Record<string, (...args: unknown[]) => void>);

const mockFsWriteFileSync = vi.hoisted(() => vi.fn());

vi.mock('node:fs', () => ({
  writeFileSync: mockFsWriteFileSync,
}));

vi.mock('node:child_process', () => ({
  spawn: vi.fn(() => ({
    stdout: {
      on: vi.fn((_evt: string, cb: (...args: unknown[]) => void) => {
        cliSpawnCallbacks.stdout = cb;
      }),
    },
    stderr: { on: vi.fn() },
    stdin: { write: vi.fn() },
    on: vi.fn((_evt: string, cb: (...args: unknown[]) => void) => {
      cliSpawnCallbacks[_evt] = cb;
    }),
    kill: vi.fn(),
  })),
}));

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

  it('parses --upstream-args flag', () => {
    const parsed = parseArgs([
      '--config',
      'p.yaml',
      '--upstream',
      'node',
      '--upstream-args',
      'server.js --port 9000',
    ]);
    expect(parsed.upstreamArgs).toEqual(['server.js', '--port', '9000']);
  });

  it('rejects --upstream-args without a value', () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() =>
      parseArgs(['--config', 'p.yaml', '--upstream', 'node', '--upstream-args']),
    ).toThrow('exit');
    exit.mockRestore();
    error.mockRestore();
  });

  it('parses --http-port', () => {
    const parsed = parseArgs(['--config', 'p.yaml', '--upstream', 'node', '--http-port', '8080']);
    expect(parsed.httpPort).toBe(8080);
  });

  it('rejects --http-port when < 1', () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() =>
      parseArgs(['--config', 'p.yaml', '--upstream', 'node', '--http-port', '0']),
    ).toThrow('exit');
    exit.mockRestore();
    error.mockRestore();
  });

  it('rejects --http-port when > 65535', () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() =>
      parseArgs(['--config', 'p.yaml', '--upstream', 'node', '--http-port', '99999']),
    ).toThrow('exit');
    exit.mockRestore();
    error.mockRestore();
  });

  it('parses --dry-run flag', () => {
    const parsed = parseArgs(['--config', 'p.yaml', '--upstream', 'node', '--dry-run']);
    expect(parsed.dryRun).toBe(true);
  });

  it('parses --init flag with --upstream', () => {
    const parsed = parseArgs(['--upstream', 'node', '--init']);
    expect(parsed.initMode).toBe(true);
    expect(parsed.upstreamCommand).toBe('node');
  });

  it('exits when --init is used without --upstream', () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => parseArgs(['--init'])).toThrow('exit');
    exit.mockRestore();
    error.mockRestore();
  });

  it('exits on unknown argument', () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => parseArgs(['--bogus', '--config', 'p.yaml', '--upstream', 'node'])).toThrow(
      'exit',
    );
    exit.mockRestore();
    error.mockRestore();
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

describe('doValidate', () => {
  it('exits with code 0 for valid policy', () => {
    mockValidatePolicyFile.mockReturnValue({
      valid: true,
      warnings: [],
      errors: [],
    });
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit 0');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => doValidate('valid.yaml')).toThrow('exit 0');
    expect(error.mock.calls.some((c) => c[0].includes('Policy is valid'))).toBe(true);
    exit.mockRestore();
    error.mockRestore();
  });

  it('exits with code 1 for invalid policy', () => {
    mockValidatePolicyFile.mockReturnValue({
      valid: false,
      warnings: [],
      errors: ['Unknown rule type'],
    });
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit 1');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => doValidate('invalid.yaml')).toThrow('exit 1');
    expect(error.mock.calls.some((c) => c[0].includes('Policy is invalid'))).toBe(true);
    expect(error.mock.calls.some((c) => c[0].includes('Unknown rule type'))).toBe(true);
    exit.mockRestore();
    error.mockRestore();
  });
});

describe('generatePolicyYaml', () => {
  it('generates YAML with read tools', () => {
    const yaml = generatePolicyYaml([{ name: 'read_file', description: 'Read a file' }]);
    expect(yaml).toContain('allow_read_file');
    expect(yaml).toContain('type: allow');
    expect(yaml).toContain('read_only_exceptions');
  });

  it('generates YAML with write tools needing approval', () => {
    const yaml = generatePolicyYaml([{ name: 'write_file', description: 'Write to a file' }]);
    expect(yaml).toContain('approve_write_file');
    expect(yaml).toContain('type: approval_required');
  });

  it('generates YAML with database tools having sql_safe validation', () => {
    const yaml = generatePolicyYaml([{ name: 'query_database', description: 'Run SQL queries' }]);
    expect(yaml).toContain('sql_safe');
    expect(yaml).toContain('conditions:');
  });

  it('handles mixed tool types', () => {
    const yaml = generatePolicyYaml([
      { name: 'read_file' },
      { name: 'write_file' },
      { name: 'query_db' },
    ]);
    expect(yaml).toContain('allow_read_file');
    expect(yaml).toContain('approve_write_file');
    expect(yaml).toContain('sql_safe');
  });
});

describe('main', () => {
  it('shows help and exits on --help', async () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const origArgv = process.argv;
    process.argv = ['node', 'cli.js', '--help'];
    await expect(main()).rejects.toThrow('exit');
    expect(error.mock.calls.some((c) => c[0].includes('--config'))).toBe(true);
    process.argv = origArgv;
    exit.mockRestore();
    error.mockRestore();
  });

  it('shows version and exits on --version', async () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const origArgv = process.argv;
    process.argv = ['node', 'cli.js', '--version'];
    await expect(main()).rejects.toThrow('exit');
    process.argv = origArgv;
    exit.mockRestore();
    error.mockRestore();
  });

  it('calls doValidate on --validate', async () => {
    mockValidatePolicyFile.mockReturnValue({ valid: true, warnings: [], errors: [] });
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const origArgv = process.argv;
    process.argv = ['node', 'cli.js', '--validate', 'test.yaml'];
    await expect(main()).rejects.toThrow('exit');
    process.argv = origArgv;
    exit.mockRestore();
  });

  it('starts server with valid config and registers signal handlers', async () => {
    const origArgv = process.argv;
    process.argv = ['node', 'cli.js', '--config', 'p.yaml', '--upstream', 'echo'];
    await main();
    expect(process.listeners('SIGTERM').length).toBeGreaterThan(0);
    expect(process.listeners('SIGINT').length).toBeGreaterThan(0);
    process.argv = origArgv;
  });

  it('starts server with --upstream-args flag', async () => {
    const origArgv = process.argv;
    process.argv = [
      'node',
      'cli.js',
      '--config',
      'p.yaml',
      '--upstream',
      'echo',
      '--upstream-args',
      'hello world',
    ];
    await main();
    expect(process.listeners('SIGTERM').length).toBeGreaterThan(0);
    process.argv = origArgv;
  });
});

describe('doInit', () => {
  it('exits with 0 when tools/list response is received', async () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit 0');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const promise = doInit('echo', []);
    const dataHandler = cliSpawnCallbacks.stdout;
    expect(dataHandler).toBeDefined();
    dataHandler(Buffer.from(JSON.stringify({ id: 2, result: { tools: [{ name: 'test_tool' }] } })));
    cliSpawnCallbacks.exit();
    await expect(promise).rejects.toThrow('exit 0');
    expect(mockFsWriteFileSync).toHaveBeenCalled();
    exit.mockRestore();
    error.mockRestore();
  });

  it('exits with 1 when no tools/list response', async () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit 1');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const promise = doInit('echo', []);
    cliSpawnCallbacks.exit();
    await expect(promise).rejects.toThrow('exit 1');
    expect(error.mock.calls.some((c) => c[0].includes('Failed to get tools'))).toBe(true);
    exit.mockRestore();
    error.mockRestore();
  });
});
