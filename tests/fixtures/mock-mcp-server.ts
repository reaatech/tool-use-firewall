import { spawn } from 'node:child_process';

/**
 * A simple mock MCP server that can be spawned as a child process.
 * Responds to tools/list and tools/call messages.
 */
export function startMockServer(): { stop: () => void } {
  const script = `
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin });

const tools = [
  { name: 'echo', description: 'Echoes input' },
  { name: 'database_execute', description: 'Executes SQL' },
];

rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    if (msg.method === 'tools/list') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { tools }
      }) + '\\n');
    } else if (msg.method === 'tools/call') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          content: [{ type: 'text', text: 'success: ' + msg.params.name }]
        }
      }) + '\\n');
    } else {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: {}
      }) + '\\n');
    }
  } catch (e) {
    // ignore
  }
});
`;

  const proc = spawn('node', ['-e', script], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  return {
    stop: () => {
      if (!proc.killed) proc.kill();
    },
  };
}
