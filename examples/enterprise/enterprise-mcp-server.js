#!/usr/bin/env node
// Mock "enterprise" MCP server: a couple of tools across different domains
// (database, files, deploys) used by the enterprise example.

import { createInterface } from 'node:readline';

const rl = createInterface({ input: process.stdin });

const tools = [
  { name: 'database_execute', description: 'Run a SQL query' },
  { name: 'file_write', description: 'Write content to a file path' },
  { name: 'deploy_release', description: 'Trigger a release deploy' },
];

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

rl.on('line', (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }

  if (msg.method === 'initialize') {
    send({
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        serverInfo: { name: 'enterprise-mock-upstream', version: '0.0.1' },
      },
    });
    return;
  }

  if (msg.method === 'tools/list') {
    send({ jsonrpc: '2.0', id: msg.id, result: { tools } });
    return;
  }

  if (msg.method === 'tools/call') {
    const { name, arguments: args = {} } = msg.params ?? {};
    send({
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        content: [{ type: 'text', text: `[mock] ${name} called with ${JSON.stringify(args)}` }],
      },
    });
    return;
  }

  send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'Method not found' } });
});
