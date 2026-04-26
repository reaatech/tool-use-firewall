#!/usr/bin/env node
// Mock database MCP server for the database-safety example.
// Pretends to execute SQL — it never touches a real database.

import { createInterface } from 'node:readline';

const rl = createInterface({ input: process.stdin });

const tools = [
  { name: 'database_execute', description: 'Run a SQL query against the demo database' },
  { name: 'database_describe', description: 'Describe a table' },
];

function send(message) {
  process.stdout.write(JSON.stringify(message) + '\n');
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
        serverInfo: { name: 'db-mock-upstream', version: '0.0.1' },
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
    const text =
      name === 'database_execute'
        ? `[mock] would execute: ${args.query ?? ''}`
        : `[mock] would describe: ${args.table ?? ''}`;
    send({
      jsonrpc: '2.0',
      id: msg.id,
      result: { content: [{ type: 'text', text }] },
    });
    return;
  }

  send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'Method not found' } });
});
