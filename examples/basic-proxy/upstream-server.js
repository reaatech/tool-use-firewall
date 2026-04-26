#!/usr/bin/env node
// A minimal MCP-style upstream server used by the basic-proxy example.
// Reads JSON-RPC messages on stdin, writes responses on stdout.

import { createInterface } from 'node:readline';

const rl = createInterface({ input: process.stdin });

const tools = [
  { name: 'echo', description: 'Echo the input back' },
  { name: 'add', description: 'Add two numbers' },
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
        serverInfo: { name: 'basic-upstream', version: '0.0.1' },
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
    if (name === 'echo') {
      send({
        jsonrpc: '2.0',
        id: msg.id,
        result: { content: [{ type: 'text', text: String(args.text ?? '') }] },
      });
      return;
    }
    if (name === 'add') {
      const sum = Number(args.a ?? 0) + Number(args.b ?? 0);
      send({
        jsonrpc: '2.0',
        id: msg.id,
        result: { content: [{ type: 'text', text: String(sum) }] },
      });
      return;
    }
    send({
      jsonrpc: '2.0',
      id: msg.id,
      error: { code: -32601, message: `Unknown tool: ${name}` },
    });
    return;
  }

  send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'Method not found' } });
});
