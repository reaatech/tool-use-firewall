import { createInterface } from 'node:readline';
import { Logger } from '../utils/logger.js';
import { redact } from '../utils/redactor.js';
import type { ApprovalRequest, ApproverGroup, ApprovalResult } from './types.js';

export interface CLIApproverConfig {
  prompt?: string;
}

/**
 * CLI-based approval interface that prompts on the console.
 * For local development and testing only.
 * Writes to stderr (never stdout) to avoid corrupting MCP JSON-RPC streams.
 */
export class CLIApprover implements ApproverGroup {
  private logger = new Logger('CLIApprover');

  constructor(private readonly config: CLIApproverConfig = {}) {}

  async notify(request: ApprovalRequest): Promise<void> {
    const prompt = this.config.prompt ?? 'Approval required';
    this.logger.info(prompt, {
      tool: request.context.toolName,
      args: redact(request.context.arguments),
      expires: new Date(request.expiresAt).toISOString(),
    });
  }

  /**
   * Prompt the user for approval via stdin.
   */
  static async prompt(request: ApprovalRequest): Promise<ApprovalResult> {
    const rl = createInterface({
      input: process.stdin,
      output: process.stderr, // Use stderr to avoid corrupting stdout MCP stream
    });

    const answer = await new Promise<string>((resolve) => {
      rl.question(`Approve ${request.context.toolName}? [y/N]: `, (ans) => {
        rl.close();
        resolve(ans.trim().toLowerCase());
      });
    });

    if (answer === 'y' || answer === 'yes') {
      return { success: true, status: 'APPROVED' };
    }
    return { success: true, status: 'DENIED', reason: 'Denied by operator' };
  }
}
