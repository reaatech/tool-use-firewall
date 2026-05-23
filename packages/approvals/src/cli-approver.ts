import { createInterface } from 'node:readline';
import { Logger, redact } from '@reaatech/tool-use-firewall-core';
import type { ApprovalRequest, ApproverGroup, ApprovalResult } from './types.js';

export interface CLIApproverConfig {
  prompt?: string;
}

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

  static async prompt(request: ApprovalRequest): Promise<ApprovalResult> {
    const rl = createInterface({
      input: process.stdin,
      output: process.stderr,
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
