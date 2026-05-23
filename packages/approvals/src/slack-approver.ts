import type { ApprovalRequest, ApproverGroup } from './types.js';

export interface SlackApproverConfig {
  type: 'slack';
  webhook_url_env: string;
  channel?: string;
}

export class SlackApprover implements ApproverGroup {
  private readonly webhookUrl: string;
  private readonly channel?: string;

  constructor(config: SlackApproverConfig) {
    const url = process.env[config.webhook_url_env];
    if (!url) {
      throw new Error(`Environment variable ${config.webhook_url_env} is not set`);
    }
    this.webhookUrl = url;
    this.channel = config.channel;
  }

  async notify(request: ApprovalRequest): Promise<void> {
    const payload = {
      text: `*Approval Required*\n> *Tool:* \`${request.context.toolName ?? 'unknown'}\`\n> *ID:* \`${request.id}\`\n> *Session:* \`${request.context.sessionId}\`${this.channel ? '' : ''}`,
      channel: this.channel,
      mrkdwn: true,
    };

    const body = JSON.stringify(payload);
    await fetch(this.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
  }
}
