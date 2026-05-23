import type { ApprovalRequest, ApproverGroup } from './types.js';

export interface DiscordApproverConfig {
  type: 'discord';
  webhook_url_env: string;
}

export class DiscordApprover implements ApproverGroup {
  private readonly webhookUrl: string;

  constructor(config: DiscordApproverConfig) {
    const url = process.env[config.webhook_url_env];
    if (!url) {
      throw new Error(`Environment variable ${config.webhook_url_env} is not set`);
    }
    this.webhookUrl = url;
  }

  async notify(request: ApprovalRequest): Promise<void> {
    const payload = {
      content: '',
      embeds: [
        {
          title: 'Approval Required',
          color: 16750848,
          fields: [
            { name: 'Tool', value: `\`${request.context.toolName ?? 'unknown'}\``, inline: true },
            { name: 'Approval ID', value: `\`${request.id}\``, inline: true },
            { name: 'Session ID', value: `\`${request.context.sessionId}\``, inline: false },
          ],
          footer: { text: 'tool-use-firewall' },
          timestamp: new Date().toISOString(),
        },
      ],
    };

    await fetch(this.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  }
}
