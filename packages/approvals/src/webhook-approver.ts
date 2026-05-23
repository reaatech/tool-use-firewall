import { Logger, redact } from '@reaatech/tool-use-firewall-core';
import type { ApprovalRequest, ApproverGroup } from './types.js';

export interface WebhookApproverConfig {
  url: string;
  api_key_env?: string;
}

export class WebhookApprover implements ApproverGroup {
  private readonly url: string;
  private readonly apiKey: string;
  private readonly logger = new Logger('WebhookApprover');

  constructor(config: WebhookApproverConfig) {
    this.url = config.url;
    this.apiKey = config.api_key_env ? (process.env[config.api_key_env] ?? '') : '';
  }

  async notify(request: ApprovalRequest): Promise<void> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    try {
      const response = await fetch(this.url, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          event: 'approval_requested',
          approval_id: request.id,
          tool_name: request.context.toolName,
          arguments: redact(request.context.arguments),
          requested_by: request.context.agentId ?? 'unknown',
          expires_at: new Date(request.expiresAt).toISOString(),
          approval_url: `${this.url}/${request.id}`,
        }),
        signal: AbortSignal.timeout(30000),
      });
      if (!response.ok) {
        this.logger.error('Webhook returned non-OK status', {
          status: response.status,
          url: this.url,
        });
      }
    } catch (error) {
      this.logger.error('Webhook notification failed', {
        error: error instanceof Error ? error.message : String(error),
        url: this.url,
      });
    }
  }
}
