import { timingSafeEqual } from 'node:crypto';
import { Logger, redact } from '@reaatech/tool-use-firewall-core';
import { TokenBucket } from '@reaatech/tool-use-firewall-policies';
import express from 'express';
import { z } from 'zod';
import type { ApprovalWorkflow } from './workflow.js';

const RATE_LIMIT_WINDOW_MS = 60000;
const RATE_LIMIT_MAX_REQUESTS = 60;
const RATE_LIMIT_CLEANUP_INTERVAL_MS = 300000;

const approveBodySchema = z.object({
  approverId: z.string().min(1),
  approverGroup: z.string().min(1),
  comment: z.string().optional(),
});

const denyBodySchema = z.object({
  approverId: z.string().min(1),
  approverGroup: z.string().min(1),
  reason: z.string().optional(),
});

/** Creates an Express application with a REST API for managing approval requests.
 *
 * Endpoints:
 * - `GET /health` — Health check with uptime and pending count
 * - `GET /api/v1/approvals/pending` — List pending approvals (redacted)
 * - `GET /api/v1/approvals/:id` — Get a specific approval
 * - `POST /api/v1/approvals/:id/approve` — Approve a request
 * - `POST /api/v1/approvals/:id/deny` — Deny a request
 *
 * @example
 * ```ts
 * const app = createApprovalApi(workflow, apiKey);
 * app.listen(3001, '127.0.0.1', () => {
 *   console.log('Approval API listening on port 3001');
 * });
 * ```
 */
export function createApprovalApi(
  workflow: ApprovalWorkflow,
  apiKey: string,
  opts?: { getStats?: () => Record<string, unknown> },
): express.Application {
  if (typeof apiKey !== 'string' || apiKey.length === 0) {
    throw new Error('createApprovalApi requires a non-empty apiKey');
  }
  const app = express();
  const logger = new Logger('ApprovalApi');

  const ipBuckets = new Map<string, { bucket: TokenBucket; lastAccess: number }>();
  setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of ipBuckets.entries()) {
      if (now - entry.lastAccess > RATE_LIMIT_CLEANUP_INTERVAL_MS) {
        ipBuckets.delete(ip);
      }
    }
    if (ipBuckets.size > 10000) {
      const entries = Array.from(ipBuckets.entries());
      entries.sort((a, b) => a[1].lastAccess - b[1].lastAccess);
      for (const [ip] of entries.slice(0, entries.length - 10000)) {
        ipBuckets.delete(ip);
      }
    }
  }, RATE_LIMIT_CLEANUP_INTERVAL_MS).unref();

  app.use((req, _res, next) => {
    const ip = req.ip ?? req.socket.remoteAddress ?? 'unknown';
    let entry = ipBuckets.get(ip);
    if (!entry) {
      entry = {
        bucket: new TokenBucket(
          RATE_LIMIT_MAX_REQUESTS,
          RATE_LIMIT_MAX_REQUESTS / RATE_LIMIT_WINDOW_MS,
        ),
        lastAccess: Date.now(),
      };
      ipBuckets.set(ip, entry);
    }
    entry.lastAccess = Date.now();
    if (!entry.bucket.consume()) {
      _res.status(429).json({ error: 'Too many requests' });
      return;
    }
    next();
  });

  app.use(express.json({ limit: '1mb' }));

  app.use((req, res, next) => {
    if (req.path === '/health') {
      next();
      return;
    }
    const authHeader = req.headers.authorization ?? '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    try {
      const expected = Buffer.from(apiKey, 'utf8');
      const actual = Buffer.from(token, 'utf8');
      if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
    } catch {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  });

  app.get('/health', (_req, res) => {
    const payload: Record<string, unknown> = {
      status: 'ok',
      uptime: process.uptime(),
      pendingApprovals: workflow.listPending().length,
    };
    if (opts?.getStats) {
      Object.assign(payload, opts.getStats());
    }
    res.json(payload);
  });

  app.get('/api/v1/approvals/pending', (_req, res) => {
    const pending = workflow.listPending().map((r) => ({
      id: r.id,
      toolName: r.context.toolName,
      arguments: redact(r.context.arguments),
      createdAt: r.createdAt,
      expiresAt: r.expiresAt,
      requiredApprovers: r.requiredApprovers,
      pendingApprovers: r.requiredApprovers.filter(
        (g) => !r.approvals.some((a) => a.approverGroup === g),
      ),
    }));
    res.json({ approvals: pending });
  });

  app.get('/api/v1/approvals/:id', (req, res) => {
    const request = workflow.getStatus(req.params.id);
    if (!request) {
      res.status(404).json({ error: 'Approval request not found' });
      return;
    }
    res.json({
      id: request.id,
      status: request.status,
      toolName: request.context.toolName,
      arguments: redact(request.context.arguments),
      createdAt: request.createdAt,
      expiresAt: request.expiresAt,
      approvals: request.approvals,
      denials: request.denials,
    });
  });

  app.post('/api/v1/approvals/:id/approve', async (req, res) => {
    const parseResult = approveBodySchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({ error: 'Invalid request body', details: parseResult.error.issues });
      return;
    }
    const { approverId, approverGroup, comment } = parseResult.data;

    try {
      const result = await workflow.approve(req.params.id, approverId, approverGroup, comment);
      if (!result.success) {
        res.status(400).json({ error: result.reason });
        return;
      }
      res.json(result);
    } catch (error) {
      logger.error('Error approving request', {
        error: error instanceof Error ? error.message : String(error),
      });
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/api/v1/approvals/:id/deny', async (req, res) => {
    const parseResult = denyBodySchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({ error: 'Invalid request body', details: parseResult.error.issues });
      return;
    }
    const { approverId, approverGroup, reason } = parseResult.data;

    try {
      const result = await workflow.deny(req.params.id, approverId, approverGroup, reason);
      if (!result.success) {
        res.status(400).json({ error: result.reason });
        return;
      }
      res.json(result);
    } catch (error) {
      logger.error('Error denying request', {
        error: error instanceof Error ? error.message : String(error),
      });
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.use(
    (err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      logger.error('Unhandled API error', { error: err.message });
      res.status(500).json({ error: 'Internal server error' });
    },
  );

  return app;
}
