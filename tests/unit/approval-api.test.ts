import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import { createApprovalApi } from '../../src/approvals/api.js';
import { ApprovalWorkflow } from '../../src/approvals/workflow.js';
import { createRequestContext } from '../../src/middleware/context.js';
import type { ApprovalConfig } from '../../src/config/schema.js';

const TEST_KEY = 'secret-key';
const auth = (
  req: ReturnType<typeof request.agent> | ReturnType<ReturnType<typeof request>['get']>,
) =>
  (req as ReturnType<ReturnType<typeof request>['get']>).set('Authorization', `Bearer ${TEST_KEY}`);

describe('createApprovalApi', () => {
  let workflow: ApprovalWorkflow;

  const createWorkflow = (config: Partial<ApprovalConfig> = {}) => {
    return new ApprovalWorkflow({
      default_timeout_ms: 300000,
      max_pending_approvals: 1000,
      ...config,
    });
  };

  beforeEach(() => {
    workflow = createWorkflow();
  });

  describe('construction', () => {
    it('throws if apiKey is missing or empty', () => {
      expect(() => createApprovalApi(workflow, '' as unknown as string)).toThrow();
      expect(() => createApprovalApi(workflow, undefined as unknown as string)).toThrow();
    });
  });

  describe('authenticated routes', () => {
    it('exposes /health without authentication', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });

    it('rejects requests without bearer token', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const res = await request(app).get('/api/v1/approvals/pending');
      expect(res.status).toBe(401);
    });

    it('rejects requests with the wrong bearer token', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const res = await request(app)
        .get('/api/v1/approvals/pending')
        .set('Authorization', 'Bearer wrong-key');
      expect(res.status).toBe(401);
    });

    it('lists pending approvals when authenticated', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'db_query',
        arguments: { query: 'SELECT 1' },
      });
      try {
        await workflow.requestApproval(ctx);
      } catch {
        /* ignore */
      }

      const res = await auth(request(app).get('/api/v1/approvals/pending'));
      expect(res.status).toBe(200);
      expect(res.body.approvals).toHaveLength(1);
      expect(res.body.approvals[0].toolName).toBe('db_query');
    });

    it('redacts arguments in pending list', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'db_query',
        arguments: { password: 'secret' },
      });
      try {
        await workflow.requestApproval(ctx);
      } catch {
        /* ignore */
      }

      const res = await auth(request(app).get('/api/v1/approvals/pending'));
      expect(JSON.stringify(res.body)).toContain('[REDACTED]');
    });

    it('gets an approval by id', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'db_query',
      });
      let approvalId = '';
      try {
        await workflow.requestApproval(ctx);
      } catch (error) {
        approvalId = (error as { approvalId: string }).approvalId;
      }

      const res = await auth(request(app).get(`/api/v1/approvals/${approvalId}`));
      expect(res.status).toBe(200);
      expect(res.body.id).toBe(approvalId);
    });

    it('returns 404 for missing approval', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const res = await auth(request(app).get('/api/v1/approvals/nonexistent'));
      expect(res.status).toBe(404);
    });

    it('approves a request', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'db_query',
      });
      let approvalId = '';
      try {
        await workflow.requestApproval(ctx);
      } catch (error) {
        approvalId = (error as { approvalId: string }).approvalId;
      }

      const res = await auth(
        request(app)
          .post(`/api/v1/approvals/${approvalId}/approve`)
          .send({ approverId: 'user1', approverGroup: 'default' }),
      );
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('denies a request', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'db_query',
      });
      let approvalId = '';
      try {
        await workflow.requestApproval(ctx);
      } catch (error) {
        approvalId = (error as { approvalId: string }).approvalId;
      }

      const res = await auth(
        request(app)
          .post(`/api/v1/approvals/${approvalId}/deny`)
          .send({ approverId: 'user1', approverGroup: 'default', reason: 'No' }),
      );
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('DENIED');
    });

    it('returns 400 for invalid approve body', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const res = await auth(
        request(app).post('/api/v1/approvals/123/approve').send({ approverId: '' }),
      );
      expect(res.status).toBe(400);
    });

    it('returns 400 for invalid deny body', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const res = await auth(request(app).post('/api/v1/approvals/123/deny').send({}));
      expect(res.status).toBe(400);
    });

    it('returns 500 when approve throws', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'db_query',
      });
      let approvalId = '';
      try {
        await workflow.requestApproval(ctx);
      } catch (error) {
        approvalId = (error as { approvalId: string }).approvalId;
      }

      vi.spyOn(workflow, 'approve').mockRejectedValue(new Error('DB error'));
      const res = await auth(
        request(app)
          .post(`/api/v1/approvals/${approvalId}/approve`)
          .send({ approverId: 'user1', approverGroup: 'default' }),
      );
      expect(res.status).toBe(500);
    });

    it('returns 500 when deny throws', async () => {
      const app = createApprovalApi(workflow, TEST_KEY);
      const ctx = createRequestContext({
        requestId: 'r1',
        sessionId: 's1',
        method: 'tools/call',
        toolName: 'db_query',
      });
      let approvalId = '';
      try {
        await workflow.requestApproval(ctx);
      } catch (error) {
        approvalId = (error as { approvalId: string }).approvalId;
      }

      vi.spyOn(workflow, 'deny').mockRejectedValue(new Error('DB error'));
      const res = await auth(
        request(app)
          .post(`/api/v1/approvals/${approvalId}/deny`)
          .send({ approverId: 'user1', approverGroup: 'default', reason: 'No' }),
      );
      expect(res.status).toBe(500);
    });
  });
});
