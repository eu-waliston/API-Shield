import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import { requestId } from './middleware/request-id.js';
import { errorHandler, notFoundHandler } from './middleware/error-handler.js';
import { requireAdminToken } from './middleware/admin-auth.js';
import { createPolicyEngine } from './policy/policy-engine.js';
import { createPolicyGuard } from './middleware/policy-guard.js';
import { authenticate, requireScope } from './auth/authenticate.js';
import { createRateLimiter } from './rate-limit/rate-limiter.js';
import { createRouteRegistry } from './gateway/route-registry.js';
import { createServiceProxy } from './gateway/proxy.js';

const here = path.dirname(fileURLToPath(import.meta.url));

export function createApp(config, { redisClient, events, threatEngine, telemetryStore } = {}) {
  if (!redisClient) throw new Error('A connected Redis client is required');
  if (!telemetryStore) throw new Error('A telemetry store is required');

  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(requestId);

  app.get('/health', async (_req, res) => {
    try {
      await redisClient.ping();
      res.status(200).json({ status: 'ok', service: 'api-shield', dependencies: { redis: 'ok' }, timestamp: new Date().toISOString() });
    } catch {
      res.status(503).json({ status: 'degraded', service: 'api-shield', dependencies: { redis: 'error' } });
    }
  });

  app.use('/dashboard', express.static(path.join(here, '..', 'public'), { index: 'index.html', etag: true, maxAge: '5m' }));

  // Administrative/security responses can contain sensitive telemetry and policy data.
  app.use('/internal', (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    next();
  });

  const admin = requireAdminToken(config.adminToken);
  const policyEngine = createPolicyEngine(redisClient);

  app.get('/internal/security/stats', admin, async (_req, res, next) => {
    try { res.json(await telemetryStore.getStats()); } catch (error) { next(error); }
  });
  app.get('/internal/security/alerts', admin, async (req, res, next) => {
    try { res.json({ alerts: await telemetryStore.listAlerts(req.query.limit) }); } catch (error) { next(error); }
  });
  app.get('/internal/security/events', admin, async (req, res, next) => {
    try { res.json({ events: await telemetryStore.listEvents(req.query.limit) }); } catch (error) { next(error); }
  });
  app.patch('/internal/security/alerts/:id', admin, express.json({ limit: '2kb' }), async (req, res, next) => {
    try {
      const status = req.body?.status;
      if (!['open', 'investigating', 'resolved'].includes(status)) return res.status(400).json({ error: 'invalid_status', allowed: ['open', 'investigating', 'resolved'] });
      const alert = await telemetryStore.updateAlertStatus(req.params.id, status);
      if (!alert) return res.status(404).json({ error: 'alert_not_found' });
      res.json({ alert });
    } catch (error) { next(error); }
  });

  app.get('/internal/policies', admin, async (_req, res, next) => {
    try { res.json({ policies: await policyEngine.listPolicies() }); } catch (error) { next(error); }
  });
  app.put('/internal/policies', admin, express.json({ limit: '32kb' }), async (req, res, next) => {
    try {
      const policies = await policyEngine.replacePolicies(req.body?.policies);
      res.json({ policies });
    } catch (error) {
      if (/must be|requires|Duplicate|needs/.test(error.message)) return res.status(400).json({ error: 'invalid_policy', message: error.message });
      next(error);
    }
  });
  app.get('/internal/policies/blocks/:ip', admin, async (req, res, next) => {
    try {
      const block = await policyEngine.getBlock(req.params.ip);
      if (!block) return res.status(404).json({ error: 'block_not_found' });
      res.json({ block });
    } catch (error) { next(error); }
  });
  app.post('/internal/policies/blocks', admin, express.json({ limit: '4kb' }), async (req, res, next) => {
    try {
      const { ip, ttlSeconds = 900, reason = 'manual_admin_block' } = req.body || {};
      if (typeof ip !== 'string' || !ip.trim()) return res.status(400).json({ error: 'invalid_ip' });
      const block = await policyEngine.blockIp(ip, { ttlSeconds, reason, actor: 'admin' });
      res.status(201).json({ block });
    } catch (error) {
      if (/required|ttlSeconds/.test(error.message)) return res.status(400).json({ error: 'invalid_block', message: error.message });
      next(error);
    }
  });
  app.delete('/internal/policies/blocks/:ip', admin, async (req, res, next) => {
    try {
      const removed = await policyEngine.unblockIp(req.params.ip);
      res.json({ removed });
    } catch (error) { next(error); }
  });

  const auth = authenticate(config, events);
  const policyGuard = createPolicyGuard(policyEngine, events);
  const rateLimit = createRateLimiter({
    redisClient, events, windowSeconds: config.rateLimit.windowSeconds, maxRequests: config.rateLimit.maxRequests
  });
  for (const route of createRouteRegistry(config)) {
    app.use(route.publicPrefix, auth, requireScope(route.requiredScope, events), policyGuard, rateLimit,
      createServiceProxy(route, config.requestTimeoutMs, events));
  }

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}
