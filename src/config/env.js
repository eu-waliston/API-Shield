function positiveInteger(value, fallback, name) {
  if (value === undefined || value === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

function trustedServiceUrl(value, name) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error(`${name} must be a valid URL`); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error(`${name} must use HTTP or HTTPS`);
  if (parsed.username || parsed.password) throw new Error(`${name} must not contain embedded credentials`);
  if (parsed.search || parsed.hash) throw new Error(`${name} must not contain a query string or fragment`);
  return parsed.toString().replace(/\/$/, '');
}

export function loadConfig(env = process.env) {
  const jwtSecret = env.JWT_SECRET || '';
  if (jwtSecret.length < 32) throw new Error('JWT_SECRET must contain at least 32 characters');
  const adminToken = env.ADMIN_API_TOKEN || '';
  if (adminToken.length < 32) throw new Error('ADMIN_API_TOKEN must contain at least 32 characters');

  return {
    nodeEnv: env.NODE_ENV || 'development',
    host: env.HOST || '127.0.0.1',
    port: positiveInteger(env.PORT, 3000, 'PORT'),
    requestTimeoutMs: positiveInteger(env.REQUEST_TIMEOUT_MS, 5000, 'REQUEST_TIMEOUT_MS'),
    jwt: { secret: jwtSecret, issuer: env.JWT_ISSUER || 'api-shield', audience: env.JWT_AUDIENCE || 'api-shield-clients' },
    adminToken,
    redisUrl: env.REDIS_URL || 'redis://127.0.0.1:6379',
    eventRetention: positiveInteger(env.SECURITY_EVENT_RETENTION, 5000, 'SECURITY_EVENT_RETENTION'),
    alertRetention: positiveInteger(env.SECURITY_ALERT_RETENTION, 1000, 'SECURITY_ALERT_RETENTION'),
    rateLimit: {
      windowSeconds: positiveInteger(env.RATE_LIMIT_WINDOW_SECONDS, 60, 'RATE_LIMIT_WINDOW_SECONDS'),
      maxRequests: positiveInteger(env.RATE_LIMIT_MAX_REQUESTS, 60, 'RATE_LIMIT_MAX_REQUESTS')
    },
    detection: {
      windowSeconds: positiveInteger(env.DETECTION_WINDOW_SECONDS, 120, 'DETECTION_WINDOW_SECONDS'),
      authFailureThreshold: positiveInteger(env.AUTH_FAILURE_THRESHOLD, 5, 'AUTH_FAILURE_THRESHOLD'),
      forbiddenThreshold: positiveInteger(env.FORBIDDEN_THRESHOLD, 5, 'FORBIDDEN_THRESHOLD'),
      rateLimitThreshold: positiveInteger(env.RATE_LIMIT_THRESHOLD, 3, 'RATE_LIMIT_THRESHOLD'),
      routeDiversityThreshold: positiveInteger(env.ROUTE_DIVERSITY_THRESHOLD, 6, 'ROUTE_DIVERSITY_THRESHOLD'),
      multiSignalThreshold: positiveInteger(env.MULTI_SIGNAL_THRESHOLD, 3, 'MULTI_SIGNAL_THRESHOLD'),
      alertDedupSeconds: positiveInteger(env.ALERT_DEDUP_SECONDS, 300, 'ALERT_DEDUP_SECONDS')
    },
    services: { catalog: trustedServiceUrl(env.CATALOG_SERVICE_URL || 'http://127.0.0.1:4001', 'CATALOG_SERVICE_URL') }
  };
}
