import { randomUUID } from 'node:crypto';

const ALLOWED_TYPES = new Set([
  'auth.failure',
  'auth.success',
  'access.denied',
  'rate_limit.exceeded',
  'upstream.error',
  'request.validation_failed'
]);

/**
 * Events intentionally exclude tokens, cookies, bodies, and authorization headers.
 * Keep this schema narrow to reduce accidental collection of sensitive data.
 */
export function createSecurityEvent({ type, requestId, subject, ip, route, metadata = {} }) {
  if (!ALLOWED_TYPES.has(type)) throw new Error(`Unsupported security event type: ${type}`);

  return {
    id: randomUUID(),
    type,
    timestamp: new Date().toISOString(),
    requestId: safeString(requestId, 100),
    subject: safeString(subject, 128),
    ip: safeString(ip, 64),
    route: safeString(route, 160),
    metadata: sanitizeMetadata(metadata)
  };
}

function safeString(value, maxLength) {
  if (typeof value !== 'string') return undefined;
  return value.slice(0, maxLength);
}

function sanitizeMetadata(metadata) {
  const safe = {};
  for (const key of ['reason', 'statusCode', 'count', 'threshold', 'windowSeconds']) {
    const value = metadata?.[key];
    if (typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value))) {
      safe[key] = typeof value === 'string' ? value.slice(0, 120) : value;
    }
  }
  return safe;
}
