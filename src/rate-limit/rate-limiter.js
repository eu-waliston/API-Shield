const INCREMENT_WITH_TTL = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('TTL', KEYS[1])
return { count, ttl }
`;

export function createRateLimiter({ redisClient, windowSeconds, maxRequests, events }) {
  return async (req, res, next) => {
    const subject = req.auth?.subject;
    if (!subject) {
      return res.status(401).json({
        error: { code: 'UNAUTHORIZED', message: 'Authentication required', requestId: req.requestId }
      });
    }

    const keyPart = Buffer.from(subject).toString('base64url');
    const key = `api-shield:rate:${keyPart}`;

    try {
      const result = await redisClient.eval(INCREMENT_WITH_TTL, {
        keys: [key],
        arguments: [String(windowSeconds)]
      });
      const count = Number(result[0]);
      const ttl = Math.max(Number(result[1]), 0);

      res.setHeader('RateLimit-Limit', String(maxRequests));
      res.setHeader('RateLimit-Remaining', String(Math.max(maxRequests - count, 0)));
      res.setHeader('RateLimit-Reset', String(ttl));

      if (count > maxRequests) {
        res.setHeader('Retry-After', String(ttl || windowSeconds));
        try {
          events?.publish({
            type: 'rate_limit.exceeded',
            requestId: req.requestId,
            subject,
            ip: req.ip,
            route: req.baseUrl || req.path,
            metadata: { count, threshold: maxRequests, windowSeconds }
          });
        } catch {}
        return res.status(429).json({
          error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Request quota exceeded', requestId: req.requestId }
        });
      }

      return next();
    } catch {
      return res.status(503).json({
        error: { code: 'RATE_LIMITER_UNAVAILABLE', message: 'Request cannot be processed safely right now', requestId: req.requestId }
      });
    }
  };
}
