export function createPolicyGuard(policyEngine, events) {
  return async function policyGuard(req, res, next) {
    try {
      const scopes = Array.isArray(req.auth?.scopes) ? req.auth.scopes : [];
      const decision = await policyEngine.evaluate({
        ip: req.ip || req.socket?.remoteAddress || 'unknown',
        route: req.originalUrl || req.path,
        scopes
      });
      if (!decision.allowed) {
        events?.publish({
          type: 'policy_denied',
          requestId: req.requestId,
          ip: req.ip || req.socket?.remoteAddress || 'unknown',
          route: req.originalUrl || req.path,
          subject: req.auth?.subject || 'anonymous',
          metadata: { reason: decision.reason, policyId: decision.policyId || null }
        });
        return res.status(403).json({
          error: 'request_blocked_by_policy',
          message: 'The request was rejected by an API Shield security policy.',
          requestId: req.requestId
        });
      }
      req.policyDecision = decision;
      next();
    } catch (error) {
      // Fail closed: policy storage is a security control, not an optional decoration.
      return res.status(503).json({ error: 'policy_engine_unavailable', requestId: req.requestId });
    }
  };
}
