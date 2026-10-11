import jwt from 'jsonwebtoken';

function emit(events, req, type, reason) {
  try {
    events?.publish({
      type,
      requestId: req.requestId,
      ip: req.ip,
      route: req.baseUrl || req.path,
      metadata: { reason }
    });
  } catch {
    // Security telemetry must not leak exceptions to clients or break auth handling.
  }
}

function unauthorized(res, req, code = 'UNAUTHORIZED') {
  return res.status(401).json({
    error: { code, message: 'Valid bearer token required', requestId: req.requestId }
  });
}

export function authenticate(config, events) {
  return (req, res, next) => {
    const header = req.get('authorization') || '';
    const match = /^Bearer ([^\s]+)$/i.exec(header);
    if (!match) {
      emit(events, req, 'auth.failure', 'missing_or_malformed_bearer');
      return unauthorized(res, req);
    }

    try {
      const claims = jwt.verify(match[1], config.jwt.secret, {
        algorithms: ['HS256'],
        issuer: config.jwt.issuer,
        audience: config.jwt.audience
      });

      if (typeof claims.sub !== 'string' || claims.sub.trim() === '') {
        emit(events, req, 'auth.failure', 'missing_subject');
        return unauthorized(res, req, 'INVALID_TOKEN');
      }

      req.auth = {
        subject: claims.sub,
        scopes: typeof claims.scope === 'string' ? claims.scope.split(/\s+/).filter(Boolean) : []
      };
      return next();
    } catch {
      emit(events, req, 'auth.failure', 'invalid_token');
      return unauthorized(res, req, 'INVALID_TOKEN');
    }
  };
}

export function requireScope(requiredScope, events) {
  return (req, res, next) => {
    if (!req.auth || !req.auth.scopes.includes(requiredScope)) {
      try {
        events?.publish({
          type: 'access.denied',
          requestId: req.requestId,
          subject: req.auth?.subject,
          ip: req.ip,
          route: req.baseUrl || req.path,
          metadata: { reason: 'missing_required_scope', statusCode: 403 }
        });
      } catch {}
      return res.status(403).json({
        error: { code: 'FORBIDDEN', message: 'Insufficient permissions', requestId: req.requestId }
      });
    }
    return next();
  };
}
