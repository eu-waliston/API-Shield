import { timingSafeEqual } from 'node:crypto';

export function requireAdminToken(expectedToken) {
  return function adminAuth(req, res, next) {
    const header = req.get('authorization') || '';
    const match = /^Bearer\s+(.+)$/i.exec(header);
    const supplied = match?.[1] || '';
    const a = Buffer.from(supplied);
    const b = Buffer.from(expectedToken);
    const valid = a.length === b.length && timingSafeEqual(a, b);
    if (!valid) {
      res.set('WWW-Authenticate', 'Bearer realm="api-shield-admin"');
      return res.status(401).json({ error: 'admin_auth_required', message: 'A valid admin bearer token is required.' });
    }
    next();
  };
}
