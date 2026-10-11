import { createProxyMiddleware } from 'http-proxy-middleware';

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function createServiceProxy(route, timeoutMs, events) {
  return createProxyMiddleware({
    target: route.upstreamUrl,
    changeOrigin: true,
    xfwd: true,
    proxyTimeout: timeoutMs,
    timeout: timeoutMs,
    pathRewrite: (path) => {
      const rewritten = path.replace(new RegExp(`^${escapeRegExp(route.publicPrefix)}`), route.upstreamPathPrefix);
      return rewritten || '/';
    },
    on: {
      proxyReq(proxyReq, req) {
        proxyReq.setHeader('x-request-id', req.requestId);
      },
      error(err, req, res) {
        try {
          events?.publish({
            type: 'upstream.error',
            requestId: req.requestId,
            subject: req.auth?.subject,
            ip: req.ip,
            route: req.baseUrl || req.path,
            metadata: { reason: err.code || 'proxy_error' }
          });
        } catch {}

        if (res.headersSent) return res.destroy();
        const unavailable = ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND'].includes(err.code);
        res.writeHead(unavailable ? 502 : 500, {
          'content-type': 'application/json',
          'x-request-id': req.requestId || 'unknown'
        });
        res.end(JSON.stringify({
          error: {
            code: unavailable ? 'UPSTREAM_UNAVAILABLE' : 'PROXY_ERROR',
            message: unavailable ? 'Upstream service is unavailable' : 'Request could not be proxied',
            requestId: req.requestId || null
          }
        }));
      }
    }
  });
}
