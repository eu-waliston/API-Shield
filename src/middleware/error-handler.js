export function notFoundHandler(req, res) {
  res.status(404).json({ error: { code: 'ROUTE_NOT_FOUND', message: 'Route not found', requestId: req.requestId } });
}

export function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);
  const safeMessage = String(err?.message || 'Unknown error')
    .replace(/[\r\n\t]/g, ' ')
    .slice(0, 300);
  console.error(JSON.stringify({
    level: 'error', event: 'request_error', requestId: req.requestId,
    method: req.method, path: req.path, message: safeMessage
  }));
  const status = Number.isInteger(err?.status) && err.status >= 400 && err.status <= 599 ? err.status : 500;
  res.status(status).json({
    error: {
      code: status < 500 ? 'REQUEST_ERROR' : 'INTERNAL_ERROR',
      message: status < 500 ? 'Request could not be processed' : 'Internal server error',
      requestId: req.requestId
    }
  });
}
