export function attachRequestContext(req, _res, next) {
  req.auth = req.auth || {};
  next();
}
