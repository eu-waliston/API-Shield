import { randomUUID } from 'node:crypto';
const SAFE_REQUEST_ID = /^[a-zA-Z0-9._:-]{1,100}$/;
export function requestId(req, res, next) {
  const supplied = req.get('x-request-id');
  const id = supplied && SAFE_REQUEST_ID.test(supplied) ? supplied : randomUUID();
  req.requestId = id;
  res.setHeader('x-request-id', id);
  next();
}
