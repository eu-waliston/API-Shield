import test from 'node:test';
import assert from 'node:assert/strict';
import { requestId } from '../../src/middleware/request-id.js';

function response() {
  return { headers: {}, setHeader(name, value) { this.headers[name] = value; } };
}

test('accepts a safe request id and returns it in the response header', () => {
  const req = { get: () => 'trace-123:abc' };
  const res = response();
  requestId(req, res, () => {});
  assert.equal(req.requestId, 'trace-123:abc');
  assert.equal(res.headers['x-request-id'], 'trace-123:abc');
});

test('replaces request ids containing unsafe characters', () => {
  const req = { get: () => 'trace\r\ninjected' };
  const res = response();
  requestId(req, res, () => {});
  assert.notEqual(req.requestId, 'trace\r\ninjected');
  assert.match(req.requestId, /^[0-9a-f-]{36}$/i);
});
