import test from 'node:test';
import assert from 'node:assert/strict';
import { requireAdminToken } from '../../src/middleware/admin-auth.js';

function mockResponse() {
  return {
    statusCode: 200, body: null, headers: {},
    set(name, value) { this.headers[name] = value; return this; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; }
  };
}

test('admin middleware rejects missing or invalid bearer token', () => {
  const middleware = requireAdminToken('a'.repeat(40));
  const res = mockResponse();
  middleware({ get: () => '' }, res, () => assert.fail('next must not run'));
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error, 'admin_auth_required');
});

test('admin middleware accepts the correct bearer token', () => {
  const token = 'secure-admin-token-that-is-at-least-32-chars';
  const middleware = requireAdminToken(token);
  const res = mockResponse();
  let nextCalled = false;
  middleware({ get: () => `Bearer ${token}` }, res, () => { nextCalled = true; });
  assert.equal(nextCalled, true);
});
