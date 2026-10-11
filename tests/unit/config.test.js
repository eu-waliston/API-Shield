import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../../src/config/env.js';

const base = {
  JWT_SECRET: 'j'.repeat(40),
  ADMIN_API_TOKEN: 'a'.repeat(40)
};

test('loads safe defaults with sufficiently strong secrets', () => {
  const config = loadConfig(base);
  assert.equal(config.port, 3000);
  assert.equal(config.services.catalog, 'http://127.0.0.1:4001');
});

test('rejects short JWT and admin secrets', () => {
  assert.throws(() => loadConfig({ ...base, JWT_SECRET: 'short' }), /JWT_SECRET/);
  assert.throws(() => loadConfig({ ...base, ADMIN_API_TOKEN: 'short' }), /ADMIN_API_TOKEN/);
});

test('rejects upstream protocols other than HTTP(S)', () => {
  assert.throws(() => loadConfig({ ...base, CATALOG_SERVICE_URL: 'file:///etc/passwd' }), /HTTP or HTTPS/);
});

test('rejects upstream credentials, query strings and fragments', () => {
  assert.throws(() => loadConfig({ ...base, CATALOG_SERVICE_URL: 'https://user:pass@example.test' }), /embedded credentials/);
  assert.throws(() => loadConfig({ ...base, CATALOG_SERVICE_URL: 'https://example.test/?token=secret' }), /query string or fragment/);
  assert.throws(() => loadConfig({ ...base, CATALOG_SERVICE_URL: 'https://example.test/#frag' }), /query string or fragment/);
});

test('rejects invalid positive-integer configuration', () => {
  assert.throws(() => loadConfig({ ...base, PORT: '0' }), /PORT must be a positive integer/);
  assert.throws(() => loadConfig({ ...base, RATE_LIMIT_MAX_REQUESTS: '-1' }), /RATE_LIMIT_MAX_REQUESTS must be a positive integer/);
});
