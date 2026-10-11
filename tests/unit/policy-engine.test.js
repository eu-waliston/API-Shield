import test from 'node:test';
import assert from 'node:assert/strict';
import { createPolicyEngine } from '../../src/policy/policy-engine.js';

function fakeRedis() {
  const values = new Map();
  return {
    async exists(k) { return values.has(k) ? 1 : 0; },
    async set(k, v, opts = {}) { values.set(k, v); return 'OK'; },
    async get(k) { return values.get(k) ?? null; },
    async del(k) { return values.delete(k) ? 1 : 0; },
    async ttl(k) { return values.has(k) ? 60 : -2; }
  };
}

test('temporary block denies a client and can be removed', async () => {
  const engine = createPolicyEngine(fakeRedis());
  await engine.blockIp('203.0.113.4', { ttlSeconds: 60, reason: 'test' });
  assert.equal((await engine.evaluate({ ip: '203.0.113.4', route: '/v1/items' })).allowed, false);
  assert.equal(await engine.unblockIp('203.0.113.4'), true);
  assert.equal((await engine.evaluate({ ip: '203.0.113.4', route: '/v1/items' })).allowed, true);
});

test('first enabled matching policy wins', async () => {
  const engine = createPolicyEngine(fakeRedis());
  await engine.replacePolicies([
    { id: 'deny-admin', enabled: true, action: 'deny', match: { routePrefix: '/v1/admin' } },
    { id: 'allow-api', enabled: true, action: 'allow', match: { routePrefix: '/v1' } }
  ]);
  assert.equal((await engine.evaluate({ ip: '198.51.100.2', route: '/v1/admin/users' })).allowed, false);
  assert.equal((await engine.evaluate({ ip: '198.51.100.2', route: '/v1/items' })).allowed, true);
});

test('policy validation rejects duplicate ids and malformed routes', async () => {
  const engine = createPolicyEngine(fakeRedis());
  await assert.rejects(() => engine.replacePolicies([
    { id: 'same', enabled: true, action: 'deny', match: { routePrefix: '/' } },
    { id: 'same', enabled: true, action: 'allow', match: { routePrefix: '/v1' } }
  ]), /Duplicate policy id/);
  await assert.rejects(() => engine.replacePolicies([
    { id: 'bad', enabled: true, action: 'deny', match: { routePrefix: 'v1' } }
  ]), /routePrefix/);
});

test('blockIp rejects malformed IP addresses', async () => {
  const engine = createPolicyEngine(fakeRedis());
  await assert.rejects(() => engine.blockIp('not-an-ip', { ttlSeconds: 60 }), /valid IP address/);
  await assert.rejects(() => engine.blockIp('127.0.0.1;FLUSHALL', { ttlSeconds: 60 }), /valid IP address/);
});

test('blockIp accepts IPv4 and IPv6 addresses', async () => {
  const engine = createPolicyEngine(fakeRedis());
  assert.equal((await engine.blockIp('203.0.113.9', { ttlSeconds: 60 })).ip, '203.0.113.9');
  assert.equal((await engine.blockIp('2001:db8::1', { ttlSeconds: 60 })).ip, '2001:db8::1');
});
