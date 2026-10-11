import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

const root = new URL('../../', import.meta.url);
const read = (name) => readFileSync(new URL(name, root), 'utf8');

test('Docker image uses non-root node user and production dependencies', () => {
  const dockerfile = read('Dockerfile');
  assert.match(dockerfile, /npm install --omit=dev/);
  assert.match(dockerfile, /USER node/);
  assert.match(dockerfile, /HEALTHCHECK/);
  assert.match(dockerfile, /NODE_ENV=production/);
});

test('Compose does not publish Redis and binds API to loopback by default', () => {
  const compose = read('compose.yaml');
  assert.match(compose, /127\.0\.0\.1:3000:3000/);
  assert.match(compose, /REDIS_PASSWORD/);
  assert.match(compose, /condition: service_healthy/);
  assert.doesNotMatch(compose, /6379:6379/);
});

test('Docker build context excludes secrets and tests', () => {
  const ignore = read('.dockerignore');
  assert.match(ignore, /^\.env$/m);
  assert.match(ignore, /^tests$/m);
  assert.match(ignore, /^node_modules$/m);
});
