import test from 'node:test';
import assert from 'node:assert/strict';
import { createThreatEngine, calculateRiskScore } from '../../src/security/threat-engine.js';

const config = {
  detection: {
    windowSeconds: 120,
    authFailureThreshold: 3,
    forbiddenThreshold: 3,
    rateLimitThreshold: 2,
    routeDiversityThreshold: 3,
    multiSignalThreshold: 3,
    alertDedupSeconds: 60
  }
};

function event(type, timestamp, subject = 'client-a') {
  return {
    id: `${type}-${timestamp}-${Math.random()}`,
    type,
    timestamp: new Date(timestamp).toISOString(),
    subject,
    ip: '127.0.0.1',
    route: '/api/catalog'
  };
}

test('creates an alert after authentication failure threshold', () => {
  let clock = 1_000_000;
  const engine = createThreatEngine(config, { now: () => clock });
  engine.ingest(event('auth.failure', clock));
  clock += 1000;
  engine.ingest(event('auth.failure', clock));
  clock += 1000;
  const result = engine.ingest(event('auth.failure', clock));

  assert.equal(result.alerts.length, 1);
  assert.equal(result.alerts[0].ruleId, 'AUTH_FAILURE_BURST');
  assert.equal(result.alerts[0].eventCount, 3);
  assert.ok(result.alerts[0].riskScore > 0);
});

test('deduplicates repeated alerts during suppression window', () => {
  let clock = 2_000_000;
  const engine = createThreatEngine(config, { now: () => clock });
  for (let i = 0; i < 3; i++) {
    engine.ingest(event('auth.failure', clock));
    clock += 1000;
  }
  const next = engine.ingest(event('auth.failure', clock));
  assert.equal(next.alerts.length, 0);
  assert.equal(engine.listAlerts().length, 1);
});

test('does not correlate events belonging to different subjects', () => {
  let clock = 3_000_000;
  const engine = createThreatEngine(config, { now: () => clock });
  engine.ingest(event('auth.failure', clock, 'client-a'));
  clock += 1000;
  engine.ingest(event('auth.failure', clock, 'client-b'));
  clock += 1000;
  const result = engine.ingest(event('auth.failure', clock, 'client-c'));
  assert.equal(result.alerts.length, 0);
});

test('risk score is bounded from zero to one hundred', () => {
  assert.equal(calculateRiskScore({ baseScore: 100, count: 100, threshold: 1, severity: 'critical' }), 100);
  assert.ok(calculateRiskScore({ baseScore: 10, count: 1, threshold: 5, severity: 'low' }) >= 0);
});


test('detects route diversity across security events for one identity', () => {
  let clock = 4_000_000;
  const engine = createThreatEngine(config, { now: () => clock });
  engine.ingest({ ...event('auth.failure', clock), route: '/v1/a' });
  clock += 1000;
  engine.ingest({ ...event('access.denied', clock), route: '/v1/b' });
  clock += 1000;
  const result = engine.ingest({ ...event('rate_limit.exceeded', clock), route: '/v1/c' });
  assert.ok(result.alerts.some((alert) => alert.ruleId === 'ROUTE_DIVERSITY_SPIKE'));
  const alert = result.alerts.find((item) => item.ruleId === 'ROUTE_DIVERSITY_SPIKE');
  assert.equal(alert.observedValue, 3);
  assert.equal(alert.threshold, 3);
  assert.equal(alert.detectionWindowSeconds, 120);
});

test('detects escalation when distinct security signal types accumulate', () => {
  let clock = 5_000_000;
  const engine = createThreatEngine(config, { now: () => clock });
  engine.ingest(event('auth.failure', clock));
  clock += 1000;
  engine.ingest(event('access.denied', clock));
  clock += 1000;
  const result = engine.ingest(event('rate_limit.exceeded', clock));
  assert.ok(result.alerts.some((alert) => alert.ruleId === 'MULTI_SIGNAL_ESCALATION'));
});
