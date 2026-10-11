import { randomUUID } from 'node:crypto';

const RULES = [
  {
    id: 'AUTH_FAILURE_BURST',
    eventType: 'auth.failure',
    severity: 'high',
    baseScore: 35,
    reason: 'Repeated authentication failures within the detection window.'
  },
  {
    id: 'FORBIDDEN_BURST',
    eventType: 'access.denied',
    severity: 'medium',
    baseScore: 25,
    reason: 'Repeated authorization denials within the detection window.'
  },
  {
    id: 'RATE_LIMIT_BURST',
    eventType: 'rate_limit.exceeded',
    severity: 'medium',
    baseScore: 20,
    reason: 'Repeated rate-limit violations within the detection window.'
  },
  {
    id: 'ROUTE_DIVERSITY_SPIKE',
    eventType: '*',
    severity: 'medium',
    baseScore: 30,
    reason: 'One identity generated security events across an unusually large number of routes.'
  },
  {
    id: 'MULTI_SIGNAL_ESCALATION',
    eventType: '*',
    severity: 'high',
    baseScore: 40,
    reason: 'Multiple distinct security signal types were observed for the same identity.'
  }
];

export function createThreatEngine(config, { now = () => Date.now(), onAlert = () => {} } = {}) {
  const events = [];
  const alerts = [];
  const dedup = new Map();

  function ingest(event) {
    const currentTime = now();
    const windowMs = config.detection.windowSeconds * 1000;
    events.push(event);
    prune(currentTime, windowMs);

    const matched = [];
    for (const rule of RULES) {
      if (rule.eventType !== '*' && rule.eventType !== event.type) continue;

      const identity = event.subject || event.ip || 'unknown';
      const relevant = events.filter((candidate) =>
        (rule.eventType === '*' || candidate.type === rule.eventType) &&
        (candidate.subject || candidate.ip || 'unknown') === identity &&
        currentTime - Date.parse(candidate.timestamp) <= windowMs
      );

      const threshold = thresholdFor(rule.id, config.detection);
      const signalValue = rule.id === 'ROUTE_DIVERSITY_SPIKE'
        ? new Set(relevant.map((item) => item.route).filter(Boolean)).size
        : rule.id === 'MULTI_SIGNAL_ESCALATION'
          ? new Set(relevant.map((item) => item.type)).size
          : relevant.length;
      if (signalValue >= threshold) {
        const alert = buildAlert(rule, event, relevant, threshold, config.detection.alertDedupSeconds, config.detection.windowSeconds, currentTime);
        if (alert && !isDuplicate(alert, currentTime)) {
          alerts.push(alert);
          dedup.set(alert.dedupKey, currentTime);
          onAlert(alert);
          matched.push(alert);
        }
      }
    }
    return { event, alerts: matched };
  }

  function prune(currentTime, windowMs) {
    while (events.length && currentTime - Date.parse(events[0].timestamp) > windowMs) events.shift();
    for (const [key, timestamp] of dedup.entries()) {
      if (currentTime - timestamp > config.detection.alertDedupSeconds * 1000) dedup.delete(key);
    }
  }

  function isDuplicate(alert, currentTime) {
    const last = dedup.get(alert.dedupKey);
    return last !== undefined && currentTime - last <= config.detection.alertDedupSeconds * 1000;
  }

  function buildAlert(rule, event, relatedEvents, threshold, dedupSeconds, windowSeconds, currentTime) {
    const riskScore = calculateRiskScore({
      baseScore: rule.baseScore,
      count: relatedEvents.length,
      threshold,
      severity: rule.severity
    });
    const identity = event.subject || event.ip || 'unknown';
    return {
      id: randomUUID(),
      ruleId: rule.id,
      title: rule.id.replaceAll('_', ' '),
      severity: rule.severity,
      riskScore,
      riskLevel: riskLevel(riskScore),
      reason: rule.reason,
      subject: event.subject,
      ip: event.ip,
      route: event.route,
      firstSeen: relatedEvents[0]?.timestamp,
      lastSeen: event.timestamp,
      eventCount: relatedEvents.length,
      observedValue: rule.id === 'ROUTE_DIVERSITY_SPIKE'
        ? new Set(relatedEvents.map((item) => item.route).filter(Boolean)).size
        : rule.id === 'MULTI_SIGNAL_ESCALATION'
          ? new Set(relatedEvents.map((item) => item.type)).size
          : relatedEvents.length,
      threshold,
      detectionWindowSeconds: windowSeconds,
      evidenceEventIds: relatedEvents.slice(-20).map((item) => item.id),
      status: 'open',
      dedupKey: `${rule.id}:${identity}`,
      dedupSeconds,
      createdAt: new Date(currentTime).toISOString()
    };
  }

  return {
    ingest,
    listAlerts: () => alerts.map(({ dedupKey, dedupSeconds, ...publicAlert }) => publicAlert),
    listRecentEvents: (limit = 100) => events.slice(-Math.max(1, Math.min(limit, 500))),
    getStats: () => ({
      eventsInWindow: events.length,
      openAlerts: alerts.filter((alert) => alert.status === 'open').length
    })
  };
}

function thresholdFor(ruleId, detection) {
  if (ruleId === 'AUTH_FAILURE_BURST') return detection.authFailureThreshold;
  if (ruleId === 'FORBIDDEN_BURST') return detection.forbiddenThreshold;
  if (ruleId === 'ROUTE_DIVERSITY_SPIKE') return detection.routeDiversityThreshold ?? 6;
  if (ruleId === 'MULTI_SIGNAL_ESCALATION') return detection.multiSignalThreshold ?? 3;
  return detection.rateLimitThreshold;
}

export function calculateRiskScore({ baseScore, count, threshold, severity }) {
  const severityWeight = severity === 'high' ? 1.25 : severity === 'critical' ? 1.5 : 1;
  const volumeBonus = Math.min(25, Math.max(0, count - threshold) * 5);
  return Math.max(0, Math.min(100, Math.round(baseScore * severityWeight + volumeBonus)));
}

function riskLevel(score) {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}
