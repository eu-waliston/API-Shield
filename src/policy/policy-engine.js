import { isIP } from 'node:net';
const BLOCK_PREFIX = 'api-shield:blocked:';
const POLICY_KEY = 'api-shield:policies';

function normalizeIp(ip = '') {
  return String(ip).replace(/^::ffff:/, '').trim();
}

export function createPolicyEngine(redisClient, { defaultAction = 'allow' } = {}) {
  async function isBlocked(ip) {
    const normalized = normalizeIp(ip);
    if (!normalized) return false;
    return (await redisClient.exists(`${BLOCK_PREFIX}${normalized}`)) === 1;
  }

  async function blockIp(ip, { ttlSeconds = 900, reason = 'policy_violation', actor = 'system' } = {}) {
    const normalized = normalizeIp(ip);
    if (!normalized || isIP(normalized) === 0) throw new Error('A valid IP address is required');
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 86400) {
      throw new Error('ttlSeconds must be an integer between 1 and 86400');
    }
    const record = { ip: normalized, reason: String(reason).slice(0, 200), actor: String(actor).slice(0, 100), createdAt: new Date().toISOString() };
    await redisClient.set(`${BLOCK_PREFIX}${normalized}`, JSON.stringify(record), { EX: ttlSeconds });
    return { ...record, ttlSeconds };
  }

  async function unblockIp(ip) {
    return (await redisClient.del(`${BLOCK_PREFIX}${normalizeIp(ip)}`)) === 1;
  }

  async function getBlock(ip) {
    const normalized = normalizeIp(ip);
    const key = `${BLOCK_PREFIX}${normalized}`;
    const [raw, ttlSeconds] = await Promise.all([redisClient.get(key), redisClient.ttl(key)]);
    if (!raw || ttlSeconds < 0) return null;
    try { return { ...JSON.parse(raw), ttlSeconds }; } catch { return { ip: normalized, reason: 'unknown', ttlSeconds }; }
  }

  async function listPolicies() {
    const raw = await redisClient.get(POLICY_KEY);
    if (!raw) return [
      { id: 'default', enabled: true, action: defaultAction, match: { routePrefix: '/' }, description: 'Default gateway behavior' }
    ];
    try { return JSON.parse(raw); } catch { return []; }
  }

  async function replacePolicies(policies) {
    if (!Array.isArray(policies) || policies.length > 100) throw new Error('policies must be an array with at most 100 entries');
    const ids = new Set();
    for (const p of policies) {
      if (!p || typeof p.id !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(p.id)) throw new Error('Each policy requires a valid id');
      if (ids.has(p.id)) throw new Error(`Duplicate policy id: ${p.id}`);
      ids.add(p.id);
      if (typeof p.enabled !== 'boolean') throw new Error(`Policy ${p.id}: enabled must be boolean`);
      if (!['allow', 'deny'].includes(p.action)) throw new Error(`Policy ${p.id}: action must be allow or deny`);
      if (p.match?.routePrefix !== undefined && (typeof p.match.routePrefix !== 'string' || !p.match.routePrefix.startsWith('/') || p.match.routePrefix.length > 200)) {
        throw new Error(`Policy ${p.id}: routePrefix must be a path beginning with /`);
      }
      if (p.match?.requiredScope !== undefined && (typeof p.match.requiredScope !== 'string' || p.match.requiredScope.length > 100)) {
        throw new Error(`Policy ${p.id}: requiredScope must be a string of at most 100 characters`);
      }
      if (!p.match || (!p.match.routePrefix && !p.match.requiredScope)) throw new Error(`Policy ${p.id}: match needs routePrefix or requiredScope`);
    }
    await redisClient.set(POLICY_KEY, JSON.stringify(policies));
    return policies;
  }

  async function evaluate({ ip, route, scopes = [] }) {
    const block = await getBlock(ip);
    if (block) return { allowed: false, action: 'deny', reason: 'temporary_ip_block', block };
    const policies = await listPolicies();
    // First enabled matching rule wins; order is part of policy semantics.
    for (const policy of policies) {
      if (!policy.enabled) continue;
      const routeMatches = policy.match.routePrefix ? String(route || '/').startsWith(policy.match.routePrefix) : true;
      const scopeMatches = policy.match.requiredScope ? scopes.includes(policy.match.requiredScope) : true;
      if (routeMatches && scopeMatches) {
        return { allowed: policy.action !== 'deny', action: policy.action, reason: `policy:${policy.id}`, policyId: policy.id };
      }
    }
    return { allowed: defaultAction !== 'deny', action: defaultAction, reason: 'default_action' };
  }

  return { isBlocked, blockIp, unblockIp, getBlock, listPolicies, replacePolicies, evaluate };
}
