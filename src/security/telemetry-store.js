const EVENTS_KEY = 'api-shield:security:events';
const ALERTS_KEY = 'api-shield:security:alerts';

export function createTelemetryStore(redisClient, { eventRetention = 5000, alertRetention = 1000 } = {}) {
  async function append(key, item, limit) {
    await redisClient.rPush(key, JSON.stringify(item));
    await redisClient.lTrim(key, -limit, -1);
  }

  async function read(key, limit = 100) {
    const safeLimit = Math.max(1, Math.min(Number.parseInt(limit, 10) || 100, 500));
    const rows = await redisClient.lRange(key, -safeLimit, -1);
    return rows.map((row) => {
      try { return JSON.parse(row); } catch { return null; }
    }).filter(Boolean).reverse();
  }

  return {
    saveEvent: (event) => append(EVENTS_KEY, event, eventRetention),
    saveAlert: (alert) => append(ALERTS_KEY, alert, alertRetention),
    listEvents: (limit) => read(EVENTS_KEY, limit),
    listAlerts: (limit) => read(ALERTS_KEY, limit),
    async getStats() {
      const [events, alerts] = await Promise.all([
        redisClient.lLen(EVENTS_KEY),
        redisClient.lRange(ALERTS_KEY, 0, -1)
      ]);
      const parsed = alerts.map((raw) => { try { return JSON.parse(raw); } catch { return null; } }).filter(Boolean);
      return {
        storedEvents: events,
        storedAlerts: parsed.length,
        openAlerts: parsed.filter((alert) => alert.status === 'open').length,
        criticalAlerts: parsed.filter((alert) => alert.riskLevel === 'critical' && alert.status === 'open').length
      };
    },
    async updateAlertStatus(id, status) {
      const rows = await redisClient.lRange(ALERTS_KEY, 0, -1);
      let updated = null;
      const rewritten = rows.map((raw) => {
        let alert;
        try { alert = JSON.parse(raw); } catch { return raw; }
        if (alert.id === id) {
          alert.status = status;
          alert.updatedAt = new Date().toISOString();
          updated = alert;
        }
        return JSON.stringify(alert);
      });
      if (updated) {
        const multi = redisClient.multi();
        multi.del(ALERTS_KEY);
        if (rewritten.length) multi.rPush(ALERTS_KEY, rewritten);
        multi.lTrim(ALERTS_KEY, -alertRetention, -1);
        await multi.exec();
      }
      return updated;
    }
  };
}
