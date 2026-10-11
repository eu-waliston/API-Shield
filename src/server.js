import 'dotenv/config';
import { createClient } from 'redis';
import { createApp } from './app.js';
import { loadConfig } from './config/env.js';
import { createThreatEngine } from './security/threat-engine.js';
import { createSecurityEventBus } from './security/event-bus.js';
import { createTelemetryStore } from './security/telemetry-store.js';

const config = loadConfig();
const redisClient = createClient({ url: config.redisUrl });
redisClient.on('error', (err) => console.error(JSON.stringify({
  level: 'error', event: 'redis_error', message: err.message
})));
try {
  await redisClient.connect();
} catch (error) {
  console.error(JSON.stringify({
    level: 'error', event: 'redis_connect_failed',
    message: String(error?.message || 'Redis connection failed').replace(/[\\r\\n\\t]/g, ' ').slice(0, 300)
  }));
  process.exit(1);
}

const telemetryStore = createTelemetryStore(redisClient, {
  eventRetention: config.eventRetention,
  alertRetention: config.alertRetention
});

const threatEngine = createThreatEngine(config, {
  onAlert: (alert) => {
    console.warn(JSON.stringify({
      level: 'warn', event: 'security_alert', alertId: alert.id, ruleId: alert.ruleId,
      severity: alert.severity, riskScore: alert.riskScore, riskLevel: alert.riskLevel,
      reason: alert.reason, subject: alert.subject, ip: alert.ip, eventCount: alert.eventCount
    }));
    telemetryStore.saveAlert(alert).catch((error) => console.error(JSON.stringify({
      level: 'error', event: 'security_alert_persist_failed', message: error.message
    })));
  }
});

const events = createSecurityEventBus(threatEngine, console, telemetryStore);
const app = createApp(config, { redisClient, events, threatEngine, telemetryStore });
const server = app.listen(config.port, config.host, () => console.log(JSON.stringify({
  level: 'info', event: 'server_started', service: 'api-shield', host: config.host,
  port: config.port, environment: config.nodeEnv
})));

let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(JSON.stringify({ level: 'info', event: 'shutdown_started', signal }));
  server.close(async (error) => {
    try { if (redisClient.isOpen) await redisClient.quit(); } catch (closeError) {
      console.error(JSON.stringify({
        level: 'error', event: 'redis_shutdown_failed',
        message: String(closeError?.message || 'Redis shutdown failed').replace(/[\\r\\n\\t]/g, ' ').slice(0, 300)
      }));
    }
    if (error) {
      console.error(JSON.stringify({ level: 'error', event: 'shutdown_failed', message: error.message }));
      process.exit(1);
    }
    process.exit(0);
  });
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
