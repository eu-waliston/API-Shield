import { createSecurityEvent } from './events.js';

export function createSecurityEventBus(threatEngine, logger = console, telemetryStore = null) {
  return {
    publish(input) {
      const event = createSecurityEvent(input);
      logger.info?.(JSON.stringify({
        level: 'info', event: 'security_event', securityEventId: event.id,
        type: event.type, requestId: event.requestId, route: event.route, metadata: event.metadata
      }));
      // Detection remains synchronous; persistence is best-effort and errors are visible in logs.
      const result = threatEngine.ingest(event);
      if (telemetryStore) {
        telemetryStore.saveEvent(event).catch((error) => logger.error?.(JSON.stringify({
          level: 'error', event: 'security_event_persist_failed', message: error.message
        })));
      }
      return result;
    }
  };
}
