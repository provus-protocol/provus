/**
 * @provus/node — config.ts
 *
 * Edge node configuration.
 *
 * Every Edge node has:
 *   - Its own operator identity (keypair)
 *   - A designated Relay node endpoint
 *   - A local SQLite database path
 *   - Heartbeat and queue settings
 *
 * Configuration is loaded from environment variables with sensible defaults.
 * In production: use a config file or secrets manager.
 */

export interface EdgeNodeConfig {
  /** This node's operator identifier */
  operatorId: string;

  /** HTTP port this Edge node listens on */
  port: number;

  /** Host to bind to */
  host: string;

  /** Designated Relay node endpoint */
  relayEndpoint: string;

  /** Path to the local SQLite database */
  dbPath: string;

  /**
   * Heartbeat interval in milliseconds.
   * TSD §6.5: Edge → Relay heartbeat every 30 seconds.
   */
  heartbeatIntervalMs: number;

  /**
   * Maximum age of a queued submission before it is
   * marked as submission-failed. TSD §6.4:
   * "Records that exceed the age limit without successful
   * submission are flagged as submission-failed."
   */
  queueMaxAgeMs: number;

  /**
   * Maximum number of records in the submission queue.
   * When exceeded, oldest records are dropped.
   */
  queueMaxDepth: number;

  /**
   * Default TTL for cached trust query results, in seconds.
   * Relying parties can override per query.
   */
  cacheTtlSeconds: number;

  /**
   * How many consecutive missed heartbeats before
   * marking the Relay as degraded.
   * TSD §6.5: 3 missed = degraded, 5 missed = offline.
   */
  heartbeatDegradedThreshold: number;
  heartbeatOfflineThreshold: number;
}

export function loadConfig(): EdgeNodeConfig {
  return {
    operatorId: process.env.OPERATOR_ID ?? "edge-operator-default",
    port: Number(process.env.PORT ?? 3100),
    host: process.env.HOST ?? "0.0.0.0",
    relayEndpoint: process.env.RELAY_ENDPOINT ?? "http://localhost:3200",
    dbPath: process.env.DB_PATH ?? "./provus-edge.db",
    heartbeatIntervalMs: Number(process.env.HEARTBEAT_INTERVAL_MS ?? 30_000),
    queueMaxAgeMs: Number(process.env.QUEUE_MAX_AGE_MS ?? 24 * 60 * 60 * 1000), // 24h
    queueMaxDepth: Number(process.env.QUEUE_MAX_DEPTH ?? 1000),
    cacheTtlSeconds: Number(process.env.CACHE_TTL_SECONDS ?? 300), // 5 minutes
    heartbeatDegradedThreshold: 3,
    heartbeatOfflineThreshold: 5,
  };
}
