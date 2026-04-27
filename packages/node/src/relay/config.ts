/**
 * @provus/node — relay/config.ts
 *
 * Relay node configuration. TSD §6.1.
 *
 * A Relay node is operated by a Tier 1 institutional attester.
 * It holds a domain-scoped record store, serves query traffic,
 * and propagates records upward to Anchor nodes and laterally
 * to peer Relay nodes in the same domain.
 */

import type { Domain } from "@provus/core";

export interface RelayNodeConfig {
  /** Operator identifier — must be a credentialed Tier 1 attester */
  operatorId: string;

  /** HTTP port */
  port: number;

  /** Host */
  host: string;

  /**
   * Domain this Relay is credentialed for.
   * TSD §5.6: A Tier 1 attester's authority is domain-bound.
   * A Relay cannot serve attestation records outside this domain
   * with Tier 1 weight.
   */
  domain: Domain;

  /** Path to SQLite database */
  dbPath: string;

  /**
   * Anchor node endpoints.
   * TSD §6.2: Relay → Anchor propagation target < 5 seconds.
   * Multiple anchors for quorum — records sent to all.
   */
  anchorEndpoints: string[];

  /**
   * Peer Relay endpoints in the same domain.
   * TSD §6.2: Relay → Relay lateral propagation target < 2 seconds.
   */
  peerRelayEndpoints: string[];

  /**
   * Heartbeat interval for Edge → Relay monitoring.
   * TSD §6.5: Relay monitors Edge nodes via heartbeat.
   */
  heartbeatIntervalMs: number;

  /**
   * Maximum age of a record before it's considered stale
   * for query purposes, in seconds.
   */
  maxRecordAgeSeconds: number;

  /**
   * High-severity revocation push target, in milliseconds.
   * TSD §6.2: "< 5 seconds full propagation."
   */
  revocationPushTimeoutMs: number;
}

export function loadRelayConfig(): RelayNodeConfig {
  const domain = (process.env.RELAY_DOMAIN ?? "operational_behavior") as Domain;

  return {
    operatorId: process.env.OPERATOR_ID ?? "relay-operator-default",
    port: Number(process.env.PORT ?? 3200),
    host: process.env.HOST ?? "0.0.0.0",
    domain,
    dbPath: process.env.DB_PATH ?? "./provus-relay.db",
    anchorEndpoints: (process.env.ANCHOR_ENDPOINTS ?? "http://localhost:3300")
      .split(",")
      .map((e) => e.trim()),
    peerRelayEndpoints: (process.env.PEER_RELAY_ENDPOINTS ?? "")
      .split(",")
      .map((e) => e.trim())
      .filter(Boolean),
    heartbeatIntervalMs: Number(process.env.HEARTBEAT_INTERVAL_MS ?? 10_000),
    maxRecordAgeSeconds: Number(process.env.MAX_RECORD_AGE_SECONDS ?? 90 * 24 * 60 * 60),
    revocationPushTimeoutMs: Number(process.env.REVOCATION_PUSH_TIMEOUT_MS ?? 4_500),
  };
}
