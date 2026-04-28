/**
 * @provus/node — anchor/config.ts
 *
 * Anchor node configuration. TSD §6.1.
 *
 * Anchor nodes are operated by Tier 0 attesters — the genesis
 * institutions that seed the entire trust graph. They are
 * write-authoritative and sync-authoritative. They do NOT
 * serve query traffic directly.
 *
 * TSD §6.1: "Anchor nodes do not serve query traffic directly.
 * They are write-authoritative and sync-authoritative. Putting
 * them on the query path would make them a bottleneck and a
 * DDoS target."
 *
 * Quorum model (PoC):
 *   Threshold signature — N anchor nodes, M must confirm.
 *   Production: MonadBFT consensus (n=3f+1, <1/3 Byzantine).
 */

export interface AnchorNodeConfig {
  /** This anchor's identifier */
  nodeId: string;

  /** Operator — must be a Tier 0 attester institution */
  operatorId: string;

  /** HTTP port */
  port: number;

  /** Host */
  host: string;

  /** Path to SQLite database */
  dbPath: string;

  /**
   * All Anchor node endpoints in the cluster (including self).
   * TSD §6.1: "3–7 nodes at genesis, must maintain quorum."
   */
  clusterEndpoints: string[];

  /**
   * Quorum threshold — how many anchors must confirm a record.
   * PoC default: Math.floor(N/2) + 1 (simple majority).
   * Production: MonadBFT uses 2f+1 out of 3f+1.
   */
  quorumThreshold: number;

  /**
   * All Relay node endpoints.
   * Anchor pushes high-severity revocations to all Relays.
   * TSD §6.2: High-severity revocation push target < 5 seconds.
   */
  relayEndpoints: string[];

  /**
   * Consensus timeout — how long to wait for quorum confirmation
   * before marking a record as provisional.
   */
  consensusTimeoutMs: number;

  /**
   * Sync interval with peer Anchor nodes, in milliseconds.
   * Anchors must maintain synchrony with each other.
   */
  syncIntervalMs: number;
}

export function loadAnchorConfig(): AnchorNodeConfig {
  const clusterRaw = process.env.ANCHOR_CLUSTER_ENDPOINTS ?? "http://localhost:3300";
  const clusterEndpoints = clusterRaw.split(",").map((e) => e.trim());
  const N = clusterEndpoints.length;

  return {
    nodeId: process.env.NODE_ID ?? "anchor-0",
    operatorId: process.env.OPERATOR_ID ?? "anchor-operator-genesis",
    port: Number(process.env.PORT ?? 3300),
    host: process.env.HOST ?? "0.0.0.0",
    dbPath: process.env.DB_PATH ?? "./provus-anchor.db",
    clusterEndpoints,
    quorumThreshold: Number(
      process.env.QUORUM_THRESHOLD ?? Math.floor(N / 2) + 1
    ),
    relayEndpoints: (process.env.RELAY_ENDPOINTS ?? "http://localhost:3200")
      .split(",")
      .map((e) => e.trim()),
    consensusTimeoutMs: Number(process.env.CONSENSUS_TIMEOUT_MS ?? 10_000),
    syncIntervalMs: Number(process.env.SYNC_INTERVAL_MS ?? 5_000),
  };
}
