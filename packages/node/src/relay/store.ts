/**
 * @provus/node — relay/store.ts
 *
 * Domain-scoped record store for the Relay node.
 *
 * TSD §6.1: "Relay nodes — domain-scoped record store + full mesh index.
 * Serve query traffic. Propagate up to Anchors, lateral to peers."
 *
 * Unlike the Edge store (which holds only the operator's own agents),
 * the Relay store holds ALL records for its credentialed domain —
 * from every Edge node that submits to it.
 *
 * Tables:
 *   domain_identities    — all agent identities in this domain
 *   domain_attestations  — all attestations in this domain
 *   domain_revocations   — all revocation notices
 *   mesh_index           — full index of record locations across domains
 *   propagation_log      — record of upstream/lateral propagation attempts
 *   edge_registry        — registered Edge nodes and their heartbeat status
 *   anchor_queue         — records queued for Anchor propagation
 *   peer_queue           — records queued for peer Relay propagation
 */

import initSqlJs from "sql.js";
import type { Database } from "sql.js";
import * as fs from "fs";
import * as path from "path";
import type { RelayNodeConfig } from "./config.js";
import type {
  AgentIdentity,
  AttestationRecord,
  RevocationNotice,
} from "@provus/core";

export interface EdgeNodeEntry {
  nodeId: string;
  operatorId: string;
  endpoint: string;
  lastHeartbeatAt: string | null;
  status: "active" | "degraded" | "offline";
  missedHeartbeats: number;
  registeredAt: string;
}

export interface PropagationRecord {
  id: string;
  recordId: string;
  recordType: "identity" | "attestation" | "revocation" | "incident";
  target: string;
  targetType: "anchor" | "peer_relay";
  status: "pending" | "sent" | "failed";
  attempts: number;
  queuedAt: string;
  sentAt: string | null;
}

export class RelayStore {
  private db!: Database;
  private config: RelayNodeConfig;

  constructor(config: RelayNodeConfig) {
    this.config = config;
  }

  async initialize(): Promise<void> {
    const SQL = await initSqlJs();

    if (fs.existsSync(this.config.dbPath)) {
      const buf = fs.readFileSync(this.config.dbPath);
      this.db = new SQL.Database(buf);
    } else {
      this.db = new SQL.Database();
    }

    this.createTables();
    this.persist();
    console.log(`[provus:relay:store] Initialized at ${this.config.dbPath}`);
    console.log(`[provus:relay:store] Domain: ${this.config.domain}`);
  }

  private createTables(): void {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS domain_identities (
        agent_id    TEXT PRIMARY KEY,
        data        TEXT NOT NULL,
        domain      TEXT NOT NULL,
        received_at TEXT NOT NULL,
        source_edge TEXT
      );

      CREATE TABLE IF NOT EXISTS domain_attestations (
        attestation_id  TEXT PRIMARY KEY,
        agent_id        TEXT NOT NULL,
        domain          TEXT NOT NULL,
        data            TEXT NOT NULL,
        valid_until     TEXT NOT NULL,
        issued_at       TEXT NOT NULL,
        received_at     TEXT NOT NULL,
        source_edge     TEXT,
        anchor_confirmed INTEGER NOT NULL DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_attestations_agent
        ON domain_attestations(agent_id);
      CREATE INDEX IF NOT EXISTS idx_attestations_domain
        ON domain_attestations(domain);

      CREATE TABLE IF NOT EXISTS domain_revocations (
        attestation_id  TEXT NOT NULL,
        data            TEXT NOT NULL,
        revoked_at      TEXT NOT NULL,
        received_at     TEXT NOT NULL,
        severity        TEXT NOT NULL DEFAULT 'standard',
        propagated      INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS mesh_index (
        record_id     TEXT NOT NULL,
        record_type   TEXT NOT NULL,
        domain        TEXT NOT NULL,
        relay_endpoint TEXT NOT NULL,
        indexed_at    TEXT NOT NULL,
        PRIMARY KEY (record_id, record_type)
      );

      CREATE TABLE IF NOT EXISTS propagation_log (
        id          TEXT PRIMARY KEY,
        record_id   TEXT NOT NULL,
        record_type TEXT NOT NULL,
        target      TEXT NOT NULL,
        target_type TEXT NOT NULL,
        status      TEXT NOT NULL DEFAULT 'pending',
        attempts    INTEGER NOT NULL DEFAULT 0,
        queued_at   TEXT NOT NULL,
        sent_at     TEXT
      );

      CREATE TABLE IF NOT EXISTS edge_registry (
        node_id           TEXT PRIMARY KEY,
        operator_id       TEXT NOT NULL,
        endpoint          TEXT,
        last_heartbeat_at TEXT,
        status            TEXT NOT NULL DEFAULT 'active',
        missed_heartbeats INTEGER NOT NULL DEFAULT 0,
        registered_at     TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS anchor_queue (
        id          TEXT PRIMARY KEY,
        record_id   TEXT NOT NULL,
        record_type TEXT NOT NULL,
        payload     TEXT NOT NULL,
        priority    TEXT NOT NULL DEFAULT 'standard',
        queued_at   TEXT NOT NULL,
        attempts    INTEGER NOT NULL DEFAULT 0,
        status      TEXT NOT NULL DEFAULT 'pending'
      );

      CREATE TABLE IF NOT EXISTS peer_queue (
        id            TEXT PRIMARY KEY,
        record_id     TEXT NOT NULL,
        record_type   TEXT NOT NULL,
        peer_endpoint TEXT NOT NULL,
        payload       TEXT NOT NULL,
        queued_at     TEXT NOT NULL,
        attempts      INTEGER NOT NULL DEFAULT 0,
        status        TEXT NOT NULL DEFAULT 'pending'
      );
    `);
  }

  private persist(): void {
    const data = this.db.export();
    const dir = path.dirname(this.config.dbPath);
    if (dir && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(this.config.dbPath, Buffer.from(data));
  }

  private q<T>(sql: string, params: any[] = []): T[] {
    const stmt = this.db.prepare(sql);
    const results: T[] = [];
    stmt.bind(params);
    while (stmt.step()) results.push(stmt.getAsObject() as T);
    stmt.free();
    return results;
  }

  private exec(sql: string, params: any[] = []): void {
    this.db.run(sql, params);
    this.persist();
  }

  // ── IDENTITIES ─────────────────────────────────────────────────────────────

  saveIdentity(identity: AgentIdentity, sourceEdge?: string): void {
    this.exec(
      `INSERT OR REPLACE INTO domain_identities
         (agent_id, data, domain, received_at, source_edge)
       VALUES (?, ?, ?, ?, ?)`,
      [identity.agentId, JSON.stringify(identity), this.config.domain,
       new Date().toISOString(), sourceEdge ?? null]
    );
  }

  getIdentity(agentId: string): AgentIdentity | null {
    const rows = this.q<{ data: string }>(
      "SELECT data FROM domain_identities WHERE agent_id = ?", [agentId]
    );
    return rows.length ? JSON.parse(rows[0].data) : null;
  }

  getAllIdentities(): AgentIdentity[] {
    return this.q<{ data: string }>("SELECT data FROM domain_identities")
      .map((r) => JSON.parse(r.data));
  }

  // ── ATTESTATIONS ───────────────────────────────────────────────────────────

  saveAttestation(record: AttestationRecord, sourceEdge?: string): void {
    this.exec(
      `INSERT OR REPLACE INTO domain_attestations
         (attestation_id, agent_id, domain, data, valid_until, issued_at, received_at, source_edge)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [record.attestationId, record.subjectAgentId, record.domain,
       JSON.stringify(record), record.validUntil, record.issuedAt,
       new Date().toISOString(), sourceEdge ?? null]
    );
  }

  getAttestationsForAgent(agentId: string): AttestationRecord[] {
    return this.q<{ data: string }>(
      "SELECT data FROM domain_attestations WHERE agent_id = ?", [agentId]
    ).map((r) => JSON.parse(r.data));
  }

  getAttestation(attestationId: string): AttestationRecord | null {
    const rows = this.q<{ data: string }>(
      "SELECT data FROM domain_attestations WHERE attestation_id = ?",
      [attestationId]
    );
    return rows.length ? JSON.parse(rows[0].data) : null;
  }

  markAnchorConfirmed(attestationId: string): void {
    this.exec(
      "UPDATE domain_attestations SET anchor_confirmed = 1 WHERE attestation_id = ?",
      [attestationId]
    );
  }

  // ── REVOCATIONS ────────────────────────────────────────────────────────────

  saveRevocation(notice: RevocationNotice, severity: "standard" | "high" = "standard"): void {
    this.exec(
      `INSERT INTO domain_revocations
         (attestation_id, data, revoked_at, received_at, severity, propagated)
       VALUES (?, ?, ?, ?, ?, 0)`,
      [notice.attestationId, JSON.stringify(notice),
       notice.revokedAt, new Date().toISOString(), severity]
    );
  }

  getRevocations(): RevocationNotice[] {
    return this.q<{ data: string }>("SELECT data FROM domain_revocations")
      .map((r) => JSON.parse(r.data));
  }

  /**
   * Get high-severity revocations that haven't been propagated yet.
   * TSD §6.2: High-severity revocations use a dedicated fast path,
   * targeting < 5 seconds full propagation (Anchor → all Relays).
   */
  getUnpropagatedHighSeverityRevocations(): RevocationNotice[] {
    return this.q<{ data: string }>(
      "SELECT data FROM domain_revocations WHERE severity = 'high' AND propagated = 0"
    ).map((r) => JSON.parse(r.data));
  }

  markRevocationPropagated(attestationId: string): void {
    this.exec(
      "UPDATE domain_revocations SET propagated = 1 WHERE attestation_id = ?",
      [attestationId]
    );
  }

  // ── MESH INDEX ─────────────────────────────────────────────────────────────

  /**
   * TSD §6.1: Relay nodes hold a "full mesh index" — they know where
   * every record type lives across all domains, even if they don't
   * hold the record itself.
   */
  indexRecord(
    recordId: string,
    recordType: string,
    domain: string,
    relayEndpoint: string
  ): void {
    this.exec(
      `INSERT OR REPLACE INTO mesh_index
         (record_id, record_type, domain, relay_endpoint, indexed_at)
       VALUES (?, ?, ?, ?, ?)`,
      [recordId, recordType, domain, relayEndpoint, new Date().toISOString()]
    );
  }

  findRecord(recordId: string, recordType: string): string | null {
    const rows = this.q<{ relay_endpoint: string }>(
      "SELECT relay_endpoint FROM mesh_index WHERE record_id = ? AND record_type = ?",
      [recordId, recordType]
    );
    return rows.length ? rows[0].relay_endpoint : null;
  }

  // ── ANCHOR QUEUE ───────────────────────────────────────────────────────────

  /**
   * Queue a record for propagation to Anchor nodes.
   * TSD §6.2: Relay → Anchor propagation target < 5 seconds.
   */
  queueForAnchor(
    id: string,
    recordId: string,
    recordType: string,
    payload: unknown,
    priority: "standard" | "high" = "standard"
  ): void {
    this.exec(
      `INSERT OR IGNORE INTO anchor_queue
         (id, record_id, record_type, payload, priority, queued_at, status)
       VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
      [id, recordId, recordType, JSON.stringify(payload),
       priority, new Date().toISOString()]
    );
  }

  getPendingAnchorQueue(priority?: "standard" | "high"): any[] {
    const sql = priority
      ? "SELECT * FROM anchor_queue WHERE status = 'pending' AND priority = ? ORDER BY queued_at ASC LIMIT 100"
      : "SELECT * FROM anchor_queue WHERE status = 'pending' ORDER BY priority DESC, queued_at ASC LIMIT 100";
    const params = priority ? [priority] : [];
    return this.q<any>(sql, params);
  }

  markAnchorQueueItem(id: string, status: "sent" | "failed"): void {
    this.exec(
      "UPDATE anchor_queue SET status = ?, attempts = attempts + 1 WHERE id = ?",
      [status, id]
    );
  }

  // ── PEER QUEUE ─────────────────────────────────────────────────────────────

  /**
   * Queue a record for lateral propagation to peer Relay nodes.
   * TSD §6.2: Relay → Relay (same domain) target < 2 seconds.
   */
  queueForPeer(
    id: string,
    recordId: string,
    recordType: string,
    peerEndpoint: string,
    payload: unknown
  ): void {
    this.exec(
      `INSERT OR IGNORE INTO peer_queue
         (id, record_id, record_type, peer_endpoint, payload, queued_at, status)
       VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
      [id, recordId, recordType, peerEndpoint,
       JSON.stringify(payload), new Date().toISOString()]
    );
  }

  getPendingPeerQueue(): any[] {
    return this.q<any>(
      "SELECT * FROM peer_queue WHERE status = 'pending' ORDER BY queued_at ASC LIMIT 100"
    );
  }

  markPeerQueueItem(id: string, status: "sent" | "failed"): void {
    this.exec(
      "UPDATE peer_queue SET status = ?, attempts = attempts + 1 WHERE id = ?",
      [status, id]
    );
  }

  // ── EDGE REGISTRY ──────────────────────────────────────────────────────────

  registerEdgeNode(nodeId: string, operatorId: string, endpoint?: string): void {
    this.exec(
      `INSERT OR REPLACE INTO edge_registry
         (node_id, operator_id, endpoint, status, missed_heartbeats, registered_at)
       VALUES (?, ?, ?, 'active', 0, ?)`,
      [nodeId, operatorId, endpoint ?? null, new Date().toISOString()]
    );
    console.log(`[provus:relay:store] Edge node registered: ${nodeId}`);
  }

  recordEdgeHeartbeat(nodeId: string): void {
    this.exec(
      `UPDATE edge_registry
       SET last_heartbeat_at = ?, status = 'active', missed_heartbeats = 0
       WHERE node_id = ?`,
      [new Date().toISOString(), nodeId]
    );
  }

  markEdgeMissedHeartbeat(nodeId: string): void {
    this.exec(
      `UPDATE edge_registry
       SET missed_heartbeats = missed_heartbeats + 1,
           status = CASE
             WHEN missed_heartbeats + 1 >= 5 THEN 'offline'
             WHEN missed_heartbeats + 1 >= 3 THEN 'degraded'
             ELSE status
           END
       WHERE node_id = ?`,
      [nodeId]
    );
  }

  getEdgeNodes(): EdgeNodeEntry[] {
    return this.q<any>("SELECT * FROM edge_registry").map((r) => ({
      nodeId: r.node_id,
      operatorId: r.operator_id,
      endpoint: r.endpoint,
      lastHeartbeatAt: r.last_heartbeat_at,
      status: r.status,
      missedHeartbeats: r.missed_heartbeats,
      registeredAt: r.registered_at,
    }));
  }

  // ── STATS ──────────────────────────────────────────────────────────────────

  getStats(): {
    identities: number;
    attestations: number;
    activeAttestations: number;
    revocations: number;
    pendingAnchorQueue: number;
    pendingPeerQueue: number;
    edgeNodes: number;
    activeEdgeNodes: number;
  } {
    const now = new Date().toISOString();
    const count = (sql: string, p: any[] = []) =>
      (this.q<{ cnt: number }>(sql, p)[0]?.cnt ?? 0);

    return {
      identities: count("SELECT COUNT(*) as cnt FROM domain_identities"),
      attestations: count("SELECT COUNT(*) as cnt FROM domain_attestations"),
      activeAttestations: count(
        "SELECT COUNT(*) as cnt FROM domain_attestations WHERE valid_until > ?", [now]
      ),
      revocations: count("SELECT COUNT(*) as cnt FROM domain_revocations"),
      pendingAnchorQueue: count(
        "SELECT COUNT(*) as cnt FROM anchor_queue WHERE status = 'pending'"
      ),
      pendingPeerQueue: count(
        "SELECT COUNT(*) as cnt FROM peer_queue WHERE status = 'pending'"
      ),
      edgeNodes: count("SELECT COUNT(*) as cnt FROM edge_registry"),
      activeEdgeNodes: count(
        "SELECT COUNT(*) as cnt FROM edge_registry WHERE status = 'active'"
      ),
    };
  }

  close(): void {
    this.persist();
    this.db.close();
  }
}
