/**
 * @provus/node — anchor/store.ts
 *
 * Authoritative ledger for the Anchor node.
 *
 * This is the canonical record of truth for VeritasMesh.
 * A record that has reached Anchor consensus is authoritative.
 * A record pending consensus is provisional.
 *
 * TSD §6.2: "A record that makes it to Anchor consensus is
 * authoritative. A record that's sitting at a Relay node but
 * hasn't reached Anchor consensus yet is provisional — valid
 * for query purposes but flagged as unconfirmed."
 *
 * Tables:
 *   authoritative_records  — all confirmed records
 *   pending_records        — records awaiting quorum confirmation
 *   quorum_votes           — per-record votes from peer Anchors
 *   revocation_log         — all revocations, with propagation status
 *   anchor_sync_log        — sync history with peer Anchors
 *   authoritative_queries  — log of authoritative query requests
 */

import initSqlJs from "sql.js";
import type { Database } from "sql.js";
import * as fs from "fs";
import * as path from "path";
import type { AnchorNodeConfig } from "./config.js";

export type RecordType = "identity" | "attestation" | "revocation" | "incident";
export type RecordStatus = "pending" | "confirmed" | "rejected";

export interface AuthoritativeRecord {
  recordId: string;
  recordType: RecordType;
  domain: string;
  payload: string;       // JSON serialized
  status: RecordStatus;
  submittedAt: string;
  confirmedAt: string | null;
  quorumVotes: number;
  quorumRequired: number;
  submittedBy: string;   // relay node that submitted
}

export interface QuorumVote {
  recordId: string;
  voterId: string;       // anchor node ID that voted
  vote: "confirm" | "reject";
  signature: string;
  votedAt: string;
}

export interface RevocationLogEntry {
  attestationId: string;
  severity: "standard" | "high";
  payload: string;
  recordedAt: string;
  propagatedToRelays: number;
  totalRelays: number;
  propagationCompletedAt: string | null;
}

export class AnchorStore {
  private db!: Database;
  private config: AnchorNodeConfig;

  constructor(config: AnchorNodeConfig) {
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
    console.log(`[provus:anchor:store] Initialized at ${this.config.dbPath}`);
    console.log(`[provus:anchor:store] Node: ${this.config.nodeId}`);
    console.log(`[provus:anchor:store] Quorum threshold: ${this.config.quorumThreshold}/${this.config.clusterEndpoints.length}`);
  }

  private createTables(): void {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS authoritative_records (
        record_id       TEXT NOT NULL,
        record_type     TEXT NOT NULL,
        domain          TEXT NOT NULL,
        payload         TEXT NOT NULL,
        status          TEXT NOT NULL DEFAULT 'pending',
        submitted_at    TEXT NOT NULL,
        confirmed_at    TEXT,
        quorum_votes    INTEGER NOT NULL DEFAULT 0,
        quorum_required INTEGER NOT NULL,
        submitted_by    TEXT NOT NULL,
        PRIMARY KEY (record_id, record_type)
      );

      CREATE INDEX IF NOT EXISTS idx_records_status
        ON authoritative_records(status);
      CREATE INDEX IF NOT EXISTS idx_records_type
        ON authoritative_records(record_type);

      CREATE TABLE IF NOT EXISTS quorum_votes (
        record_id   TEXT NOT NULL,
        voter_id    TEXT NOT NULL,
        vote        TEXT NOT NULL,
        signature   TEXT NOT NULL,
        voted_at    TEXT NOT NULL,
        PRIMARY KEY (record_id, voter_id)
      );

      CREATE TABLE IF NOT EXISTS revocation_log (
        attestation_id              TEXT PRIMARY KEY,
        severity                    TEXT NOT NULL DEFAULT 'standard',
        payload                     TEXT NOT NULL,
        recorded_at                 TEXT NOT NULL,
        propagated_to_relays        INTEGER NOT NULL DEFAULT 0,
        total_relays                INTEGER NOT NULL,
        propagation_completed_at    TEXT
      );

      CREATE TABLE IF NOT EXISTS anchor_sync_log (
        id              TEXT PRIMARY KEY,
        peer_node_id    TEXT NOT NULL,
        synced_at       TEXT NOT NULL,
        records_synced  INTEGER NOT NULL DEFAULT 0,
        status          TEXT NOT NULL DEFAULT 'success'
      );

      CREATE TABLE IF NOT EXISTS authoritative_queries (
        query_id        TEXT PRIMARY KEY,
        agent_id        TEXT NOT NULL,
        requested_scope TEXT NOT NULL,
        queried_at      TEXT NOT NULL,
        resolved_at     TEXT,
        requester       TEXT
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

  // ── RECORD SUBMISSION ──────────────────────────────────────────────────────

  /**
   * Submit a record for consensus consideration.
   * The record starts as 'pending' until quorum is reached.
   *
   * TSD §6.2: "A record at a Relay node pending Anchor consensus
   * is provisional — valid for query purposes but flagged as unconfirmed."
   */
  submitRecord(
    recordId: string,
    recordType: RecordType,
    domain: string,
    payload: unknown,
    submittedBy: string
  ): boolean {
    // Idempotent — don't re-submit if already exists
    const existing = this.q<{ status: string }>(
      "SELECT status FROM authoritative_records WHERE record_id = ? AND record_type = ?",
      [recordId, recordType]
    );

    if (existing.length > 0) {
      return existing[0].status === "confirmed";
    }

    this.exec(
      `INSERT INTO authoritative_records
         (record_id, record_type, domain, payload, status, submitted_at,
          quorum_votes, quorum_required, submitted_by)
       VALUES (?, ?, ?, ?, 'pending', ?, 0, ?, ?)`,
      [recordId, recordType, domain, JSON.stringify(payload),
       new Date().toISOString(), this.config.quorumThreshold, submittedBy]
    );

    // Self-vote — this anchor implicitly votes to confirm on receipt
    this.recordVote(recordId, this.config.nodeId, "confirm", "self-vote");

    return false; // pending, not yet confirmed
  }

  // ── QUORUM VOTING ──────────────────────────────────────────────────────────

  /**
   * Record a vote from a peer Anchor node.
   * When quorum is reached, the record is confirmed.
   *
   * TSD §6.2: "Anchor nodes achieve consensus on the record
   * and write it to the authoritative ledger."
   */
  recordVote(
    recordId: string,
    voterId: string,
    vote: "confirm" | "reject",
    signature: string
  ): { confirmed: boolean; votes: number; required: number } {
    // Record the vote (idempotent per voter)
    this.exec(
      `INSERT OR IGNORE INTO quorum_votes
         (record_id, voter_id, vote, signature, voted_at)
       VALUES (?, ?, ?, ?, ?)`,
      [recordId, voterId, vote, signature, new Date().toISOString()]
    );

    // Count confirm votes
    const votes = this.q<{ cnt: number }>(
      "SELECT COUNT(*) as cnt FROM quorum_votes WHERE record_id = ? AND vote = 'confirm'",
      [recordId]
    );
    const confirmCount = votes[0]?.cnt ?? 0;

    // Get quorum requirement
    const record = this.q<{ quorum_required: number; status: string }>(
      "SELECT quorum_required, status FROM authoritative_records WHERE record_id = ?",
      [recordId]
    );

    if (!record.length) {
      return { confirmed: false, votes: confirmCount, required: this.config.quorumThreshold };
    }

    const required = record[0].quorum_required;
    const alreadyConfirmed = record[0].status === "confirmed";

    if (!alreadyConfirmed && confirmCount >= required) {
      // Quorum reached — confirm the record
      this.exec(
        `UPDATE authoritative_records
         SET status = 'confirmed', confirmed_at = ?, quorum_votes = ?
         WHERE record_id = ?`,
        [new Date().toISOString(), confirmCount, recordId]
      );

      console.log(
        `[provus:anchor:store] ✓ CONFIRMED: ${recordId.slice(0, 16)}… ` +
        `(${confirmCount}/${required} votes)`
      );

      return { confirmed: true, votes: confirmCount, required };
    }

    // Update vote count on existing record
    this.exec(
      "UPDATE authoritative_records SET quorum_votes = ? WHERE record_id = ?",
      [confirmCount, recordId]
    );

    return { confirmed: alreadyConfirmed, votes: confirmCount, required };
  }

  // ── RECORD RETRIEVAL ───────────────────────────────────────────────────────

  getRecord(recordId: string, recordType: RecordType): AuthoritativeRecord | null {
    const rows = this.q<any>(
      "SELECT * FROM authoritative_records WHERE record_id = ? AND record_type = ?",
      [recordId, recordType]
    );
    if (!rows.length) return null;
    return this.mapRecord(rows[0]);
  }

  getConfirmedRecords(recordType?: RecordType): AuthoritativeRecord[] {
    const sql = recordType
      ? "SELECT * FROM authoritative_records WHERE status = 'confirmed' AND record_type = ? ORDER BY confirmed_at DESC"
      : "SELECT * FROM authoritative_records WHERE status = 'confirmed' ORDER BY confirmed_at DESC";
    const params = recordType ? [recordType] : [];
    return this.q<any>(sql, params).map(this.mapRecord);
  }

  getPendingRecords(): AuthoritativeRecord[] {
    return this.q<any>(
      "SELECT * FROM authoritative_records WHERE status = 'pending' ORDER BY submitted_at ASC"
    ).map(this.mapRecord);
  }

  isConfirmed(recordId: string): boolean {
    const rows = this.q<{ status: string }>(
      "SELECT status FROM authoritative_records WHERE record_id = ?",
      [recordId]
    );
    return rows.length > 0 && rows[0].status === "confirmed";
  }

  private mapRecord(r: any): AuthoritativeRecord {
    return {
      recordId: r.record_id,
      recordType: r.record_type,
      domain: r.domain,
      payload: r.payload,
      status: r.status,
      submittedAt: r.submitted_at,
      confirmedAt: r.confirmed_at,
      quorumVotes: r.quorum_votes,
      quorumRequired: r.quorum_required,
      submittedBy: r.submitted_by,
    };
  }

  // ── REVOCATION LOG ─────────────────────────────────────────────────────────

  /**
   * Record a revocation in the authoritative revocation log.
   * High-severity revocations trigger immediate Relay propagation.
   *
   * TSD §6.2: Revocation fast path — Anchor → all Relays, target < 5s.
   */
  recordRevocation(
    attestationId: string,
    severity: "standard" | "high",
    payload: unknown
  ): void {
    this.exec(
      `INSERT OR REPLACE INTO revocation_log
         (attestation_id, severity, payload, recorded_at,
          propagated_to_relays, total_relays)
       VALUES (?, ?, ?, ?, 0, ?)`,
      [attestationId, severity, JSON.stringify(payload),
       new Date().toISOString(), this.config.relayEndpoints.length]
    );
  }

  markRevocationPropagated(attestationId: string, relayCount: number): void {
    this.exec(
      `UPDATE revocation_log
       SET propagated_to_relays = ?, propagation_completed_at = ?
       WHERE attestation_id = ?`,
      [relayCount, new Date().toISOString(), attestationId]
    );
  }

  getUnpropagatedRevocations(): RevocationLogEntry[] {
    return this.q<any>(
      `SELECT * FROM revocation_log
       WHERE propagated_to_relays < total_relays`
    ).map((r) => ({
      attestationId: r.attestation_id,
      severity: r.severity,
      payload: r.payload,
      recordedAt: r.recorded_at,
      propagatedToRelays: r.propagated_to_relays,
      totalRelays: r.total_relays,
      propagationCompletedAt: r.propagation_completed_at,
    }));
  }

  // ── SYNC LOG ───────────────────────────────────────────────────────────────

  recordSync(
    id: string,
    peerNodeId: string,
    recordsSynced: number,
    status: "success" | "failed"
  ): void {
    this.exec(
      `INSERT OR REPLACE INTO anchor_sync_log
         (id, peer_node_id, synced_at, records_synced, status)
       VALUES (?, ?, ?, ?, ?)`,
      [id, peerNodeId, new Date().toISOString(), recordsSynced, status]
    );
  }

  // ── AUTHORITATIVE QUERIES ──────────────────────────────────────────────────

  logAuthoritativeQuery(
    queryId: string,
    agentId: string,
    requestedScope: string[],
    requester?: string
  ): void {
    this.exec(
      `INSERT INTO authoritative_queries
         (query_id, agent_id, requested_scope, queried_at, requester)
       VALUES (?, ?, ?, ?, ?)`,
      [queryId, agentId, JSON.stringify(requestedScope),
       new Date().toISOString(), requester ?? null]
    );
  }

  markQueryResolved(queryId: string): void {
    this.exec(
      "UPDATE authoritative_queries SET resolved_at = ? WHERE query_id = ?",
      [new Date().toISOString(), queryId]
    );
  }

  // ── STATS ──────────────────────────────────────────────────────────────────

  getStats(): {
    totalRecords: number;
    confirmedRecords: number;
    pendingRecords: number;
    revocations: number;
    unpropagatedRevocations: number;
    authoritativeQueries: number;
  } {
    const count = (sql: string, p: any[] = []) =>
      (this.q<{ cnt: number }>(sql, p)[0]?.cnt ?? 0);

    return {
      totalRecords: count("SELECT COUNT(*) as cnt FROM authoritative_records"),
      confirmedRecords: count(
        "SELECT COUNT(*) as cnt FROM authoritative_records WHERE status = 'confirmed'"
      ),
      pendingRecords: count(
        "SELECT COUNT(*) as cnt FROM authoritative_records WHERE status = 'pending'"
      ),
      revocations: count("SELECT COUNT(*) as cnt FROM revocation_log"),
      unpropagatedRevocations: count(
        "SELECT COUNT(*) as cnt FROM revocation_log WHERE propagated_to_relays < total_relays"
      ),
      authoritativeQueries: count("SELECT COUNT(*) as cnt FROM authoritative_queries"),
    };
  }

  close(): void {
    this.persist();
    this.db.close();
  }
}
