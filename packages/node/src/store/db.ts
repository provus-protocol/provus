/**
 * @provus/node — store/db.ts
 *
 * Persistent store for the Edge node using sql.js (pure JS SQLite).
 * No native bindings required.
 *
 * Data is persisted to disk as a binary SQLite file and loaded
 * on startup. Writes are flushed to disk after every mutation.
 */

import initSqlJs from "sql.js";
import type { Database } from "sql.js";
import * as fs from "fs";
import * as path from "path";
import type { EdgeNodeConfig } from "../config.js";
import type {
  AgentIdentity,
  AttestationRecord,
  RevocationNotice,
  TrustEnvelope,
  IncidentRecord,
} from "@provus/core";

export interface QueuedSubmission {
  id: string;
  type: "attestation" | "identity" | "incident" | "revocation";
  payload: string;
  queuedAt: string;
  attempts: number;
  lastAttemptAt: string | null;
  status: "pending" | "submitted" | "failed";
}

export interface CachedQuery {
  agentId: string;
  scopeHash: string;
  envelope: string;
  cachedAt: string;
  expiresAt: string;
  stale: boolean;
}

export interface NodeState {
  operatorId: string;
  relayStatus: "connected" | "degraded" | "offline";
  missedHeartbeats: number;
  lastHeartbeatAt: string | null;
  lastRelayContactAt: string | null;
  startedAt: string;
}

export class EdgeStore {
  private db!: Database;
  private config: EdgeNodeConfig;
  private dbPath: string;

  constructor(config: EdgeNodeConfig) {
    this.config = config;
    this.dbPath = config.dbPath;
  }

  async initialize(): Promise<void> {
    const SQL = await initSqlJs();

    if (fs.existsSync(this.dbPath)) {
      const buf = fs.readFileSync(this.dbPath);
      this.db = new SQL.Database(buf);
    } else {
      this.db = new SQL.Database();
    }

    this.createTables();
    this.initNodeState();
    this.persist();
    console.log(`[provus:store] Initialized at ${this.dbPath}`);
  }

  private createTables(): void {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS identities (
        agent_id TEXT PRIMARY KEY, data TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS attestations (
        attestation_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
        data TEXT NOT NULL, valid_until TEXT NOT NULL, issued_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS revocations (
        attestation_id TEXT NOT NULL, data TEXT NOT NULL, revoked_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS query_cache (
        cache_key TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
        scope_hash TEXT NOT NULL, envelope TEXT NOT NULL,
        cached_at TEXT NOT NULL, expires_at TEXT NOT NULL,
        stale INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS submission_queue (
        id TEXT PRIMARY KEY, type TEXT NOT NULL, payload TEXT NOT NULL,
        queued_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
        last_attempt_at TEXT, status TEXT NOT NULL DEFAULT 'pending'
      );
      CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
        data TEXT NOT NULL, recorded_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS node_state (
        operator_id TEXT PRIMARY KEY,
        relay_status TEXT NOT NULL DEFAULT 'offline',
        missed_heartbeats INTEGER NOT NULL DEFAULT 0,
        last_heartbeat_at TEXT, last_relay_contact_at TEXT,
        started_at TEXT NOT NULL
      );
    `);
  }

  private initNodeState(): void {
    const res = this.db.exec(
      `SELECT operator_id FROM node_state WHERE operator_id = '${this.config.operatorId.replace(/'/g, "''")}'`
    );
    if (!res.length || !res[0].values.length) {
      this.db.run(
        "INSERT INTO node_state (operator_id, relay_status, missed_heartbeats, started_at) VALUES (?,?,0,?)",
        [this.config.operatorId, "offline", new Date().toISOString()]
      );
    }
  }

  private persist(): void {
    const data = this.db.export();
    const dir = path.dirname(this.dbPath);
    if (dir && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(this.dbPath, Buffer.from(data));
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

  saveIdentity(identity: AgentIdentity): void {
    this.exec(
      "INSERT OR REPLACE INTO identities (agent_id, data, created_at, updated_at) VALUES (?,?,?,?)",
      [identity.agentId, JSON.stringify(identity), identity.createdAt, identity.updatedAt]
    );
  }

  getIdentity(agentId: string): AgentIdentity | null {
    const rows = this.q<{ data: string }>("SELECT data FROM identities WHERE agent_id = ?", [agentId]);
    return rows.length ? JSON.parse(rows[0].data) : null;
  }

  getAllIdentities(): AgentIdentity[] {
    return this.q<{ data: string }>("SELECT data FROM identities").map((r) => JSON.parse(r.data));
  }

  // ── ATTESTATIONS ───────────────────────────────────────────────────────────

  saveAttestation(record: AttestationRecord): void {
    this.exec(
      "INSERT OR REPLACE INTO attestations (attestation_id, agent_id, data, valid_until, issued_at) VALUES (?,?,?,?,?)",
      [record.attestationId, record.subjectAgentId, JSON.stringify(record), record.validUntil, record.issuedAt]
    );
  }

  getAttestationsForAgent(agentId: string): AttestationRecord[] {
    return this.q<{ data: string }>("SELECT data FROM attestations WHERE agent_id = ?", [agentId])
      .map((r) => JSON.parse(r.data));
  }

  // ── REVOCATIONS ────────────────────────────────────────────────────────────

  saveRevocation(notice: RevocationNotice): void {
    this.exec(
      "INSERT INTO revocations (attestation_id, data, revoked_at) VALUES (?,?,?)",
      [notice.attestationId, JSON.stringify(notice), notice.revokedAt]
    );
  }

  getRevocations(): RevocationNotice[] {
    return this.q<{ data: string }>("SELECT data FROM revocations").map((r) => JSON.parse(r.data));
  }

  // ── QUERY CACHE ────────────────────────────────────────────────────────────

  getCachedQuery(agentId: string, scopeHash: string): CachedQuery | null {
    const rows = this.q<any>(
      "SELECT * FROM query_cache WHERE agent_id = ? AND scope_hash = ?",
      [agentId, scopeHash]
    );
    if (!rows.length) return null;

    const row = rows[0];
    let stale = row.stale === 1;

    if (new Date() > new Date(row.expires_at) && !stale) {
      this.exec("UPDATE query_cache SET stale = 1 WHERE cache_key = ?", [row.cache_key]);
      stale = true;
    }

    return {
      agentId: row.agent_id,
      scopeHash: row.scope_hash,
      envelope: row.envelope,
      cachedAt: row.cached_at,
      expiresAt: row.expires_at,
      stale,
    };
  }

  setCachedQuery(agentId: string, scopeHash: string, envelope: TrustEnvelope, ttlSeconds: number): void {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
    this.exec(
      "INSERT OR REPLACE INTO query_cache (cache_key, agent_id, scope_hash, envelope, cached_at, expires_at, stale) VALUES (?,?,?,?,?,?,0)",
      [`${agentId}:${scopeHash}`, agentId, scopeHash, JSON.stringify(envelope), now.toISOString(), expiresAt.toISOString()]
    );
  }

  markAllCacheStale(): void {
    this.exec("UPDATE query_cache SET stale = 1");
    console.log("[provus:store] All cache marked stale");
  }

  // ── SUBMISSION QUEUE ───────────────────────────────────────────────────────

  enqueue(id: string, type: QueuedSubmission["type"], payload: unknown): void {
    const cnt = (this.q<{ cnt: number }>("SELECT COUNT(*) as cnt FROM submission_queue WHERE status = 'pending'")[0]?.cnt ?? 0);
    if (cnt >= this.config.queueMaxDepth) {
      const oldest = this.q<{ id: string }>("SELECT id FROM submission_queue WHERE status='pending' ORDER BY queued_at ASC LIMIT 1");
      if (oldest.length) {
        this.exec("DELETE FROM submission_queue WHERE id = ?", [oldest[0].id]);
        console.warn("[provus:queue] Queue full — dropped oldest record");
      }
    }
    this.exec(
      "INSERT INTO submission_queue (id, type, payload, queued_at, attempts, status) VALUES (?,?,?,?,0,'pending')",
      [id, type, JSON.stringify(payload), new Date().toISOString()]
    );
  }

  getPendingSubmissions(): QueuedSubmission[] {
    const maxAge = new Date(Date.now() - this.config.queueMaxAgeMs);
    this.exec("UPDATE submission_queue SET status='failed' WHERE status='pending' AND queued_at < ?", [maxAge.toISOString()]);
    return this.q<any>("SELECT * FROM submission_queue WHERE status='pending' ORDER BY queued_at ASC LIMIT 50")
      .map((r) => ({ id: r.id, type: r.type, payload: r.payload, queuedAt: r.queued_at, attempts: r.attempts, lastAttemptAt: r.last_attempt_at, status: r.status }));
  }

  markSubmitted(id: string): void {
    this.exec("UPDATE submission_queue SET status='submitted' WHERE id=?", [id]);
  }

  markSubmissionFailed(id: string): void {
    this.exec("UPDATE submission_queue SET status='failed', attempts=attempts+1, last_attempt_at=? WHERE id=?", [new Date().toISOString(), id]);
  }

  incrementAttempt(id: string): void {
    this.exec("UPDATE submission_queue SET attempts=attempts+1, last_attempt_at=? WHERE id=?", [new Date().toISOString(), id]);
  }

  // ── INCIDENTS ──────────────────────────────────────────────────────────────

  saveIncident(incident: IncidentRecord): void {
    this.exec(
      "INSERT OR REPLACE INTO incidents (incident_id, agent_id, data, recorded_at) VALUES (?,?,?,?)",
      [incident.incidentId, incident.subjectAgentId, JSON.stringify(incident), incident.recordedAt]
    );
  }

  getIncidentsForAgent(agentId: string): IncidentRecord[] {
    return this.q<{ data: string }>("SELECT data FROM incidents WHERE agent_id=?", [agentId]).map((r) => JSON.parse(r.data));
  }

  // ── NODE STATE ─────────────────────────────────────────────────────────────

  getNodeState(): NodeState {
    const rows = this.q<any>("SELECT * FROM node_state WHERE operator_id=?", [this.config.operatorId]);
    const r = rows[0];
    return {
      operatorId: r.operator_id,
      relayStatus: r.relay_status,
      missedHeartbeats: r.missed_heartbeats,
      lastHeartbeatAt: r.last_heartbeat_at,
      lastRelayContactAt: r.last_relay_contact_at,
      startedAt: r.started_at,
    };
  }

  updateRelayStatus(status: "connected" | "degraded" | "offline", missedHeartbeats: number): void {
    this.exec(
      "UPDATE node_state SET relay_status=?, missed_heartbeats=?, last_heartbeat_at=? WHERE operator_id=?",
      [status, missedHeartbeats, new Date().toISOString(), this.config.operatorId]
    );
  }

  recordRelayContact(): void {
    this.exec(
      "UPDATE node_state SET relay_status='connected', missed_heartbeats=0, last_heartbeat_at=?, last_relay_contact_at=? WHERE operator_id=?",
      [new Date().toISOString(), new Date().toISOString(), this.config.operatorId]
    );
  }

  close(): void {
    this.persist();
    this.db.close();
  }
}
