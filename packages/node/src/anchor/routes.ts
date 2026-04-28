/**
 * @provus/node — anchor/routes.ts
 *
 * Anchor node HTTP routes.
 *
 * The Anchor node is NOT on the query path for standard queries.
 * It exposes:
 *
 * 1. Record intake from Relay nodes
 *    POST /anchor/records         — submit record for consensus
 *    POST /anchor/consensus/vote  — receive vote from peer Anchor
 *    POST /anchor/sync            — sync with peer Anchor
 *
 * 2. Authoritative query path
 *    POST /anchor/trust/query     — bypasses cache+Relay, highest assurance
 *    TSD §6.3: "Used for high-stakes decisions."
 *
 * 3. Revocation push path
 *    POST /anchor/revocation      — record revocation + push to all Relays
 *    TSD §6.2: High-severity revocations: Anchor → all Relays, target <5s.
 *
 * 4. Anchor status
 *    GET  /anchor/status
 *    GET  /anchor/ledger          — confirmed records summary
 *    GET  /anchor/pending         — records awaiting consensus
 */

import type { FastifyInstance } from "fastify";
import {
  generateId,
  now,
  type AttestationRecord,
  type AgentIdentity,
} from "@provus/core";
import type { AnchorStore } from "./store.js";
import type { ConsensusEngine } from "./consensus.js";
import type { AnchorNodeConfig } from "./config.js";
import { z } from "zod";

const RecordSubmitBody = z.object({
  recordId: z.string().min(1),
  recordType: z.enum(["identity", "attestation", "revocation", "incident"]),
  domain: z.string().min(1),
  payload: z.unknown(),
  submittedBy: z.string().min(1),
});

const VoteBody = z.object({
  recordId: z.string().min(1),
  recordType: z.string(),
  domain: z.string(),
  payload: z.unknown(),
  proposerId: z.string(),
});

const RevocationBody = z.object({
  attestationId: z.string().min(1),
  severity: z.enum(["standard", "high"]).default("standard"),
  payload: z.unknown(),
  submittedBy: z.string().min(1),
});

const TrustQueryBody = z.object({
  subjectAgentId: z.string().min(1),
  requestedScope: z.array(z.string()).min(1),
  requester: z.string().optional(),
});

export async function anchorRoutes(
  app: FastifyInstance,
  opts: {
    config: AnchorNodeConfig;
    store: AnchorStore;
    consensus: ConsensusEngine;
  }
) {
  const { config, store, consensus } = opts;

  // ── RECORD INTAKE ──────────────────────────────────────────────────────────

  /**
   * POST /anchor/records
   * Relay nodes submit records here for Anchor consensus.
   *
   * TSD §6.2 replication sequence step 4:
   * "Anchor nodes achieve consensus on the record and write it
   * to the authoritative ledger."
   */
  app.post("/anchor/records", async (req, reply) => {
    const body = RecordSubmitBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const { recordId, recordType, domain, payload, submittedBy } = body.data;

    console.log(
      `[provus:anchor] Record submitted: ${recordType} ${recordId.slice(0, 16)}… by ${submittedBy}`
    );

    // Run consensus
    const result = await consensus.propose(
      recordId, recordType, domain, payload, submittedBy
    );

    const status = result.confirmed ? 201 : 202; // 201=confirmed, 202=pending

    return reply.status(status).send({
      recordId,
      recordType,
      confirmed: result.confirmed,
      votes: result.votes,
      required: result.required,
      elapsed: result.elapsed,
      status: result.confirmed ? "confirmed" : "pending",
      message: result.confirmed
        ? `Record confirmed by quorum (${result.votes}/${result.required} votes, ${result.elapsed}ms)`
        : `Record pending quorum (${result.votes}/${result.required} votes so far)`,
      tsdRef: result.confirmed
        ? "TSD §6.2 — record written to authoritative ledger"
        : "TSD §6.2 — record provisional pending Anchor consensus",
    });
  });

  /**
   * POST /anchor/consensus/vote
   * Receive a vote request from a peer Anchor node.
   * Validate the record and respond with this node's vote.
   */
  app.post("/anchor/consensus/vote", async (req, reply) => {
    const body = VoteBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid vote request" });
    }

    const { recordId, recordType, domain, payload, proposerId } = body.data;

    // Simple validation: record structure looks valid
    // Production: verify proposer's signature, check attester credentials
    const vote = "confirm"; // PoC: always confirm valid records
    const signature = `${config.nodeId}:${recordId}:confirm`; // PoC signature

    const result = consensus.receiveVote(
      recordId,
      config.nodeId,
      vote,
      signature
    );

    // Also ensure record is in our store
    store.submitRecord(
      recordId,
      recordType as any,
      domain,
      payload,
      proposerId
    );

    return reply.send({
      vote,
      voterId: config.nodeId,
      recordId,
      quorumStatus: {
        confirmed: result.confirmed,
        votes: result.votes,
        required: result.required,
      },
    });
  });

  /**
   * POST /anchor/sync
   * Peer Anchor sync — exchange confirmed record counts.
   * Triggers reconciliation if counts differ.
   */
  app.post("/anchor/sync", async (req, reply) => {
    const body = req.body as any;
    const stats = store.getStats();

    return reply.send({
      nodeId: config.nodeId,
      confirmedRecords: stats.confirmedRecords,
      pendingRecords: stats.pendingRecords,
      recordsSynced: 0, // full sync in production
      timestamp: now(),
    });
  });

  // ── REVOCATION PUSH ────────────────────────────────────────────────────────

  /**
   * POST /anchor/revocation
   *
   * Record a revocation and push to all Relay nodes.
   * High-severity: immediate push to all Relays.
   * Standard: queued with normal propagation.
   *
   * TSD §6.2: "High-severity revocations use a dedicated push path —
   * Anchor → all Relay nodes out-of-band, targeting < 5 seconds."
   */
  app.post("/anchor/revocation", async (req, reply) => {
    const body = RevocationBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const { attestationId, severity, payload, submittedBy } = body.data;

    // Record in authoritative revocation log
    store.recordRevocation(attestationId, severity, payload);

    // Submit for consensus
    await consensus.propose(
      attestationId, "revocation", "global", payload, submittedBy
    );

    const start = Date.now();
    let propagatedCount = 0;

    if (severity === "high") {
      // FAST PATH: push immediately to all Relay nodes
      // TSD §6.2: target < 5 seconds full propagation
      console.log(
        `[provus:anchor] HIGH SEVERITY revocation — pushing to ${config.relayEndpoints.length} Relay(s)`
      );

      const results = await Promise.allSettled(
        config.relayEndpoints.map(async (relayEndpoint) => {
          const controller = new AbortController();
          const timeout = setTimeout(
            () => controller.abort(),
            4500 // 4.5s — within 5s target
          );

          try {
            const response = await fetch(
              `${relayEndpoint}/relay/revocation/push`,
              {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  payload,
                  severity: "high",
                  source: config.nodeId,
                }),
                signal: controller.signal,
              }
            );
            clearTimeout(timeout);
            return response.ok;
          } catch {
            clearTimeout(timeout);
            return false;
          }
        })
      );

      propagatedCount = results.filter(
        (r) => r.status === "fulfilled" && r.value === true
      ).length;

      const elapsed = Date.now() - start;
      store.markRevocationPropagated(attestationId, propagatedCount);

      console.log(
        `[provus:anchor] Revocation propagated to ${propagatedCount}/${config.relayEndpoints.length} Relay(s) ` +
        `in ${elapsed}ms (target: <5000ms, ${elapsed < 5000 ? "✓ MET" : "✗ EXCEEDED"})`
      );

      return reply.status(201).send({
        attestationId,
        severity,
        fastPath: true,
        propagatedToRelays: propagatedCount,
        totalRelays: config.relayEndpoints.length,
        elapsed,
        slaTarget: "< 5000ms",
        slaMet: elapsed < 5000,
        tsdRef: "TSD §6.2 — high-severity revocation fast path",
      });
    }

    // Standard severity: queued propagation
    return reply.status(201).send({
      attestationId,
      severity,
      fastPath: false,
      message: "Standard revocation queued for propagation",
    });
  });

  // ── AUTHORITATIVE QUERY ────────────────────────────────────────────────────

  /**
   * POST /anchor/trust/query
   *
   * Authoritative trust query — bypasses cache and Relay layer entirely.
   *
   * TSD §7.3: "Bypasses cache and Relay, goes to Anchor cluster.
   * Slower and more expensive. Use for high-stakes decisions."
   *
   * TSD §6.3: "Authoritative query (high-stakes) → bypasses cache +
   * Relay, goes directly to Anchor cluster."
   *
   * This resolves the trust query from confirmed Anchor records only —
   * no provisional records, no stale cache.
   */
  app.post("/anchor/trust/query", async (req, reply) => {
    const body = TrustQueryBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const queryId = generateId();
    store.logAuthoritativeQuery(
      queryId,
      body.data.subjectAgentId,
      body.data.requestedScope,
      body.data.requester
    );

    // Resolve from confirmed Anchor records only
    const confirmedAttestations = store
      .getConfirmedRecords("attestation")
      .filter((r) => {
        try {
          const payload = JSON.parse(r.payload);
          return payload.subjectAgentId === body.data.subjectAgentId;
        } catch {
          return false;
        }
      });

    const confirmedIdentity = store
      .getConfirmedRecords("identity")
      .find((r) => {
        try {
          const payload = JSON.parse(r.payload) as AgentIdentity;
          return payload.agentId === body.data.subjectAgentId;
        } catch {
          return false;
        }
      });

    if (!confirmedIdentity) {
      return reply.status(404).send({
        error: "Agent not found in authoritative ledger",
        agentId: body.data.subjectAgentId,
        note: "Agent may exist on VeritasMesh but has not yet reached Anchor consensus.",
      });
    }

    const identity = JSON.parse(confirmedIdentity.payload) as AgentIdentity;

    // Check scope coverage
    const requestedInScope = body.data.requestedScope.filter((cap) =>
      identity.capabilityScope.includes(cap)
    );

    // Build confidence from confirmed attestations
    const attestations = confirmedAttestations.map((r) =>
      JSON.parse(r.payload) as AttestationRecord
    );

    const validAttestations = attestations.filter((a) => {
      return new Date(a.validUntil) > new Date();
    });

    const confidenceScores = validAttestations.map((a) => a.confidenceScore);
    const avgConfidence = confidenceScores.length > 0
      ? confidenceScores.reduce((s, c) => s + c, 0) / confidenceScores.length
      : 0;

    store.markQueryResolved(queryId);

    return reply.send({
      queryId,
      authoritative: true,
      subjectAgentId: body.data.subjectAgentId,
      identity: {
        agentId: identity.agentId,
        status: identity.status,
        capabilityScope: identity.capabilityScope,
      },
      trustEnvelope: {
        recommendedScope: requestedInScope,
        confidenceInterval: [
          Math.max(0, avgConfidence - 0.05),
          Math.min(1, avgConfidence + 0.05),
        ],
        freshnessTimestamp: confirmedIdentity.confirmedAt ?? now(),
        attestationRefs: validAttestations.map((a) => a.attestationId),
        expiry: validAttestations.length > 0
          ? validAttestations.reduce((min, a) =>
              a.validUntil < min ? a.validUntil : min,
              validAttestations[0].validUntil
            )
          : new Date(Date.now() + 300_000).toISOString(),
        resolvedFrom: "authoritative",
        resolvedAt: now(),
      },
      confirmedAttestations: validAttestations.length,
      tsdRef: "TSD §6.3 — authoritative query path, bypasses cache and Relay",
    });
  });

  // ── ANCHOR STATUS ──────────────────────────────────────────────────────────

  /**
   * GET /anchor/status
   */
  app.get("/anchor/status", async (req, reply) => {
    const stats = store.getStats();
    const consensusStatus = consensus.getStatus();

    return reply.send({
      node: {
        type: "anchor",
        tier: 0,
        nodeId: config.nodeId,
        operatorId: config.operatorId,
        version: "0.1.0",
      },
      consensus: consensusStatus,
      ledger: {
        totalRecords: stats.totalRecords,
        confirmedRecords: stats.confirmedRecords,
        pendingRecords: stats.pendingRecords,
        revocations: stats.revocations,
        unpropagatedRevocations: stats.unpropagatedRevocations,
      },
      queries: {
        authoritativeQueriesServed: stats.authoritativeQueries,
      },
      relay: {
        endpoints: config.relayEndpoints,
        count: config.relayEndpoints.length,
      },
      tsdRef: "TSD §6.1 — Anchor node: write-authoritative, sync-authoritative",
      checkedAt: now(),
    });
  });

  /**
   * GET /anchor/ledger
   * Summary of confirmed authoritative records.
   */
  app.get("/anchor/ledger", async (req, reply) => {
    const confirmed = store.getConfirmedRecords();
    const byType = confirmed.reduce((acc, r) => {
      acc[r.recordType] = (acc[r.recordType] ?? 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return reply.send({
      confirmed: confirmed.length,
      byType,
      latestConfirmation: confirmed[0]?.confirmedAt ?? null,
      tsdRef: "TSD §6.2 — authoritative ledger",
    });
  });

  /**
   * GET /anchor/pending
   * Records awaiting quorum.
   */
  app.get("/anchor/pending", async (req, reply) => {
    const pending = store.getPendingRecords();
    return reply.send({
      count: pending.length,
      records: pending.map((r) => ({
        recordId: r.recordId,
        recordType: r.recordType,
        domain: r.domain,
        votes: r.quorumVotes,
        required: r.quorumRequired,
        submittedAt: r.submittedAt,
      })),
    });
  });
}
