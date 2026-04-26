/**
 * @provus/sdk — routes/query.ts
 *
 * Query interface. TSD Section 7.3.
 * Public-facing. Any party making a trust decision uses this surface.
 *
 * Routes:
 *   POST   /trust/query
 *   POST   /trust/query/authoritative
 *   POST   /trust/batch
 *   GET    /trust/verify/:attestationId
 *   GET    /trust/lineage/:agentId
 */

import type { FastifyInstance } from "fastify";
import {
  resolveQuery,
  resolveLineage,
  verifyAttestation,
  DEFAULT_POLICY_WEIGHTS,
  now,
  type TrustQuery,
} from "@provus/core";
import { getState } from "../state.js";
import {
  TrustQueryBody,
  TrustBatchBody,
} from "../validators/index.js";

export async function queryRoutes(app: FastifyInstance) {

  // ── TRUST RESOLUTION ───────────────────────────────────────────────────────

  /**
   * POST /trust/query
   *
   * TSD §7.3: "Primary call. Returns trust envelope. policyWeights is
   * the relying party's own scoring function — not prescribed by the SDK."
   *
   * TSD §4.3: "There is no oracle. The relying party applies their own
   * policy weights and makes their own decision."
   */
  app.post("/trust/query", async (req, reply) => {
    const body = TrustQueryBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const state = getState();

    const query: TrustQuery = {
      subjectAgentId: body.data.subjectAgentId,
      requestedScope: body.data.requestedScope,
      policyWeights: {
        ...DEFAULT_POLICY_WEIGHTS,
        ...(body.data.policyWeights ?? {}),
        domainWeights: {
          ...DEFAULT_POLICY_WEIGHTS.domainWeights,
          ...(body.data.policyWeights?.domainWeights ?? {}),
        },
      },
      queriedAt: now(),
    };

    try {
      const envelope = resolveQuery(query, state.store);
      return reply.send({
        envelope,
        // Decision guidance — the relying party makes the final call
        guidance: {
          confidence: envelope.confidenceInterval,
          scopeGranted: envelope.recommendedScope.length > 0,
          scopeCoverage: `${envelope.recommendedScope.length}/${body.data.requestedScope.length} requested capabilities supported`,
          freshness: envelope.freshnessTimestamp,
          expiry: envelope.expiry,
          tsdNote: "TSD §4.3: The relying party is sovereign. This envelope is evidence — not a verdict.",
        },
      });
    } catch (err: any) {
      if (err.code === "IDENTITY_NOT_FOUND") {
        return reply.status(404).send({ error: err.message });
      }
      throw err;
    }
  });

  /**
   * POST /trust/query/authoritative
   *
   * TSD §7.3: "Bypasses cache and Relay, goes to Anchor cluster.
   * Reserved for high-stakes decisions."
   *
   * In the PoC: same resolution as standard query, marked authoritative.
   * In production: routes to Anchor nodes, bypassing Relay cache entirely.
   */
  app.post("/trust/query/authoritative", async (req, reply) => {
    const body = TrustQueryBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const state = getState();

    const query: TrustQuery = {
      subjectAgentId: body.data.subjectAgentId,
      requestedScope: body.data.requestedScope,
      policyWeights: {
        ...DEFAULT_POLICY_WEIGHTS,
        ...(body.data.policyWeights ?? {}),
        domainWeights: {
          ...DEFAULT_POLICY_WEIGHTS.domainWeights,
          ...(body.data.policyWeights?.domainWeights ?? {}),
        },
      },
      queriedAt: now(),
    };

    try {
      const envelope = resolveQuery(query, state.store);

      // Mark as authoritative — in production this goes to Anchor consensus
      const authoritativeEnvelope = {
        ...envelope,
        resolvedFrom: "authoritative" as const,
      };

      return reply.send({
        envelope: authoritativeEnvelope,
        authoritativeNote:
          "In production: resolved against Anchor node consensus, bypassing Relay cache. " +
          "Use for high-stakes decisions (e.g. financial transactions, critical infrastructure). TSD §7.3",
      });
    } catch (err: any) {
      if (err.code === "IDENTITY_NOT_FOUND") {
        return reply.status(404).send({ error: err.message });
      }
      throw err;
    }
  });

  /**
   * POST /trust/batch
   *
   * TSD §7.3: "Resolves trust for multiple agents simultaneously.
   * Required for orchestrators evaluating candidate agent pools."
   *
   * Single-agent query latency multiplied across hundreds of agents
   * would be prohibitive. Batch is the answer.
   */
  app.post("/trust/batch", async (req, reply) => {
    const body = TrustBatchBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const state = getState();
    const results = [];
    const errors = [];

    const policyWeights = {
      ...DEFAULT_POLICY_WEIGHTS,
      ...(body.data.policyWeights ?? {}),
      domainWeights: {
        ...DEFAULT_POLICY_WEIGHTS.domainWeights,
        ...(body.data.policyWeights?.domainWeights ?? {}),
      },
    };

    for (const agentId of body.data.agentIds) {
      try {
        const query: TrustQuery = {
          subjectAgentId: agentId,
          requestedScope: body.data.requestedScope,
          policyWeights,
          queriedAt: now(),
        };

        const envelope = resolveQuery(query, state.store);
        results.push({
          agentId,
          status: "resolved",
          envelope,
          // Rank agents by confidence midpoint for orchestrator convenience
          confidenceMidpoint:
            (envelope.confidenceInterval[0] + envelope.confidenceInterval[1]) / 2,
        });
      } catch (err: any) {
        errors.push({ agentId, error: err.message });
      }
    }

    // Sort by confidence descending — highest trust agents first
    results.sort((a, b) => b.confidenceMidpoint - a.confidenceMidpoint);

    return reply.send({
      requested: body.data.agentIds.length,
      resolved: results.length,
      failed: errors.length,
      results,
      errors,
      rankedNote:
        "Results sorted by confidence midpoint descending. " +
        "Orchestrators should apply their own policy before selection. TSD §7.3",
    });
  });

  // ── VERIFICATION ───────────────────────────────────────────────────────────

  /**
   * GET /trust/verify/:attestationId
   *
   * TSD §7.3: "Independently verifies a specific attestation: checks
   * attester signature, current tier standing, and revocation notices."
   *
   * Used when a relying party wants to verify an attestation independently
   * rather than trusting the mesh's assembled envelope.
   */
  app.get<{ Params: { attestationId: string } }>(
    "/trust/verify/:attestationId",
    async (req, reply) => {
      const state = getState();
      const { attestationId } = req.params;

      // Find the attestation across all agents
      let targetAttestation = null;
      for (const [, attestations] of state.store.attestations) {
        const found = attestations.find((a) => a.attestationId === attestationId);
        if (found) {
          targetAttestation = found;
          break;
        }
      }

      if (!targetAttestation) {
        return reply.status(404).send({
          error: "Attestation not found",
          attestationId,
        });
      }

      // Get the attester's public key
      // In production: resolved from the attester's registered identity on VeritasMesh
      // In PoC: resolved from our in-memory attester registry
      const attesterKeypair = state.attesters.get(targetAttestation.attesterId);
      if (!attesterKeypair) {
        return reply.status(422).send({
          error: "Attester public key not found — cannot verify signature",
          attesterId: targetAttestation.attesterId,
          note: "In production: attester public key resolved from VeritasMesh attester registry.",
        });
      }

      const result = await verifyAttestation(
        targetAttestation,
        attesterKeypair.publicKey,
        state.store.revocations
      );

      return reply.send({
        attestationId,
        verification: result,
        attestation: targetAttestation,
        tsdRef: "TSD §7.3 — Independent verification without trusting mesh envelope",
      });
    }
  );

  // ── LINEAGE ────────────────────────────────────────────────────────────────

  /**
   * GET /trust/lineage/:agentId
   *
   * TSD §7.3: "Returns full identity lineage: parent chain, provisioning
   * events, inherited scope constraints."
   *
   * Critical for multi-agent pipeline scenarios where a relying party
   * needs to understand not just the agent they're interacting with
   * but the entire chain that produced it.
   */
  app.get<{ Params: { agentId: string } }>(
    "/trust/lineage/:agentId",
    async (req, reply) => {
      const state = getState();

      try {
        const lineage = resolveLineage(req.params.agentId, state.store);

        return reply.send({
          agentId: req.params.agentId,
          lineage,
          interpretation: {
            depth: lineage.depth,
            rootIsTopLevel: lineage.rootIsTopLevel,
            note: lineage.rootIsTopLevel
              ? "This agent was provisioned directly — no parent chain."
              : `This agent has ${lineage.depth} ancestor(s). Trust inheritance is bounded — ` +
                "child inherits at most parent's tier within parent's credentialed domain. TSD §5.5",
          },
        });
      } catch (err: any) {
        if (err.code === "IDENTITY_NOT_FOUND") {
          return reply.status(404).send({ error: err.message });
        }
        throw err;
      }
    }
  );

  // ── MESH STATUS ────────────────────────────────────────────────────────────

  /**
   * GET /trust/mesh/status
   * Returns the current state of the local mesh store.
   * Production equivalent: mesh health dashboard.
   */
  app.get("/trust/mesh/status", async (req, reply) => {
    const state = getState();

    let totalAttestations = 0;
    let activeAttestations = 0;

    for (const [, attestations] of state.store.attestations) {
      totalAttestations += attestations.length;
      activeAttestations += attestations.filter(
        (a) => !isExpiredStr(a.validUntil)
      ).length;
    }

    return reply.send({
      mesh: "local-poc",
      orchestratorPublicKey: state.orchestrator.publicKey.slice(0, 16) + "…",
      registeredAgents: state.store.identities.size,
      totalAttestations,
      activeAttestations,
      revocations: state.store.revocations.length,
      pendingRequests: state.pendingRequests.size,
      incidents: state.incidents.size,
      attesters: state.attesters.size,
      checkedAt: now(),
      note: "In production: Relay node health, Anchor quorum status, propagation latency.",
    });
  });
}

function isExpiredStr(ts: string): boolean {
  return new Date(ts) < new Date();
}
