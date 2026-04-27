/**
 * @provus/node — relay/routes.ts
 *
 * Relay node HTTP routes.
 *
 * Three surfaces:
 *
 * 1. Edge intake — receives records from Edge nodes
 *    POST /relay/identity
 *    POST /relay/attestation
 *    POST /relay/incident
 *    POST /relay/revocation
 *    POST /relay/heartbeat
 *
 * 2. Query serving — resolves trust queries for relying parties
 *    POST /relay/trust/query
 *    GET  /relay/trust/verify/:attestationId
 *    GET  /relay/trust/lineage/:agentId
 *    POST /relay/records  (peer Relay → this Relay lateral sync)
 *    POST /relay/revocation/push (high-severity fast path)
 *
 * 3. Relay status
 *    GET  /relay/status
 *    GET  /relay/edges
 *    GET  /relay/propagation/status
 */

import type { FastifyInstance } from "fastify";
import {
  resolveQuery,
  resolveLineage,
  verifyAttestation,
  DEFAULT_POLICY_WEIGHTS,
  now,
  generateId,
  type TrustQuery,
  type AttestationRecord,
  type AgentIdentity,
  type RevocationNotice,
} from "@provus/core";
import type { RelayStore } from "./store.js";
import type { PropagationManager } from "./propagation.js";
import type { RelayNodeConfig } from "./config.js";
import { z } from "zod";

const TrustQueryBody = z.object({
  subjectAgentId: z.string().min(1),
  requestedScope: z.array(z.string()).min(1),
  policyWeights: z.object({
    minimumAttesterTier: z.number().optional(),
    minimumConfidence: z.number().optional(),
    maxRecordAgeSeconds: z.number().optional(),
    domainWeights: z.record(z.number()).optional(),
  }).optional(),
});

export async function relayRoutes(
  app: FastifyInstance,
  opts: {
    config: RelayNodeConfig;
    store: RelayStore;
    propagation: PropagationManager;
  }
) {
  const { config, store, propagation } = opts;

  // ── EDGE INTAKE ────────────────────────────────────────────────────────────

  /**
   * POST /relay/identity
   * Accept an identity record from an Edge node.
   * Validates, stores, queues for Anchor and peer propagation.
   */
  app.post("/relay/identity", async (req, reply) => {
    const body = req.body as any;
    const identity = body?.identity ?? body as AgentIdentity;

    if (!identity?.agentId || !identity?.publicKey) {
      return reply.status(400).send({ error: "Invalid identity record" });
    }

    // Store in domain record set
    store.saveIdentity(identity, body?.sourceEdge);

    // Index in mesh for cross-domain queries
    store.indexRecord(
      identity.agentId,
      "identity",
      config.domain,
      `http://${config.host}:${config.port}`
    );

    // Queue for upstream Anchor and lateral peer propagation
    propagation.queueRecord(identity.agentId, "identity", identity);

    console.log(`[provus:relay] Accepted identity: ${identity.agentId.slice(0, 16)}…`);

    return reply.status(201).send({
      accepted: true,
      agentId: identity.agentId,
      domain: config.domain,
      propagation: "queued",
    });
  });

  /**
   * POST /relay/attestation
   * Accept an attestation record from an Edge node.
   *
   * TSD §4.2: "Relay nodes validate the attester signature and confirm
   * the attester's current tier standing before writing the record."
   */
  app.post("/relay/attestation", async (req, reply) => {
    const body = req.body as any;
    const attestation = body?.attestation ?? body as AttestationRecord;

    if (!attestation?.attestationId || !attestation?.subjectAgentId) {
      return reply.status(400).send({ error: "Invalid attestation record" });
    }

    // Domain check — only accept records for our credentialed domain
    // TSD §5.2: "Domain binding is enforced at the protocol level."
    if (attestation.domain !== config.domain) {
      return reply.status(422).send({
        error: "Domain mismatch",
        message: `This Relay is credentialed for '${config.domain}'. ` +
                 `Received attestation for '${attestation.domain}'.`,
        tsdRef: "TSD §5.2 — domain binding enforced at protocol level",
      });
    }

    store.saveAttestation(attestation, body?.sourceEdge);
    store.indexRecord(
      attestation.attestationId,
      "attestation",
      config.domain,
      `http://${config.host}:${config.port}`
    );

    propagation.queueRecord(
      attestation.attestationId,
      "attestation",
      attestation
    );

    console.log(
      `[provus:relay] Accepted attestation: ${attestation.attestationId.slice(0, 16)}… ` +
      `(${attestation.claimType} / ${attestation.domain})`
    );

    return reply.status(201).send({
      accepted: true,
      attestationId: attestation.attestationId,
      domain: config.domain,
      propagation: "queued",
    });
  });

  /**
   * POST /relay/revocation
   * Accept a revocation notice. High-severity triggers immediate fast-path push.
   *
   * TSD §6.2: "High-severity revocations use a dedicated push path,
   * targeting < 5 seconds full propagation."
   */
  app.post("/relay/revocation", async (req, reply) => {
    const body = req.body as any;
    const notice = body?.notice ?? body as RevocationNotice;
    const severity = body?.severity ?? "standard";

    if (!notice?.attestationId) {
      return reply.status(400).send({ error: "Invalid revocation notice" });
    }

    store.saveRevocation(notice, severity);

    // High-severity: immediate push bypassing queue cycle
    propagation.queueRecord(
      notice.attestationId,
      "revocation",
      notice,
      severity === "high" || severity === "critical" ? "high" : "standard"
    );

    console.log(
      `[provus:relay] Accepted revocation: ${notice.attestationId.slice(0, 16)}… ` +
      `(severity: ${severity})`
    );

    return reply.status(201).send({
      accepted: true,
      attestationId: notice.attestationId,
      severity,
      fastPath: severity === "high" || severity === "critical",
    });
  });

  /**
   * POST /relay/revocation/push
   * High-severity revocation fast-path endpoint.
   * Receives immediate pushes from Anchor nodes or other Relays.
   */
  app.post("/relay/revocation/push", async (req, reply) => {
    const body = req.body as any;
    const notice = body?.payload as RevocationNotice;

    if (!notice?.attestationId) {
      return reply.status(400).send({ error: "Invalid revocation notice" });
    }

    store.saveRevocation(notice, "high");
    store.markRevocationPropagated(notice.attestationId);

    console.log(
      `[provus:relay] HIGH SEVERITY revocation received (fast path): ${notice.attestationId.slice(0, 16)}…`
    );

    return reply.send({ accepted: true, fastPath: true });
  });

  /**
   * POST /relay/incident
   * Accept an incident record from an Edge node or inspector.
   */
  app.post("/relay/incident", async (req, reply) => {
    const body = req.body as any;
    if (!body?.incidentId) {
      return reply.status(400).send({ error: "Invalid incident record" });
    }

    propagation.queueRecord(body.incidentId, "incident", body);

    console.log(`[provus:relay] Accepted incident: ${body.incidentId.slice(0, 16)}…`);

    return reply.status(201).send({
      accepted: true,
      incidentId: body.incidentId,
      propagation: "queued",
    });
  });

  /**
   * POST /relay/heartbeat
   * Receive heartbeat from an Edge node.
   * TSD §6.5: Edge → Relay heartbeat every 30 seconds.
   */
  app.post("/relay/heartbeat", async (req, reply) => {
    const body = req.body as any;
    const { nodeId, operatorId, endpoint } = body ?? {};

    if (!nodeId) {
      return reply.status(400).send({ error: "nodeId required" });
    }

    // Register if first heartbeat, update if known
    store.registerEdgeNode(nodeId, operatorId ?? "unknown", endpoint);
    store.recordEdgeHeartbeat(nodeId);

    return reply.send({
      acknowledged: true,
      nodeId,
      relayDomain: config.domain,
      relayStatus: "connected",
      timestamp: now(),
    });
  });

  /**
   * POST /relay/records
   * Lateral sync — receive records from peer Relay nodes.
   */
  app.post("/relay/records", async (req, reply) => {
    const body = req.body as any;
    const { payload, source } = body ?? {};

    if (!payload) {
      return reply.status(400).send({ error: "Missing payload" });
    }

    // Store based on record type
    if (payload.agentId && payload.publicKey) {
      store.saveIdentity(payload, source);
    } else if (payload.attestationId && payload.subjectAgentId) {
      if (payload.domain === config.domain) {
        store.saveAttestation(payload, source);
      }
    } else if (payload.attestationId && payload.revokedAt) {
      store.saveRevocation(payload);
    }

    return reply.send({ accepted: true });
  });

  // ── QUERY SERVING ──────────────────────────────────────────────────────────

  /**
   * POST /relay/trust/query
   *
   * TSD §6.3: "Relay assembles trust envelope from domain store.
   * Fans out sub-queries to peer Relays for multi-domain agents."
   */
  app.post("/relay/trust/query", async (req, reply) => {
    const body = TrustQueryBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    // Build local store view from relay's domain store
    const identities = new Map(
      store.getAllIdentities().map((id) => [id.agentId, id])
    );
    const attestationMap = new Map<string, AttestationRecord[]>();
    for (const identity of identities.values()) {
      attestationMap.set(
        identity.agentId,
        store.getAttestationsForAgent(identity.agentId)
      );
    }

    const localStore = {
      identities,
      attestations: attestationMap,
      revocations: store.getRevocations(),
    };

    const query: TrustQuery = {
      subjectAgentId: body.data.subjectAgentId,
      requestedScope: body.data.requestedScope,
      policyWeights: {
        ...DEFAULT_POLICY_WEIGHTS,
        ...(body.data.policyWeights ?? {}),
        minimumAttesterTier: (body.data.policyWeights?.minimumAttesterTier ?? 2) as 0|1|2|3,
        domainWeights: {
          ...DEFAULT_POLICY_WEIGHTS.domainWeights,
          ...(body.data.policyWeights?.domainWeights ?? {}),
        },
      },
      queriedAt: now(),
    };

    try {
      const envelope = resolveQuery(query, localStore as any);

      // Check if we need to fan out to peer Relays for multi-domain data
      // TSD §6.3: "If the subject agent has records spanning multiple domains,
      // the Relay node fans out sub-queries to peer Relay nodes."
      const peerResults = await fanOutToPeers(
        body.data.subjectAgentId,
        body.data.requestedScope,
        config.peerRelayEndpoints
      );

      return reply.send({
        envelope,
        domain: config.domain,
        peerContributions: peerResults.length,
        source: "relay",
      });
    } catch (err: any) {
      if (err.code === "IDENTITY_NOT_FOUND") {
        // Check mesh index — agent may be in another domain
        const location = store.findRecord(body.data.subjectAgentId, "identity");
        if (location) {
          return reply.status(307).send({
            error: "Agent not in this domain",
            redirectTo: `${location}/relay/trust/query`,
            tsdRef: "TSD §6.3 — cross-domain fan-out",
          });
        }
        return reply.status(404).send({ error: err.message });
      }
      throw err;
    }
  });

  /**
   * GET /relay/trust/verify/:attestationId
   * Verify an attestation record against this Relay's domain store.
   */
  app.get<{ Params: { attestationId: string } }>(
    "/relay/trust/verify/:attestationId",
    async (req, reply) => {
      const attestation = store.getAttestation(req.params.attestationId);
      if (!attestation) {
        return reply.status(404).send({ error: "Attestation not found" });
      }

      // For PoC: verification uses the attestation's own public key reference
      // Production: resolve attester public key from attester registry
      return reply.send({
        attestationId: req.params.attestationId,
        attestation,
        domain: config.domain,
        anchorConfirmed: false, // would be true after Anchor consensus in production
        note: "Full signature verification requires attester public key from VeritasMesh registry.",
      });
    }
  );

  /**
   * GET /relay/trust/lineage/:agentId
   */
  app.get<{ Params: { agentId: string } }>(
    "/relay/trust/lineage/:agentId",
    async (req, reply) => {
      const identities = new Map(
        store.getAllIdentities().map((id) => [id.agentId, id])
      );
      const attestationMap = new Map<string, AttestationRecord[]>();
      for (const identity of identities.values()) {
        attestationMap.set(
          identity.agentId,
          store.getAttestationsForAgent(identity.agentId)
        );
      }

      try {
        const lineage = resolveLineage(req.params.agentId, {
          identities,
          attestations: attestationMap,
          revocations: store.getRevocations(),
        } as any);

        return reply.send({ agentId: req.params.agentId, lineage });
      } catch (err: any) {
        if (err.code === "IDENTITY_NOT_FOUND") {
          return reply.status(404).send({ error: err.message });
        }
        throw err;
      }
    }
  );

  // ── RELAY STATUS ───────────────────────────────────────────────────────────

  /**
   * GET /relay/status
   */
  app.get("/relay/status", async (req, reply) => {
    const stats = store.getStats();
    const propStatus = propagation.getStatus();

    return reply.send({
      node: {
        type: "relay",
        tier: 1,
        operatorId: config.operatorId,
        domain: config.domain,
        version: "0.1.0",
      },
      domain: {
        credentialedFor: config.domain,
        identities: stats.identities,
        attestations: stats.attestations,
        activeAttestations: stats.activeAttestations,
        revocations: stats.revocations,
      },
      propagation: {
        anchorEndpoints: propStatus.anchorEndpoints,
        peerEndpoints: propStatus.peerEndpoints,
        pendingAnchor: propStatus.pendingAnchor,
        pendingPeer: propStatus.pendingPeer,
        isFlushing: propStatus.isFlushing,
      },
      edges: {
        total: stats.edgeNodes,
        active: stats.activeEdgeNodes,
      },
      tsdRef: "TSD §6.1 — Relay node: domain-scoped record store + query serving",
      checkedAt: now(),
    });
  });

  /**
   * GET /relay/edges
   * List all registered Edge nodes and their heartbeat status.
   */
  app.get("/relay/edges", async (req, reply) => {
    const edges = store.getEdgeNodes();
    return reply.send({ count: edges.length, edges });
  });

  /**
   * GET /relay/propagation/status
   */
  app.get("/relay/propagation/status", async (req, reply) => {
    return reply.send(propagation.getStatus());
  });
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

/**
 * Fan out a trust query to peer Relay nodes for multi-domain data.
 * TSD §6.3: "If the subject agent has records spanning multiple domains,
 * the Relay node fans out sub-queries to peer Relay nodes."
 */
async function fanOutToPeers(
  agentId: string,
  requestedScope: string[],
  peerEndpoints: string[]
): Promise<any[]> {
  if (!peerEndpoints.length) return [];

  const results = await Promise.allSettled(
    peerEndpoints.map(async (endpoint) => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 2000);

        const response = await fetch(`${endpoint}/relay/trust/query`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ subjectAgentId: agentId, requestedScope }),
          signal: controller.signal,
        });

        clearTimeout(timeout);
        if (response.ok) return await response.json();
        return null;
      } catch {
        return null;
      }
    })
  );

  return results
    .filter((r) => r.status === "fulfilled" && r.value !== null)
    .map((r) => (r as PromiseFulfilledResult<any>).value);
}
