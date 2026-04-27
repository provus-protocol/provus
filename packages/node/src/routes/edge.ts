/**
 * @provus/node — routes/edge.ts
 *
 * Edge node HTTP routes.
 *
 * The Edge node exposes a subset of the SDK surface, backed by
 * persistent SQLite storage and Relay submission logic.
 *
 * Routes:
 *   POST  /edge/identity/provision    — provision agent, queue upstream
 *   GET   /edge/identity/:agentId     — get identity from local store
 *   POST  /edge/attest/request        — request attestation, queue upstream
 *   GET   /edge/attest/list/:agentId  — list attestations from local store
 *   POST  /edge/trust/query           — local-first trust query with cache
 *   GET   /edge/node/status           — node health, relay status, queue depth
 *   GET   /edge/node/queue            — pending submission queue
 */

import type { FastifyInstance } from "fastify";
import {
  provision,
  createRequest,
  issue,
  resolveQuery,
  DEFAULT_POLICY_WEIGHTS,
  contentAddress,
  generateKeyPair,
  now,
  type TrustQuery,
} from "@provus/core";
import type { EdgeStore } from "../store/db.js";
import type { HeartbeatManager } from "../heartbeat/manager.js";
import type { SubmissionQueue } from "../queue/manager.js";
import type { EdgeNodeConfig } from "../config.js";
import { z } from "zod";

// ── VALIDATORS ────────────────────────────────────────────────────────────────

const ProvisionBody = z.object({
  orchestratorId: z.string().min(1),
  capabilityScope: z.array(z.string()).min(1),
  intendedScope: z.string().min(1),
  mode: z.enum(["orchestrator", "enclave"]).default("orchestrator"),
});

const AttestBody = z.object({
  subjectAgentId: z.string().min(1),
  claimType: z.enum(["capability", "behavior", "policy_compliance", "safety_evaluation", "scope_boundary"]),
  domain: z.enum(["infrastructure", "safety_evaluation", "regulatory_compliance", "financial_services", "healthcare", "operational_behavior"]),
  evidence: z.unknown(),
  targetTier: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]),
  requestedConfidence: z.number().min(0).max(1),
});

const TrustQueryBody = z.object({
  subjectAgentId: z.string().min(1),
  requestedScope: z.array(z.string()).min(1),
  policyWeights: z.object({
    minimumAttesterTier: z.number().optional(),
    minimumConfidence: z.number().optional(),
    maxRecordAgeSeconds: z.number().optional(),
    domainWeights: z.record(z.number()).optional(),
  }).optional(),
  forceRelay: z.boolean().default(false),
});

// ── ROUTES ────────────────────────────────────────────────────────────────────

export async function edgeRoutes(
  app: FastifyInstance,
  opts: {
    config: EdgeNodeConfig;
    store: EdgeStore;
    heartbeat: HeartbeatManager;
    queue: SubmissionQueue;
    orchestratorPrivateKey: string;
    defaultAttesterPrivateKey: string;
    defaultAttesterPublicKey: string;
  }
) {
  const {
    config,
    store,
    heartbeat,
    queue,
    orchestratorPrivateKey,
    defaultAttesterPrivateKey,
    defaultAttesterPublicKey,
  } = opts;

  // ── IDENTITY ───────────────────────────────────────────────────────────────

  /**
   * POST /edge/identity/provision
   *
   * Provisions an agent and submits the Provenance Certificate upstream.
   * TSD §4.1 — must complete before any agent action.
   */
  app.post("/edge/identity/provision", async (req, reply) => {
    const body = ProvisionBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const result = await provision(orchestratorPrivateKey, {
      orchestratorId: body.data.orchestratorId,
      capabilityScope: body.data.capabilityScope,
      intendedScope: body.data.intendedScope,
      mode: body.data.mode,
    });

    // Persist locally first — always
    store.saveIdentity(result.identity);

    // Submit upstream or queue
    const submissionResult = await queue.submitOrQueue(
      result.identity.agentId,
      "identity",
      result.certificate
    );

    return reply.status(201).send({
      agentId: result.identity.agentId,
      publicKey: result.identity.publicKey,
      privateKey: result.privateKey,
      identity: result.identity,
      certificate: result.certificate,
      upstream: submissionResult,
      relayStatus: heartbeat.getStatus(),
    });
  });

  /**
   * GET /edge/identity/:agentId
   * Returns identity from local store — no relay call needed.
   */
  app.get<{ Params: { agentId: string } }>(
    "/edge/identity/:agentId",
    async (req, reply) => {
      const identity = store.getIdentity(req.params.agentId);
      if (!identity) {
        return reply.status(404).send({ error: "Agent not found" });
      }
      return reply.send({ identity });
    }
  );

  // ── ATTESTATION ────────────────────────────────────────────────────────────

  /**
   * POST /edge/attest/request
   *
   * Issues an attestation and queues it for upstream relay submission.
   */
  app.post("/edge/attest/request", async (req, reply) => {
    const body = AttestBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const identity = store.getIdentity(body.data.subjectAgentId);
    if (!identity) {
      return reply.status(404).send({ error: "Subject agent not found" });
    }

    const request = createRequest({
      subjectAgentId: body.data.subjectAgentId,
      claimType: body.data.claimType,
      domain: body.data.domain,
      evidence: body.data.evidence,
      targetTier: body.data.targetTier,
      requestedConfidence: body.data.requestedConfidence,
    });

    const attestation = await issue({
      request,
      attesterId: defaultAttesterPublicKey,
      attesterTier: 2,
      confidenceScore: Math.min(body.data.requestedConfidence, 0.85),
      validForSeconds: 90 * 24 * 60 * 60,
      attesterPrivateKey: defaultAttesterPrivateKey,
    });

    // Persist locally
    store.saveAttestation(attestation);

    // Submit upstream or queue
    const submissionResult = await queue.submitOrQueue(
      attestation.attestationId,
      "attestation",
      attestation
    );

    return reply.status(201).send({
      attestation,
      upstream: submissionResult,
      relayStatus: heartbeat.getStatus(),
    });
  });

  /**
   * GET /edge/attest/list/:agentId
   * Returns attestations from local store.
   */
  app.get<{ Params: { agentId: string } }>(
    "/edge/attest/list/:agentId",
    async (req, reply) => {
      const attestations = store.getAttestationsForAgent(req.params.agentId);
      const revocations = store.getRevocations().filter((r) =>
        attestations.some((a) => a.attestationId === r.attestationId)
      );
      return reply.send({ count: attestations.length, attestations, revocations });
    }
  );

  // ── TRUST QUERY ────────────────────────────────────────────────────────────

  /**
   * POST /edge/trust/query
   *
   * Local-first trust query with cache.
   *
   * TSD §6.3 — resolution strategy:
   *   1. Cache hit + valid TTL → return immediately
   *   2. Cache hit + expired TTL → re-query Relay, update cache
   *   3. Cache miss → query Relay
   *   4. Relay unreachable → serve stale cache with staleness flag
   */
  app.post("/edge/trust/query", async (req, reply) => {
    const body = TrustQueryBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const scopeHash = contentAddress(body.data.requestedScope);
    const relayStatus = heartbeat.getStatus();

    // Step 1: Check local cache
    if (!body.data.forceRelay) {
      const cached = store.getCachedQuery(body.data.subjectAgentId, scopeHash);

      if (cached) {
        const envelope = JSON.parse(cached.envelope);

        if (!cached.stale) {
          // Cache hit, valid TTL — return immediately
          return reply.send({
            envelope,
            source: "cache",
            stale: false,
            relayStatus,
          });
        }

        if (relayStatus !== "connected") {
          // Cache hit but stale, Relay unreachable — serve with staleness flag
          // TSD §6.4: "Availability over consistency — serve stale cache
          // with explicit staleness flag if Relay is down."
          return reply.send({
            envelope,
            source: "cache",
            stale: true,
            stalenessWarning:
              "Relay unreachable — this envelope may not reflect recent changes. " +
              "TSD §6.4: Edge node serving stale cache in degraded mode.",
            relayStatus,
          });
        }
      }
    }

    // Step 2: Relay is reachable — resolve from local store
    // (In production: proxy to Relay node for authoritative data)
    // For PoC: resolve locally with what we have

    const identities = new Map(
      store.getAllIdentities().map((id) => [id.agentId, id])
    );
    const attestationMap = new Map<string, any[]>();
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

    try {
      const query: TrustQuery = {
        subjectAgentId: body.data.subjectAgentId,
        requestedScope: body.data.requestedScope,
        policyWeights: {
          ...DEFAULT_POLICY_WEIGHTS,
          ...(body.data.policyWeights ?? {}),
          minimumAttesterTier: (body.data.policyWeights?.minimumAttesterTier ?? 2) as 0 | 1 | 2 | 3,
          domainWeights: {
            ...DEFAULT_POLICY_WEIGHTS.domainWeights,
            ...(body.data.policyWeights?.domainWeights ?? {}),
          },
        },
        queriedAt: now(),
      };

      const envelope = resolveQuery(query, localStore as any);

      // Cache the result
      store.setCachedQuery(
        body.data.subjectAgentId,
        scopeHash,
        envelope,
        config.cacheTtlSeconds
      );

      return reply.send({
        envelope,
        source: relayStatus === "connected" ? "relay" : "local",
        stale: false,
        relayStatus,
      });
    } catch (err: any) {
      if (err.code === "IDENTITY_NOT_FOUND") {
        return reply.status(404).send({ error: err.message });
      }
      throw err;
    }
  });

  // ── NODE STATUS ────────────────────────────────────────────────────────────

  /**
   * GET /edge/node/status
   * Node health, relay status, queue depth, cache stats.
   */
  app.get("/edge/node/status", async (req, reply) => {
    const nodeState = store.getNodeState();
    const queueStatus = queue.getStatus();
    const identities = store.getAllIdentities();

    return reply.send({
      node: {
        operatorId: config.operatorId,
        type: "edge",
        tier: 2,
        version: "0.1.0",
        startedAt: nodeState.startedAt,
      },
      relay: {
        endpoint: config.relayEndpoint,
        status: heartbeat.getStatus(),
        missedHeartbeats: heartbeat.getMissedBeats(),
        lastContact: nodeState.lastRelayContactAt,
        degradedThreshold: config.heartbeatDegradedThreshold,
        offlineThreshold: config.heartbeatOfflineThreshold,
      },
      store: {
        agents: identities.length,
        activeAgents: identities.filter((i) => i.status === "active").length,
      },
      queue: {
        pending: queueStatus.pending,
        isFlushing: queueStatus.isFlushing,
        maxDepth: config.queueMaxDepth,
        maxAgeHours: config.queueMaxAgeMs / 3600000,
      },
      tsdRef: "TSD §6.1 — Edge node: lightweight Tier 2 operator node",
      checkedAt: now(),
    });
  });

  /**
   * GET /edge/node/queue
   * Pending submission queue — useful for operator debugging.
   */
  app.get("/edge/node/queue", async (req, reply) => {
    const pending = store.getPendingSubmissions();
    return reply.send({
      count: pending.length,
      items: pending.map((item) => ({
        id: item.id,
        type: item.type,
        queuedAt: item.queuedAt,
        attempts: item.attempts,
        lastAttemptAt: item.lastAttemptAt,
        status: item.status,
      })),
    });
  });

  /**
   * POST /edge/node/flush
   * Manually trigger a queue flush — useful after connectivity is restored.
   */
  app.post("/edge/node/flush", async (req, reply) => {
    if (heartbeat.getStatus() !== "connected") {
      return reply.status(503).send({
        error: "Relay unreachable",
        relayStatus: heartbeat.getStatus(),
        message: "Cannot flush queue — Relay node is not reachable.",
      });
    }

    queue.flush().catch(console.error);
    return reply.send({ message: "Queue flush started", relayStatus: heartbeat.getStatus() });
  });
}
