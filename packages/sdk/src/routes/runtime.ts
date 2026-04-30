/**
 * @provus/sdk — routes/runtime.ts
 *
 * Runtime interface. TSD Section 7.1.
 * Mandatory surface — a compliant agent runtime must implement all of these.
 *
 * Routes:
 *   POST   /identity/provision
 *   GET    /identity/:agentId
 *   POST   /identity/:agentId/rotate
 *   POST   /identity/:agentId/terminate
 *   POST   /attest/request
 *   GET    /attest/status/:requestId
 *   GET    /attest/list/:agentId
 *   POST   /scope/check
 *   POST   /scope/declare
 *   POST   /incident/record
 *   POST   /incident/:incidentId/acknowledge
 */

import type { FastifyInstance } from "fastify";
import {
  provision,
  verifyCertificate,
  rotate,
  terminate,
  createRequest,
  issue,
  decline,
  registerIdentity,
  storeAttestation,
  contentAddress,
  generateId,
  now,
  enforceAttestation,
} from "@provus/core";
import { getState, getAttesterForRequest } from "../state.js";
import {
  ProvisionBody,
  RotateBody,
  TerminateBody,
  AttestRequestBody,
  ScopeCheckBody,
  IncidentBody,
  AcknowledgeBody,
} from "../validators/index.js";

export async function runtimeRoutes(app: FastifyInstance) {

  // ── IDENTITY ───────────────────────────────────────────────────────────────

  /**
   * POST /identity/provision
   *
   * TSD §4.1: "The first act must be key generation and identity registration.
   * An agent that acts before it has a registered identity is invisible
   * to the trust layer."
   */
  app.post("/identity/provision", async (req, reply) => {
    const body = ProvisionBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const state = getState();
    const result = await provision(state.orchestrator.privateKey, {
      orchestratorId: body.data.orchestratorId,
      capabilityScope: body.data.capabilityScope,
      intendedScope: body.data.intendedScope,
      mode: body.data.mode,
    });

    // Register in the mesh store — from this point the agent is visible
    registerIdentity(state.store, result.identity);

    // Warm the scope cache immediately on provisioning
    // TSD §7.4: scope.check must return in <10ms for cache-warm calls
    state.scopeCache.set(result.identity.agentId, result.identity.capabilityScope);

    // Return the certificate and identity — private key goes to the caller
    // In production enclave mode: private key never leaves the enclave
    return reply.status(201).send({
      agentId: result.identity.agentId,
      publicKey: result.identity.publicKey,
      privateKey: result.privateKey, // caller holds this securely
      identity: result.identity,
      certificate: result.certificate,
      message: "Agent provisioned. Store the privateKey securely — it is not retained by the SDK.",
    });
  });

  /**
   * GET /identity/:agentId
   * Return the identity record for an agent.
   */
  app.get<{ Params: { agentId: string } }>("/identity/:agentId", async (req, reply) => {
    const state = getState();
    const identity = state.store.identities.get(req.params.agentId);
    if (!identity) {
      return reply.status(404).send({ error: "Agent not found", agentId: req.params.agentId });
    }
    return reply.send({ identity });
  });

  /**
   * POST /identity/:agentId/rotate
   *
   * TSD §7.1: "Key rotation for a live agent. Links new key to prior
   * key cryptographically. Does not reset reputation."
   */
  app.post<{ Params: { agentId: string } }>("/identity/:agentId/rotate", async (req, reply) => {
    const body = RotateBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const state = getState();
    const identity = state.store.identities.get(req.params.agentId);
    if (!identity) {
      return reply.status(404).send({ error: "Agent not found" });
    }

    // In production: the agent provides its current private key
    // In PoC: we use the orchestrator key as a stand-in for demo purposes
    // Real rotation requires the agent's actual current private key
    return reply.status(501).send({
      error: "Key rotation requires the agent's current private key.",
      message: "Call rotate() directly from @provus/core with the agent's private key. " +
               "The SDK cannot hold agent private keys — that would be a security violation.",
      tsdRef: "TSD §7.1 — SDK does not manage keys.",
    });
  });

  /**
   * POST /identity/:agentId/terminate
   *
   * TSD §7.1: "Operational decommission. Not revocation.
   * A terminated agent's record persists and is queryable."
   */
  app.post<{ Params: { agentId: string } }>("/identity/:agentId/terminate", async (req, reply) => {
    const body = TerminateBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const state = getState();
    const identity = state.store.identities.get(req.params.agentId);
    if (!identity) {
      return reply.status(404).send({ error: "Agent not found" });
    }

    // Update status in the store
    const terminated = { ...identity, status: "terminated" as const, updatedAt: now() };
    state.store.identities.set(req.params.agentId, terminated);

    // Invalidate scope cache — terminated agent must not pass scope checks
    state.scopeCache.invalidate(req.params.agentId);

    return reply.send({
      agentId: req.params.agentId,
      status: "terminated",
      reason: body.data.reason,
      terminatedAt: terminated.updatedAt,
      message: "Agent terminated. Record persists and remains queryable. This is not revocation.",
    });
  });

  // ── ATTESTATION ────────────────────────────────────────────────────────────

  /**
   * POST /attest/request
   *
   * TSD §4.2: "Pull-based — the agent/operator requests attestation.
   * Attesters do not proactively scan and endorse."
   *
   * In the PoC: auto-issues the attestation via the default attester.
   * In production: request is routed to a credentialed attester on VeritasMesh.
   */
  app.post("/attest/request", async (req, reply) => {
    const body = AttestRequestBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const state = getState();

    // Verify the subject agent exists
    const identity = state.store.identities.get(body.data.subjectAgentId);
    if (!identity) {
      return reply.status(404).send({ error: "Subject agent not found" });
    }

    // Build the attestation request
    const request = createRequest({
      subjectAgentId: body.data.subjectAgentId,
      claimType: body.data.claimType,
      domain: body.data.domain,
      evidence: body.data.evidence,
      targetTier: body.data.targetTier,
      requestedConfidence: body.data.requestedConfidence,
    });

    // Store the pending request
    state.pendingRequests.set(request.requestId, request);

    // Route to best available attester using registry
    // TSD §7.4: "Attestation routing — attester selection by tier and domain"
    const attester = getAttesterForRequest(
      state,
      body.data.targetTier,
      body.data.domain
    );

    if (!attester) {
      // No attester available for this tier/domain combination
      // TSD §5.5 ④: "Domain gaps surface explicitly — no silent fallback"
      const declineRecord = await decline(
        request,
        state.orchestrator.publicKey,
        state.orchestrator.privateKey,
        "attester_unavailable",
        `No credentialed attester available for Tier ${body.data.targetTier} ` +
        `in domain '${body.data.domain}'. ` +
        `TSD §5.5 ④: domain gaps surface explicitly.`
      );
      return reply.status(422).send({
        requestId: request.requestId,
        status: "declined",
        declineRecord,
        tsdRef: "TSD §5.5 ④ — domain gaps surface explicitly, no silent fallback",
      });
    }

    // Enforce tier authority before issuing
    // TSD §4.2: "Relay nodes validate the attester signature and confirm
    // the attester's current tier standing before writing the record."
    const preCheck = state.registry.checkAuthority(
      attester.keypair.publicKey,
      body.data.claimType,
      body.data.domain
    );

    if (!preCheck.authorized) {
      const declineRecord = await decline(
        request,
        attester.keypair.publicKey,
        attester.keypair.privateKey,
        "out_of_domain",
        preCheck.reason
      );
      return reply.status(422).send({
        requestId: request.requestId,
        status: "declined",
        declineRecord,
        enforcementReason: preCheck.reason,
        tsdRef: preCheck.tsdRef,
      });
    }

    const attestation = await issue({
      request,
      attesterId: attester.keypair.publicKey,
      attesterTier: attester.tier,
      confidenceScore: Math.min(body.data.requestedConfidence, 0.85),
      validForSeconds: 90 * 24 * 60 * 60,
      attesterPrivateKey: attester.keypair.privateKey,
    });

    // Final enforcement check on the issued record
    const enforcement = enforceAttestation(attestation, state.registry);
    if (!enforcement.allowed) {
      return reply.status(422).send({
        requestId: request.requestId,
        status: "declined",
        enforcementReason: enforcement.reason,
        tsdRef: enforcement.tsdRef,
      });
    }

    storeAttestation(state.store, attestation);

    return reply.status(201).send({
      requestId: request.requestId,
      status: "issued",
      attestation,
      evidenceRef: request.evidenceRef,
      attesterTier: attester.tier,
      attesterName: attester.name,
      enforcement: {
        tierVerified: true,
        domainVerified: true,
        effectiveTier: enforcement.effectiveTier,
      },
    });
  });

  /**
   * GET /attest/status/:requestId
   * TSD §7.1: "Returns: pending | issued | declined | expired"
   */
  app.get<{ Params: { requestId: string } }>("/attest/status/:requestId", async (req, reply) => {
    const state = getState();
    const request = state.pendingRequests.get(req.params.requestId);

    if (!request) {
      return reply.status(404).send({ error: "Request not found", requestId: req.params.requestId });
    }

    // Check if an attestation was issued for this request
    const agentAttestations = state.store.attestations.get(request.subjectAgentId) ?? [];
    const issued = agentAttestations.find((a) => a.requestId === req.params.requestId);

    return reply.send({
      requestId: req.params.requestId,
      status: issued ? "issued" : "pending",
      attestationId: issued?.attestationId ?? null,
    });
  });

  /**
   * GET /attest/list/:agentId
   * TSD §7.1: "Returns all current attestations. Runtimes should call on startup to warm cache."
   */
  app.get<{ Params: { agentId: string } }>("/attest/list/:agentId", async (req, reply) => {
    const state = getState();
    const attestations = state.store.attestations.get(req.params.agentId) ?? [];
    const revocations = state.store.revocations.filter((r) =>
      attestations.some((a) => a.attestationId === r.attestationId)
    );

    return reply.send({
      agentId: req.params.agentId,
      count: attestations.length,
      attestations,
      revocations,
    });
  });

  // ── SCOPE ──────────────────────────────────────────────────────────────────

  /**
   * POST /scope/check
   *
   * TSD §7.1: "Synchronous gate before any agent action.
   * Returns: permitted | denied | requires-attestation.
   * Must block — not advisory, not logged-only."
   *
   * TSD §7.4: "scope.check must return in <10ms for a cache-warm call."
   * Hot path: cache hit → no store read, returns in <1ms.
   */
  app.post("/scope/check", async (req, reply) => {
    const checkStart = Date.now();
    const body = ScopeCheckBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const state = getState();

    // ── HOT PATH: scope cache ─────────────────────────────────────────────
    // Cache hit: return in <1ms without touching the identity store
    const cachedScope = state.scopeCache.get(body.data.agentId);

    if (cachedScope) {
      const actionInScope = cachedScope.some(
        (cap) => body.data.action.startsWith(cap) || cap === body.data.action
      );

      if (!actionInScope) {
        return reply.send({
          result: "denied",
          reason: "Action outside declared capability scope",
          action: body.data.action,
          source: "cache",
          latencyMs: Date.now() - checkStart,
        });
      }

      // Scope permitted from cache — still check attestation support
      const attestations = state.store.attestations.get(body.data.agentId) ?? [];
      const hasAttestation = attestations.some(
        (a) => a.claimType === "capability" || a.claimType === "behavior"
      );

      return reply.send({
        result: hasAttestation ? "permitted" : "requires-attestation",
        action: body.data.action,
        agentId: body.data.agentId,
        source: "cache",
        latencyMs: Date.now() - checkStart,
        ...(hasAttestation ? {} : {
          reason: "No attestation found. Request attestation before proceeding.",
        }),
      });
    }

    // ── COLD PATH: store lookup + cache population ────────────────────────
    const identity = state.store.identities.get(body.data.agentId);

    if (!identity) {
      return reply.send({
        result: "denied",
        reason: "Agent not found",
        source: "store",
        latencyMs: Date.now() - checkStart,
      });
    }

    if (identity.status !== "active") {
      // Invalidate cache entry if agent is no longer active
      state.scopeCache.invalidate(body.data.agentId);
      return reply.send({
        result: "denied",
        reason: `Agent is ${identity.status}`,
        agentId: body.data.agentId,
        source: "store",
        latencyMs: Date.now() - checkStart,
      });
    }

    // Warm the cache for next call
    state.scopeCache.set(body.data.agentId, identity.capabilityScope);

    const actionInScope = identity.capabilityScope.some(
      (cap) => body.data.action.startsWith(cap) || cap === body.data.action
    );

    if (!actionInScope) {
      return reply.send({
        result: "denied",
        reason: "Action outside declared capability scope",
        action: body.data.action,
        declaredScope: identity.capabilityScope,
        source: "store",
        latencyMs: Date.now() - checkStart,
      });
    }

    const attestations = state.store.attestations.get(body.data.agentId) ?? [];
    const hasAttestation = attestations.some(
      (a) => a.claimType === "capability" || a.claimType === "behavior"
    );

    return reply.send({
      result: hasAttestation ? "permitted" : "requires-attestation",
      action: body.data.action,
      agentId: body.data.agentId,
      source: "store",
      latencyMs: Date.now() - checkStart,
      ...(hasAttestation ? {} : {
        reason: "No attestation found. Request attestation before proceeding.",
      }),
    });
  });

  // ── INCIDENT ───────────────────────────────────────────────────────────────

  /**
   * POST /incident/record
   *
   * TSD §7.1: "Must be callable from outside the agent process.
   * A compromised agent cannot be trusted to self-report."
   */
  app.post("/incident/record", async (req, reply) => {
    const body = IncidentBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const state = getState();

    const incident = {
      incidentId: generateId(),
      subjectAgentId: body.data.subjectAgentId,
      sessionId: body.data.sessionId,
      severity: body.data.severity,
      visibility: body.data.visibility,
      description: body.data.description,
      reporterId: body.data.reporterId,
      reporterSignature: "poc-signature", // production: signed by reporter's key
      recordedAt: now(),
    };

    state.incidents.set(incident.incidentId, incident);

    // Critical: if high severity, this would trigger the fast-path push
    // to all VeritasMesh Relay nodes (TSD §6.2 — revocation fast path)
    if (incident.severity === "critical" || incident.severity === "high") {
      console.log(`[provus:incident] HIGH SEVERITY incident recorded: ${incident.incidentId}`);
      console.log(`[provus:incident] Production: fast-path push to all Relay nodes (<5s)`);
    }

    return reply.status(201).send({
      incidentId: incident.incidentId,
      severity: incident.severity,
      visibility: incident.visibility,
      recordedAt: incident.recordedAt,
      message: incident.severity === "high" || incident.severity === "critical"
        ? "High-severity incident recorded. Operators must acknowledge within 48h to maintain Tier 2 standing."
        : "Incident recorded.",
    });
  });

  /**
   * POST /incident/:incidentId/acknowledge
   * TSD §7.1: "Required within 48h of high-severity incident for Tier 2 standing."
   */
  app.post<{ Params: { incidentId: string } }>("/incident/:incidentId/acknowledge", async (req, reply) => {
    const body = AcknowledgeBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const state = getState();
    const incident = state.incidents.get(req.params.incidentId);
    if (!incident) {
      return reply.status(404).send({ error: "Incident not found" });
    }

    return reply.send({
      incidentId: req.params.incidentId,
      acknowledgedBy: body.data.operatorId,
      acknowledgedAt: now(),
      message: "Incident acknowledged. File a rebuttal via POST /operator/incidents/:id/rebut if contested.",
    });
  });
}
