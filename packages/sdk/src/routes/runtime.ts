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
  registerIdentity,
  storeAttestation,
  contentAddress,
  generateId,
  now,
} from "@provus/core";
import { getState, getDefaultAttester } from "../state.js";
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

    // PoC: auto-issue via default attester
    // Production: this returns a pending request ID and the mesh routes it
    const attester = getDefaultAttester(state);
    const attestation = await issue({
      request,
      attesterId: attester.publicKey,
      attesterTier: 2,
      confidenceScore: Math.min(body.data.requestedConfidence, 0.85),
      validForSeconds: 90 * 24 * 60 * 60, // 90 days
      attesterPrivateKey: attester.privateKey,
    });

    storeAttestation(state.store, attestation);

    return reply.status(201).send({
      requestId: request.requestId,
      status: "issued",
      attestation,
      evidenceRef: request.evidenceRef,
      message: "Attestation issued. In production this routes to a credentialed VeritasMesh attester.",
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
   */
  app.post("/scope/check", async (req, reply) => {
    const body = ScopeCheckBody.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: "Invalid request", issues: body.error.issues });
    }

    const state = getState();
    const identity = state.store.identities.get(body.data.agentId);

    if (!identity) {
      return reply.send({ result: "denied", reason: "Agent not found" });
    }

    if (identity.status !== "active") {
      return reply.send({
        result: "denied",
        reason: `Agent is ${identity.status}`,
        agentId: body.data.agentId,
      });
    }

    // Check if the action falls within the agent's provisioned capability scope
    const actionInScope = identity.capabilityScope.some((cap) =>
      body.data.action.startsWith(cap) || cap === body.data.action
    );

    if (!actionInScope) {
      return reply.send({
        result: "denied",
        reason: "Action outside declared capability scope",
        action: body.data.action,
        declaredScope: identity.capabilityScope,
      });
    }

    // Check if there's attestation support for this action
    const attestations = state.store.attestations.get(body.data.agentId) ?? [];
    const hasAttestation = attestations.some(
      (a) => a.claimType === "capability" || a.claimType === "behavior"
    );

    if (!hasAttestation) {
      return reply.send({
        result: "requires-attestation",
        reason: "No attestation found for this capability. Request attestation before proceeding.",
        action: body.data.action,
      });
    }

    return reply.send({
      result: "permitted",
      action: body.data.action,
      agentId: body.data.agentId,
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
