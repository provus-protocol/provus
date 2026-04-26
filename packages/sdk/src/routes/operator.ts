/**
 * @provus/sdk — routes/operator.ts
 *
 * Operator interface. TSD Section 7.2.
 * Fleet management, attestation coverage, incident response.
 *
 * Routes:
 *   GET    /operator/agents
 *   GET    /operator/agents/:agentId/audit
 *   GET    /operator/attestations/coverage
 *   POST   /operator/attestations/request
 *   GET    /operator/incidents
 *   POST   /operator/incidents/:incidentId/rebut
 */

import type { FastifyInstance } from "fastify";
import {
  isExpired,
  ageInSeconds,
  now,
  generateId,
  contentAddress,
} from "@provus/core";
import { getState } from "../state.js";
import { RebuttalBody, AttestRequestBody } from "../validators/index.js";

export async function operatorRoutes(app: FastifyInstance) {

  // ── FLEET MANAGEMENT ───────────────────────────────────────────────────────

  /**
   * GET /operator/agents
   *
   * TSD §7.2: "All agents under this operator with current trust envelope,
   * attestation status, open incidents."
   */
  app.get("/operator/agents", async (req, reply) => {
    const state = getState();
    const agents = [];

    for (const [agentId, identity] of state.store.identities) {
      const attestations = state.store.attestations.get(agentId) ?? [];
      const activeAttestations = attestations.filter((a) => !isExpired(a.validUntil));
      const expiredAttestations = attestations.filter((a) => isExpired(a.validUntil));

      // Find open incidents for this agent
      const openIncidents = [...state.incidents.values()].filter(
        (i) => i.subjectAgentId === agentId
      );

      agents.push({
        agentId,
        status: identity.status,
        capabilityScope: identity.capabilityScope,
        provisionedAt: identity.originContext.provisionedAt,
        attestationSummary: {
          total: attestations.length,
          active: activeAttestations.length,
          expired: expiredAttestations.length,
        },
        openIncidents: openIncidents.length,
        highSeverityIncidents: openIncidents.filter(
          (i) => i.severity === "high" || i.severity === "critical"
        ).length,
      });
    }

    return reply.send({
      count: agents.length,
      agents,
    });
  });

  /**
   * GET /operator/agents/:agentId/audit
   *
   * TSD §7.2: "Full activity record for compliance and auditor export.
   * Auditor-exportable output required for regulated operators."
   */
  app.get<{
    Params: { agentId: string };
    Querystring: { from?: string; to?: string };
  }>("/operator/agents/:agentId/audit", async (req, reply) => {
    const state = getState();
    const { agentId } = req.params;
    const { from, to } = req.query;

    const identity = state.store.identities.get(agentId);
    if (!identity) {
      return reply.status(404).send({ error: "Agent not found", agentId });
    }

    const fromTs = from ? new Date(from).getTime() : 0;
    const toTs = to ? new Date(to).getTime() : Date.now();

    const attestations = (state.store.attestations.get(agentId) ?? []).filter((a) => {
      const ts = new Date(a.issuedAt).getTime();
      return ts >= fromTs && ts <= toTs;
    });

    const revocations = state.store.revocations.filter((r) =>
      attestations.some((a) => a.attestationId === r.attestationId)
    );

    const incidents = [...state.incidents.values()].filter((i) => {
      const ts = new Date(i.recordedAt).getTime();
      return i.subjectAgentId === agentId && ts >= fromTs && ts <= toTs;
    });

    const rebuttals = incidents.flatMap((i) =>
      state.rebuttals.get(i.incidentId) ?? []
    );

    return reply.send({
      agentId,
      identity,
      auditPeriod: {
        from: from ?? identity.originContext.provisionedAt,
        to: to ?? now(),
      },
      attestations: {
        count: attestations.length,
        records: attestations,
      },
      revocations: {
        count: revocations.length,
        records: revocations,
      },
      incidents: {
        count: incidents.length,
        records: incidents,
      },
      rebuttals: {
        count: rebuttals.length,
        records: rebuttals,
      },
      // Auditor export metadata
      exportedAt: now(),
      exportFormat: "provus-audit-v0.1",
      tsdRef: "TSD §7.2 — Auditor-exportable output",
    });
  });

  // ── ATTESTATION MANAGEMENT ─────────────────────────────────────────────────

  /**
   * GET /operator/attestations/coverage
   *
   * TSD §7.2: "Returns coverage report: gaps and attestations approaching
   * expiry across the fleet. Silent expiry is a critical operational risk."
   */
  app.get("/operator/attestations/coverage", async (req, reply) => {
    const state = getState();
    const EXPIRY_WARNING_SECONDS = 7 * 24 * 60 * 60; // 7 days

    const coverage = [];

    for (const [agentId, identity] of state.store.identities) {
      if (identity.status !== "active") continue;

      const attestations = state.store.attestations.get(agentId) ?? [];
      const active = attestations.filter((a) => !isExpired(a.validUntil));
      const approachingExpiry = active.filter((a) => {
        const secondsLeft =
          (new Date(a.validUntil).getTime() - Date.now()) / 1000;
        return secondsLeft < EXPIRY_WARNING_SECONDS;
      });

      // Determine which claim types have no active attestation
      const attestedClaimTypes = new Set(active.map((a) => a.claimType));
      const gaps: string[] = [];

      // Every active agent should have at least a behavior attestation
      if (!attestedClaimTypes.has("behavior")) gaps.push("behavior");
      if (!attestedClaimTypes.has("capability")) gaps.push("capability");

      coverage.push({
        agentId,
        status: identity.status,
        activeAttestations: active.length,
        approachingExpiry: approachingExpiry.map((a) => ({
          attestationId: a.attestationId,
          claimType: a.claimType,
          domain: a.domain,
          validUntil: a.validUntil,
          daysLeft: Math.round(
            (new Date(a.validUntil).getTime() - Date.now()) / 86400000
          ),
        })),
        gaps,
        coverageStatus:
          gaps.length === 0 && approachingExpiry.length === 0
            ? "healthy"
            : gaps.length > 0
            ? "gap"
            : "expiring-soon",
      });
    }

    const summary = {
      total: coverage.length,
      healthy: coverage.filter((c) => c.coverageStatus === "healthy").length,
      gaps: coverage.filter((c) => c.coverageStatus === "gap").length,
      expiringSoon: coverage.filter((c) => c.coverageStatus === "expiring-soon").length,
    };

    return reply.send({
      summary,
      coverage,
      checkedAt: now(),
      warning:
        summary.gaps > 0
          ? `${summary.gaps} agent(s) have attestation gaps. Silent expiry is a critical operational risk. TSD §7.2`
          : null,
    });
  });

  /**
   * POST /operator/attestations/request
   *
   * TSD §7.2: "Fleet-level wrapper supporting batch requests
   * and coverage gap tracking."
   */
  app.post("/operator/attestations/request", async (req, reply) => {
    // Delegate to the runtime attestation endpoint logic
    // In production: supports batch requests across a fleet
    return reply.status(307).send({
      message: "Use POST /attest/request for individual attestation requests.",
      batchSupport: "Coming in v0.2.0 — batch fleet attestation requests.",
    });
  });

  // ── INCIDENT MANAGEMENT ────────────────────────────────────────────────────

  /**
   * GET /operator/incidents
   *
   * TSD §7.2: "Fleet-wide incidents filterable by severity, status, time range."
   */
  app.get<{
    Querystring: {
      severity?: string;
      agentId?: string;
      from?: string;
      to?: string;
    };
  }>("/operator/incidents", async (req, reply) => {
    const state = getState();
    const { severity, agentId, from, to } = req.query;

    const fromTs = from ? new Date(from).getTime() : 0;
    const toTs = to ? new Date(to).getTime() : Date.now();

    let incidents = [...state.incidents.values()].filter((i) => {
      const ts = new Date(i.recordedAt).getTime();
      return ts >= fromTs && ts <= toTs;
    });

    if (severity) {
      incidents = incidents.filter((i) => i.severity === severity);
    }

    if (agentId) {
      incidents = incidents.filter((i) => i.subjectAgentId === agentId);
    }

    // Attach rebuttals to each incident
    const withRebuttals = incidents.map((i) => ({
      ...i,
      rebuttals: state.rebuttals.get(i.incidentId) ?? [],
    }));

    return reply.send({
      count: withRebuttals.length,
      incidents: withRebuttals,
    });
  });

  /**
   * POST /operator/incidents/:incidentId/rebut
   *
   * TSD §7.2: "Signed rebuttal appended to the incident record.
   * Cannot modify the original."
   *
   * TSD §4.4: "The original incident is not deleted; the rebuttal is
   * appended. Downstream consumers weight rebuttals as they see fit."
   */
  app.post<{ Params: { incidentId: string } }>(
    "/operator/incidents/:incidentId/rebut",
    async (req, reply) => {
      const body = RebuttalBody.safeParse(req.body);
      if (!body.success) {
        return reply
          .status(400)
          .send({ error: "Invalid request", issues: body.error.issues });
      }

      const state = getState();
      const incident = state.incidents.get(req.params.incidentId);
      if (!incident) {
        return reply.status(404).send({ error: "Incident not found" });
      }

      const rebuttal = {
        incidentId: req.params.incidentId,
        operatorId: body.data.operatorId,
        rebuttalText: body.data.rebuttalText,
        evidenceRef: body.data.evidenceRef
          ? contentAddress(body.data.evidenceRef)
          : null,
        operatorSignature: "poc-signature", // production: signed by operator key
        submittedAt: now(),
      };

      // Append — never replace
      const existing = state.rebuttals.get(req.params.incidentId) ?? [];
      state.rebuttals.set(req.params.incidentId, [...existing, rebuttal]);

      return reply.status(201).send({
        rebuttal,
        message:
          "Rebuttal appended to incident record. The original incident is not modified. " +
          "Downstream trust scoring functions weight rebuttals independently. TSD §4.4",
      });
    }
  );
}
