/**
 * @provus/sdk — validators/index.ts
 *
 * Zod schemas for every inbound request body.
 * Validation runs before any protocol logic — malformed requests
 * never reach the core.
 */

import { z } from "zod";

// ── SHARED ────────────────────────────────────────────────────────────────────

export const HexString = z.string().regex(/^[0-9a-f]+$/i, "Must be hex string");

export const Domain = z.enum([
  "infrastructure",
  "safety_evaluation",
  "regulatory_compliance",
  "financial_services",
  "healthcare",
  "operational_behavior",
]);

export const ClaimType = z.enum([
  "capability",
  "behavior",
  "policy_compliance",
  "safety_evaluation",
  "scope_boundary",
]);

export const AttesterTier = z.union([
  z.literal(0), z.literal(1), z.literal(2), z.literal(3)
]);

// ── RUNTIME INTERFACE ─────────────────────────────────────────────────────────

/**
 * POST /identity/provision
 * TSD §4.1 — Agent birth. Must complete before any agent action.
 */
export const ProvisionBody = z.object({
  orchestratorId: z.string().min(1),
  capabilityScope: z.array(z.string().min(1)).min(1, "At least one capability required"),
  intendedScope: z.string().min(1),
  mode: z.enum(["orchestrator", "enclave"]).default("orchestrator"),
  parentAgentId: z.string().optional(), // future: sub-agent provisioning
});

/**
 * POST /identity/:agentId/rotate
 * TSD §7.1 — Key rotation. Links new key to prior. Does not reset reputation.
 */
export const RotateBody = z.object({
  reason: z.string().min(1),
});

/**
 * POST /identity/:agentId/terminate
 * TSD §7.1 — Operational decommission. Not revocation.
 */
export const TerminateBody = z.object({
  reason: z.string().min(1),
});

/**
 * POST /attest/request
 * TSD §4.2 — Pull-based attestation request.
 */
export const AttestRequestBody = z.object({
  subjectAgentId: z.string().min(1),
  claimType: ClaimType,
  domain: Domain,
  evidence: z.unknown(), // any JSON — will be content-addressed
  targetTier: AttesterTier,
  requestedConfidence: z.number().min(0).max(1),
});

/**
 * POST /scope/check
 * TSD §7.1 — Synchronous gate before any agent action.
 */
export const ScopeCheckBody = z.object({
  agentId: z.string().min(1),
  action: z.string().min(1),
});

/**
 * POST /incident/record
 * TSD §4.4 — Must be callable from outside the agent process.
 */
export const IncidentBody = z.object({
  subjectAgentId: z.string().min(1),
  sessionId: z.string().min(1),
  severity: z.enum(["low", "medium", "high", "critical"]),
  visibility: z.enum(["public", "consortium", "private"]),
  description: z.string().min(1),
  reporterId: z.string().min(1),
});

/**
 * POST /incident/:incidentId/acknowledge
 */
export const AcknowledgeBody = z.object({
  operatorId: z.string().min(1),
});

// ── OPERATOR INTERFACE ────────────────────────────────────────────────────────

/**
 * POST /operator/incidents/:incidentId/rebut
 * TSD §7.2 — Signed rebuttal appended to incident. Never modifies original.
 */
export const RebuttalBody = z.object({
  operatorId: z.string().min(1),
  rebuttalText: z.string().min(1),
  evidenceRef: z.string().optional(),
});

// ── QUERY INTERFACE ───────────────────────────────────────────────────────────

const PolicyWeights = z.object({
  minimumAttesterTier: AttesterTier.default(2),
  minimumConfidence: z.number().min(0).max(1).default(0.5),
  maxRecordAgeSeconds: z.number().positive().default(7776000),
  domainWeights: z.record(z.number().min(0).max(1)).default({}),
});

/**
 * POST /trust/query
 * TSD §7.3 — Primary trust resolution. Relying party is sovereign.
 */
export const TrustQueryBody = z.object({
  subjectAgentId: z.string().min(1),
  requestedScope: z.array(z.string()).min(1),
  policyWeights: PolicyWeights.optional(),
});

/**
 * POST /trust/batch
 * TSD §7.3 — Multi-agent trust resolution for orchestrators.
 */
export const TrustBatchBody = z.object({
  agentIds: z.array(z.string()).min(1).max(100),
  requestedScope: z.array(z.string()).min(1),
  policyWeights: PolicyWeights.optional(),
});
