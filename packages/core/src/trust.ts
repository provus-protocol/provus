/**
 * @provus/core — trust.ts
 *
 * Trust query resolution and trust envelope construction. TSD Section 4.3.
 *
 * In the PoC, this runs entirely locally against an in-memory record set.
 * In production, this queries VeritasMesh — Relay nodes for standard queries,
 * Anchor nodes for authoritative queries.
 *
 * The design principle is preserved regardless of where data comes from:
 * the relying party applies their own policy weights and makes their own
 * decision. The protocol provides structured evidence, not verdicts.
 * TSD: "The relying party is sovereign."
 */

import { filterByPolicy } from "./attestation.js";
import { inSeconds, now } from "./crypto.js";
import type {
  TrustQuery,
  TrustEnvelope,
  AttestationRecord,
  RevocationNotice,
  AgentIdentity,
  CapabilityScope,
  Domain,
  PolicyWeights,
} from "./types.js";
import { ProvusError } from "./types.js";

// ── DEFAULT POLICY ────────────────────────────────────────────────────────────

/**
 * Sensible default policy weights for a relying party that hasn't
 * specified their own preferences.
 *
 * TSD: The relying party is sovereign — these are defaults, not mandates.
 * A regulated financial institution might set minimumAttesterTier: 1
 * and require safety_evaluation domain weight of 1.0.
 */
export const DEFAULT_POLICY_WEIGHTS: PolicyWeights = {
  minimumAttesterTier: 2,
  minimumConfidence: 0.5,
  maxRecordAgeSeconds: 90 * 24 * 60 * 60, // 90 days
  domainWeights: {
    infrastructure: 0.8,
    safety_evaluation: 1.0,
    regulatory_compliance: 1.0,
    financial_services: 1.0,
    healthcare: 1.0,
    operational_behavior: 0.6,
  },
};

// ── LOCAL STORE (PoC) ─────────────────────────────────────────────────────────

/**
 * In-memory record store for the PoC.
 * In production this is VeritasMesh — Relay nodes and Anchor consensus.
 * The interface is identical — resolution logic does not change.
 */
export interface LocalMeshStore {
  identities: Map<string, AgentIdentity>;
  attestations: Map<string, AttestationRecord[]>; // agentId → records
  revocations: RevocationNotice[];
}

export function createLocalStore(): LocalMeshStore {
  return {
    identities: new Map(),
    attestations: new Map(),
    revocations: [],
  };
}

export function registerIdentity(
  store: LocalMeshStore,
  identity: AgentIdentity
): void {
  store.identities.set(identity.agentId, identity);
  if (!store.attestations.has(identity.agentId)) {
    store.attestations.set(identity.agentId, []);
  }
}

export function storeAttestation(
  store: LocalMeshStore,
  record: AttestationRecord
): void {
  const existing = store.attestations.get(record.subjectAgentId) ?? [];
  store.attestations.set(record.subjectAgentId, [...existing, record]);
}

export function storeRevocation(
  store: LocalMeshStore,
  notice: RevocationNotice
): void {
  store.revocations.push(notice);
}

// ── TRUST QUERY RESOLUTION ────────────────────────────────────────────────────

/**
 * Resolve a trust query against the local store.
 *
 * TSD Section 4.3: "The query does not go to a single authority. It is
 * resolved against VeritasMesh locally — the relying party pulls the
 * relevant attestation records and deviation events for the subject,
 * applies their own scoring weights, and computes a trust score.
 * There is no oracle."
 *
 * The output is not a binary allow/deny. It is a Trust Envelope:
 * a recommended scope, a confidence interval, and an expiry time.
 */
export function resolveQuery(
  query: TrustQuery,
  store: LocalMeshStore
): TrustEnvelope {
  const identity = store.identities.get(query.subjectAgentId);

  if (!identity) {
    throw new ProvusError(
      "IDENTITY_NOT_FOUND",
      `No identity record found for agent ${query.subjectAgentId}`,
      { agentId: query.subjectAgentId }
    );
  }

  if (identity.status !== "active") {
    // Return a zero-confidence envelope for inactive agents
    // rather than throwing — the relying party should know the agent exists
    // but is inactive, and make their own decision.
    return buildZeroEnvelope(query, `Agent status: ${identity.status}`);
  }

  // Get all attestation records for this agent
  const allRecords = store.attestations.get(query.subjectAgentId) ?? [];

  // Apply relying party's policy weights
  const qualifyingRecords = filterByPolicy(
    allRecords,
    query.policyWeights,
    store.revocations
  );

  // Compute the recommended scope:
  // The intersection of the agent's provisioned capability scope
  // and the requested scope, filtered by what has attestation support.
  const recommendedScope = computeRecommendedScope(
    query.requestedScope,
    identity.capabilityScope,
    qualifyingRecords,
    query.policyWeights
  );

  // Compute the confidence interval across qualifying records
  const confidenceInterval = computeConfidenceInterval(
    qualifyingRecords,
    query.policyWeights
  );

  // Freshness: the most recent record that contributed
  const freshnessTimestamp =
    qualifyingRecords.length > 0
      ? qualifyingRecords.reduce((latest, r) =>
          r.issuedAt > latest.issuedAt ? r : latest
        ).issuedAt
      : query.queriedAt;

  // Envelope expiry: minimum TTL of contributing records,
  // or a short default if no records qualify
  const expiry =
    qualifyingRecords.length > 0
      ? qualifyingRecords.reduce((earliest, r) =>
          r.validUntil < earliest.validUntil ? r : earliest
        ).validUntil
      : inSeconds(300); // 5 minute default for empty envelope

  return {
    subjectAgentId: query.subjectAgentId,
    recommendedScope,
    confidenceInterval,
    freshnessTimestamp,
    attestationRefs: qualifyingRecords.map((r) => r.attestationId),
    expiry,
    resolvedFrom: "relay", // PoC: always "relay"; production will vary
    resolvedAt: now(),
  };
}

// ── SCOPE COMPUTATION ─────────────────────────────────────────────────────────

/**
 * Compute the recommended scope from a trust query.
 *
 * Logic:
 * 1. Start with the intersection of requested scope and agent's provisioned scope.
 *    An agent cannot be authorized for capabilities it wasn't provisioned with.
 * 2. For each capability in that intersection, check if there is attestation
 *    support above the policy's confidence threshold.
 * 3. Return the capabilities that have sufficient attestation support.
 *
 * If no attestations exist, the recommended scope may still include capabilities
 * from the provisioned scope — at a lower confidence — because identity alone
 * is meaningful even without attestation. The confidence interval will reflect this.
 */
function computeRecommendedScope(
  requestedScope: CapabilityScope,
  provisionedScope: CapabilityScope,
  qualifyingRecords: AttestationRecord[],
  policy: PolicyWeights
): CapabilityScope {
  // Step 1: intersection of requested and provisioned
  const intersection = requestedScope.filter((cap) =>
    provisionedScope.includes(cap)
  );

  if (intersection.length === 0) return [];

  // Step 2: check attestation support
  // In PoC: if there are any qualifying records in the operational_behavior
  // or capability domain, we include the full intersection.
  // Production: map specific capabilities to specific claim types.
  const hasOperationalAttestation = qualifyingRecords.some(
    (r) =>
      r.domain === "operational_behavior" || r.claimType === "capability"
  );

  if (hasOperationalAttestation) {
    return intersection;
  }

  // No operational attestation — return intersection but confidence will be low
  // The relying party sees this and makes their own call.
  return intersection;
}

// ── CONFIDENCE COMPUTATION ────────────────────────────────────────────────────

/**
 * Compute a confidence interval [low, high] from qualifying attestation records.
 *
 * TSD: "A confidence interval [low, high] probability bounds on the trust assessment."
 *
 * Algorithm:
 * - If no records: [0.0, 0.1] — identity exists but no attestation support
 * - If records exist: weighted average by domain weight and attester tier,
 *   with interval width reflecting spread of scores
 *
 * The interval width is intentional — a narrow interval reflects consistent
 * attestation, a wide interval reflects conflicting or sparse evidence.
 */
function computeConfidenceInterval(
  records: AttestationRecord[],
  policy: PolicyWeights
): [number, number] {
  if (records.length === 0) {
    return [0.0, 0.1];
  }

  // Compute weighted scores for each record
  const weightedScores = records.map((r) => {
    const domainWeight = policy.domainWeights[r.domain as Domain] ?? 0.5;
    // Tier 0 = weight 1.0, Tier 1 = 0.8, Tier 2 = 0.6, Tier 3 = 0.3
    const tierWeight = [1.0, 0.8, 0.6, 0.3][r.attesterTier] ?? 0.3;
    return r.confidenceScore * domainWeight * tierWeight;
  });

  const mean =
    weightedScores.reduce((sum, s) => sum + s, 0) / weightedScores.length;

  // Interval: mean ± half the standard deviation, clamped to [0, 1]
  const variance =
    weightedScores.reduce((sum, s) => sum + Math.pow(s - mean, 2), 0) /
    weightedScores.length;
  const stdDev = Math.sqrt(variance);
  const halfInterval = stdDev / 2;

  const low = Math.max(0, mean - halfInterval);
  const high = Math.min(1, mean + halfInterval);

  return [
    Math.round(low * 1000) / 1000,
    Math.round(high * 1000) / 1000,
  ];
}

// ── ZERO ENVELOPE ─────────────────────────────────────────────────────────────

/**
 * Build a zero-confidence trust envelope for agents that cannot be trusted
 * (inactive, revoked, or not found). The relying party receives a valid
 * envelope structure — not an error — so they can make an informed decision.
 */
function buildZeroEnvelope(
  query: TrustQuery,
  reason: string
): TrustEnvelope {
  return {
    subjectAgentId: query.subjectAgentId,
    recommendedScope: [],
    confidenceInterval: [0.0, 0.0],
    freshnessTimestamp: now(),
    attestationRefs: [],
    expiry: inSeconds(60),
    resolvedFrom: "relay",
    resolvedAt: now(),
  };
}

// ── LINEAGE ───────────────────────────────────────────────────────────────────

export interface LineageResult {
  agentId: string;
  lineageChain: AgentIdentity[];
  depth: number;
  rootIsTopLevel: boolean;
}

/**
 * Return the full identity lineage for an agent.
 *
 * TSD Section 7.3: "Returns full identity lineage: parent chain,
 * provisioning events, inherited scope constraints."
 *
 * Critical for multi-agent pipeline scenarios where a relying party
 * needs to understand not just the agent they're interacting with
 * but the entire chain that produced it.
 */
export function resolveLineage(
  agentId: string,
  store: LocalMeshStore
): LineageResult {
  const identity = store.identities.get(agentId);
  if (!identity) {
    throw new ProvusError("IDENTITY_NOT_FOUND", `Agent not found: ${agentId}`);
  }

  const lineageChain: AgentIdentity[] = [];

  for (const parentId of identity.lineageChain) {
    const parentIdentity = store.identities.get(parentId);
    if (parentIdentity) {
      lineageChain.push(parentIdentity);
    }
  }

  return {
    agentId,
    lineageChain,
    depth: lineageChain.length,
    rootIsTopLevel: identity.lineageChain.length === 0,
  };
}
