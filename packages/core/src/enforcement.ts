/**
 * @provus/core — enforcement.ts
 *
 * Tier enforcement and anti-collusion scoring. TSD Section 5.
 *
 * Three responsibilities:
 *
 * 1. Attestation enforcement
 *    Every attestation submission is checked before being written.
 *    Wrong tier, wrong domain, unregistered attester → rejected
 *    with a signed decline record, not silently dropped.
 *
 * 2. Scope inheritance enforcement
 *    TSD §5.5 ②: "A child agent can inherit at most the parent's
 *    tier standing within the parent's credentialed domain."
 *    Trust cannot be amplified through delegation.
 *
 * 3. Anti-collusion graph scoring
 *    TSD §5.4: "The scoring function penalizes tightly clustered
 *    attestation networks with no Tier 0–2 anchoring."
 *    The floor rule: peer-only attestations cannot reach scores
 *    that substitute for higher-tier authority.
 */

import type { AttestationRecord, RevocationNotice, AgentIdentity } from "./types.js";
import type { AttesterRegistry } from "./registry.js";
import { decline } from "./attestation.js";
import { now } from "./crypto.js";
import type { HexString, ClaimType, Domain, AttesterTier } from "./types.js";

// ── ENFORCEMENT RESULTS ───────────────────────────────────────────────────────

export interface EnforcementResult {
  allowed: boolean;
  reason: string;
  effectiveTier: AttesterTier | null;
  tsdRef: string;
}

export interface GraphScoringResult {
  /** Adjusted confidence score after anti-collusion analysis */
  adjustedScore: number;

  /** Original unweighted score */
  rawScore: number;

  /** Whether the floor rule was applied */
  floorRuleApplied: boolean;

  /** Graph density of the peer attestation network [0.0–1.0] */
  peerDensity: number;

  /** Whether the agent has any Tier 0–2 attestation anchoring */
  hasHigherTierAnchor: boolean;

  /** Breakdown of contributing attestations by tier */
  tierBreakdown: Record<AttesterTier, number>;

  tsdRef: string;
}

// ── ATTESTATION ENFORCEMENT ───────────────────────────────────────────────────

/**
 * Enforce tier authority before accepting an attestation record.
 *
 * Called by Relay nodes when receiving an attestation from an Edge node.
 * TSD §4.2: "Relay nodes validate the attester signature and confirm
 * the attester's current tier standing and domain credentialing
 * before writing the record to their domain store."
 */
export function enforceAttestation(
  record: AttestationRecord,
  registry: AttesterRegistry
): EnforcementResult {
  const check = registry.checkAuthority(
    record.attesterId,
    record.claimType,
    record.domain
  );

  if (!check.authorized) {
    return {
      allowed: false,
      reason: check.reason,
      effectiveTier: check.effectiveTier,
      tsdRef: check.tsdRef,
    };
  }

  // Verify the attester's recorded tier matches the attestation's stated tier
  const registryTier = registry.getEffectiveTier(record.attesterId);
  if (registryTier !== null && record.attesterTier !== registryTier) {
    return {
      allowed: false,
      reason: `Attestation claims Tier ${record.attesterTier} but attester ` +
              `is registered as Tier ${registryTier}.`,
      effectiveTier: registryTier,
      tsdRef: "TSD §5 — attester tier must match registry record",
    };
  }

  // Confidence score sanity check
  if (record.confidenceScore < 0 || record.confidenceScore > 1) {
    return {
      allowed: false,
      reason: `Confidence score ${record.confidenceScore} is outside [0.0, 1.0]`,
      effectiveTier: registryTier,
      tsdRef: "TSD §3.2 — confidence score is probability mass [0.0–1.0]",
    };
  }

  // Check attestation hasn't already expired before being submitted
  if (new Date(record.validUntil) < new Date()) {
    return {
      allowed: false,
      reason: `Attestation validity window already expired: ${record.validUntil}`,
      effectiveTier: registryTier,
      tsdRef: "TSD §3.2 — all attestations expire",
    };
  }

  return {
    allowed: true,
    reason: `Authorized: Tier ${registryTier} attester in domain '${record.domain}'`,
    effectiveTier: registryTier,
    tsdRef: "TSD §4.2 — relay validation passed",
  };
}

// ── SCOPE INHERITANCE ENFORCEMENT ─────────────────────────────────────────────

export interface ScopeInheritanceResult {
  valid: boolean;
  violations: string[];
  tsdRef: string;
}

/**
 * Enforce scope inheritance constraints for sub-agents.
 *
 * TSD §5.5 ②: "A child agent can inherit at most the parent's tier
 * standing within the parent's credentialed domain. Trust cannot be
 * amplified through delegation — it can only be scoped down."
 *
 * TSD §3.1: "Capability scope declared at provisioning is the maximum
 * scope the agent can ever claim."
 */
export function enforceScopeInheritance(
  child: AgentIdentity,
  parent: AgentIdentity
): ScopeInheritanceResult {
  const violations: string[] = [];

  // Child cannot claim capabilities not held by parent
  const invalidCaps = child.capabilityScope.filter(
    (cap) => !parent.capabilityScope.includes(cap)
  );

  if (invalidCaps.length > 0) {
    violations.push(
      `Child claims capabilities not held by parent: ${invalidCaps.join(", ")}. ` +
      `Trust cannot be amplified through delegation.`
    );
  }

  // Lineage chain must include the parent
  if (!child.lineageChain.includes(parent.agentId)) {
    violations.push(
      `Parent agent ${parent.agentId.slice(0, 16)}… is not in child's lineage chain.`
    );
  }

  // Child cannot have a deeper scope than parent
  if (child.capabilityScope.length > parent.capabilityScope.length) {
    violations.push(
      `Child has ${child.capabilityScope.length} capabilities, parent has ` +
      `${parent.capabilityScope.length}. Child scope must be ≤ parent scope.`
    );
  }

  return {
    valid: violations.length === 0,
    violations,
    tsdRef: "TSD §5.5 ② — tier inheritance bounded, trust cannot be amplified",
  };
}

// ── ANTI-COLLUSION GRAPH SCORING ──────────────────────────────────────────────

/**
 * Apply anti-collusion graph scoring to a set of attestation records.
 *
 * TSD §5.4: "The scoring function penalizes tightly clustered attestation
 * networks with no Tier 0–2 anchoring. An agent that has only peer
 * attestations and no higher-tier endorsement should carry a floor-level
 * trust score regardless of how many peers vouch for it."
 *
 * The floor rule is the hard backstop — peer-only attestation volumes
 * cannot reach scores that substitute for authority, regardless of
 * how sophisticated the collusion ring is.
 *
 * Detection heuristics:
 *   - High ratio of Tier 3 (peer) to Tier 0–2 attestations
 *   - No higher-tier anchor in the attestation set
 *   - Attesters form a tightly clustered graph (circular attestation)
 */
export function applyGraphScoring(
  agentId: HexString,
  attestations: AttestationRecord[],
  registry: AttesterRegistry
): GraphScoringResult {

  if (attestations.length === 0) {
    return {
      adjustedScore: 0.0,
      rawScore: 0.0,
      floorRuleApplied: false,
      peerDensity: 0,
      hasHigherTierAnchor: false,
      tierBreakdown: { 0: 0, 1: 0, 2: 0, 3: 0 },
      tsdRef: "TSD §5.4 — no attestations",
    };
  }

  // Count attestations by tier
  const tierBreakdown: Record<AttesterTier, number> = { 0: 0, 1: 0, 2: 0, 3: 0 };
  const attesterIds = new Set<HexString>();

  for (const att of attestations) {
    const effectiveTier = registry.getEffectiveTier(att.attesterId) ?? att.attesterTier;
    tierBreakdown[effectiveTier as AttesterTier]++;
    attesterIds.add(att.attesterId);
  }

  const hasHigherTierAnchor =
    tierBreakdown[0] > 0 || tierBreakdown[1] > 0 || tierBreakdown[2] > 0;

  const peerCount = tierBreakdown[3];
  const totalCount = attestations.length;
  const peerDensity = peerCount / totalCount;

  // Compute raw weighted score
  const rawScore = computeWeightedScore(attestations, registry);

  // ── FLOOR RULE ────────────────────────────────────────────────────────────
  // TSD §5.4: "An agent with only peer attestations and no higher-tier
  // endorsement should carry a floor-level trust score regardless of
  // peer attestation volume."

  const FLOOR_SCORE = 0.1; // Maximum score without higher-tier anchoring

  if (!hasHigherTierAnchor) {
    return {
      adjustedScore: Math.min(rawScore, FLOOR_SCORE),
      rawScore,
      floorRuleApplied: true,
      peerDensity,
      hasHigherTierAnchor: false,
      tierBreakdown,
      tsdRef:
        "TSD §5.4 — floor rule applied: no Tier 0–2 anchor. " +
        "Peer-only attestations cannot substitute for authority.",
    };
  }

  // ── DENSITY PENALTY ───────────────────────────────────────────────────────
  // Penalize high peer density even when higher-tier anchors exist.
  // A network that is 90% peer attestations with one Tier 2 token
  // is suspicious — the Tier 2 anchor may itself be part of the ring.

  let densityPenalty = 0;

  if (peerDensity > 0.8) {
    // > 80% peer attestations — high suspicion
    densityPenalty = 0.3;
  } else if (peerDensity > 0.6) {
    // > 60% peer attestations — moderate suspicion
    densityPenalty = 0.15;
  }

  // ── CIRCULAR ATTESTATION DETECTION ───────────────────────────────────────
  // Detect when the attesting peers are themselves attested by agents
  // in the same network. This is a simplified heuristic — full graph
  // analysis requires the complete attestation graph, not just one agent's records.

  const uniqueAttesterRatio = attesterIds.size / totalCount;
  let circularPenalty = 0;

  if (uniqueAttesterRatio < 0.5 && peerCount > 3) {
    // Same attesters appearing multiple times — possible circular ring
    circularPenalty = 0.2;
    console.warn(
      `[provus:enforcement] Potential circular attestation ring detected for ` +
      `agent ${agentId.slice(0, 16)}… (unique attester ratio: ${uniqueAttesterRatio.toFixed(2)})`
    );
  }

  const adjustedScore = Math.max(0, rawScore - densityPenalty - circularPenalty);

  return {
    adjustedScore: Math.round(adjustedScore * 1000) / 1000,
    rawScore: Math.round(rawScore * 1000) / 1000,
    floorRuleApplied: false,
    peerDensity: Math.round(peerDensity * 100) / 100,
    hasHigherTierAnchor,
    tierBreakdown,
    tsdRef: densityPenalty > 0 || circularPenalty > 0
      ? "TSD §5.4 — density/circular penalty applied to peer attestation network"
      : "TSD §5.4 — graph scoring clean",
  };
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

/**
 * Compute a weighted confidence score from attestation records.
 * Weights: Tier 0 = 1.0, Tier 1 = 0.8, Tier 2 = 0.6, Tier 3 = 0.3.
 */
function computeWeightedScore(
  attestations: AttestationRecord[],
  registry: AttesterRegistry
): number {
  const TIER_WEIGHTS: Record<AttesterTier, number> = {
    0: 1.0,
    1: 0.8,
    2: 0.6,
    3: 0.3,
  };

  let totalWeight = 0;
  let weightedSum = 0;

  for (const att of attestations) {
    const effectiveTier =
      (registry.getEffectiveTier(att.attesterId) ?? att.attesterTier) as AttesterTier;
    const weight = TIER_WEIGHTS[effectiveTier];
    weightedSum += att.confidenceScore * weight;
    totalWeight += weight;
  }

  return totalWeight > 0 ? weightedSum / totalWeight : 0;
}

// ── DEMOTION PROPAGATION ──────────────────────────────────────────────────────

/**
 * When an attester is demoted, re-weight all their issued attestations.
 *
 * TSD §5.5 ③: "If a Tier 1 attester is demoted or removed, all attestations
 * they issued are re-weighted to Tier 2 standing — not invalidated, but downgraded.
 * Downstream trust queries must reflect this."
 *
 * Returns the re-weighted attestation records. The originals are not modified —
 * the caller decides what to do with the re-weighted copies.
 */
export function propagateDemotion(
  demotedAttesterId: HexString,
  attestations: AttestationRecord[]
): {
  reweighted: AttestationRecord[];
  count: number;
} {
  const affected = attestations.filter(
    (a) => a.attesterId === demotedAttesterId
  );

  const reweighted = affected.map((a) => ({
    ...a,
    attesterTier: 2 as AttesterTier, // re-weight to Tier 2
    // Note: confidenceScore unchanged — demotion affects authority weight,
    // not the attester's judgment about what they observed
  }));

  if (affected.length > 0) {
    console.log(
      `[provus:enforcement] Demotion propagated: ${affected.length} attestation(s) ` +
      `by ${demotedAttesterId.slice(0, 16)}… re-weighted to Tier 2`
    );
  }

  return { reweighted, count: affected.length };
}

// ── TIER UPGRADE CHECK ────────────────────────────────────────────────────────

/**
 * Check if a Tier 2 operator meets the admission threshold.
 *
 * TSD §5.3: "Tier 2 admission requires:
 *   1. Minimum 90 days of continuous agent activity
 *   2. At least one non-declined attestation from a Tier 1 attester
 *   3. Zero unresolved high-severity incidents"
 */
export function checkTier2Eligibility(params: {
  firstActivityAt: string;
  hasTier1Attestation: boolean;
  openHighSeverityIncidents: number;
}): { eligible: boolean; reasons: string[] } {
  const reasons: string[] = [];

  const daysSinceFirst =
    (Date.now() - new Date(params.firstActivityAt).getTime()) / 86400000;

  if (daysSinceFirst < 90) {
    reasons.push(
      `Insufficient activity tenure: ${Math.floor(daysSinceFirst)} days ` +
      `(minimum: 90 days of continuous activity).`
    );
  }

  if (!params.hasTier1Attestation) {
    reasons.push(
      "No Tier 1 attestation found. At least one non-declined Tier 1 attestation " +
      "is required within the operational window."
    );
  }

  if (params.openHighSeverityIncidents > 0) {
    reasons.push(
      `${params.openHighSeverityIncidents} unresolved high-severity incident(s). ` +
      "All high-severity incidents must have a filed rebuttal before Tier 2 admission."
    );
  }

  return {
    eligible: reasons.length === 0,
    reasons,
  };
}
