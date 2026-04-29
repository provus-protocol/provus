/**
 * @provus/core — registry.ts
 *
 * Attester registry. TSD Section 5.
 *
 * The registry is the source of truth for attester authority.
 * Every attestation submission is checked against it before
 * the record is written to the mesh.
 *
 * An attester has:
 *   - A tier (0–3) governing structural authority
 *   - A set of credentialed domains (Tier 1 only — domain-bound)
 *   - A validity window (attesters can be revoked)
 *   - A credibility score (earned through track record — separate from authority)
 *
 * TSD §5: "Authority is structural. Credibility is earned."
 *
 * Cross-tier constraints enforced here:
 *   ① Trust cannot flow upward
 *   ② Tier inheritance is bounded
 *   ③ Attester demotion propagates
 *   ④ Domain gaps surface explicitly
 *   ⑤ Authority ≠ credibility
 */

import { sign, verify, generateKeyPair, generateId, now, inSeconds } from "./crypto.js";
import type {
  AttesterTier,
  Domain,
  ClaimType,
  HexString,
} from "./types.js";
import { ProvusError } from "./types.js";

// ── REGISTRY TYPES ────────────────────────────────────────────────────────────

/**
 * An attester's registry entry.
 * This is the canonical record of their authority on the mesh.
 */
export interface AttesterRecord {
  /** The attester's public key — their identity on the mesh */
  attesterId: HexString;

  /** Display name — informational only */
  name: string;

  /**
   * Tier. Governs structural authority.
   * TSD §5: "Tier governs authority — not credibility."
   */
  tier: AttesterTier;

  /**
   * Credentialed domains. Tier 1 only — domain-bound authority.
   * Tier 0: all domains (authority is not domain-restricted at genesis).
   * Tier 2/3: not applicable (operational behavior only).
   *
   * TSD §5.2: "Domain binding is enforced at the protocol level."
   */
  credentialedDomains: Domain[];

  /**
   * Claim types this attester is authorized to issue.
   * Derived from tier and domain — but explicitly recorded for fast lookup.
   */
  authorizedClaimTypes: ClaimType[];

  /** Status. Active attesters can issue. Demoted attesters cannot. */
  status: "active" | "demoted" | "revoked";

  /**
   * Credibility score [0.0–1.0]. Earned through track record.
   * Separate from tier authority. Updated by the mesh over time.
   * TSD §5: "Authority is structural. Credibility is earned."
   */
  credibilityScore: number;

  /** ISO 8601. When this attester was admitted to the mesh. */
  admittedAt: string;

  /** ISO 8601. Admission validity expiry. */
  validUntil: string;

  /** ISO 8601. Last status change. */
  updatedAt: string;

  /**
   * The Tier 0 attester that endorsed this attester's admission.
   * Null for Tier 0 genesis attesters (self-admitting at genesis).
   * TSD §5.2: "Tier 1 attesters are endorsed by ≥1 Tier 0 anchor."
   */
  endorsedBy: HexString | null;

  /** Signature from the endorsing Tier 0 attester over this record. */
  endorsementSignature: HexString | null;

  /** History of demotion/revocation events. Append-only. */
  statusHistory: AttesterStatusEvent[];
}

export interface AttesterStatusEvent {
  previousStatus: AttesterRecord["status"];
  newStatus: AttesterRecord["status"];
  reason: string;
  changedAt: string;
  changedBy: HexString; // who made the change
}

/**
 * Result of an authority check.
 * TSD §5.4: "Domain gaps surface explicitly — no silent fallback."
 */
export interface AuthorityCheckResult {
  authorized: boolean;
  reason: string;
  effectiveTier: AttesterTier | null;
  domainMatch: boolean;
  claimTypeMatch: boolean;
  tsdRef: string;
}

// ── TIER DOMAIN MAPPING ───────────────────────────────────────────────────────

/**
 * Claim types permitted per tier.
 * TSD §5 — derived from the attester tier model.
 */
export const TIER_CLAIM_PERMISSIONS: Record<AttesterTier, ClaimType[]> = {
  0: ["capability", "behavior", "policy_compliance", "safety_evaluation", "scope_boundary"],
  1: ["capability", "behavior", "policy_compliance", "safety_evaluation", "scope_boundary"],
  2: ["capability", "behavior"],
  3: ["behavior"],
};

/**
 * Domains that require at minimum Tier 1 authority.
 * TSD §5.6: Tier 2 operators attest in operational_behavior domain only.
 */
export const TIER1_REQUIRED_DOMAINS: Domain[] = [
  "infrastructure",
  "safety_evaluation",
  "regulatory_compliance",
  "financial_services",
  "healthcare",
];

/**
 * Minimum tier required per claim type.
 */
export const CLAIM_MINIMUM_TIER: Record<ClaimType, AttesterTier> = {
  safety_evaluation:  1,
  policy_compliance:  1,
  scope_boundary:     1,
  capability:         2,
  behavior:           3,
};

// ── REGISTRY ──────────────────────────────────────────────────────────────────

export class AttesterRegistry {
  private records: Map<HexString, AttesterRecord> = new Map();

  /**
   * Register a new attester.
   * Tier 0: self-admitted at genesis (no endorser required).
   * Tier 1: must be endorsed by an active Tier 0 attester.
   * Tier 2: must meet admission threshold (handled externally).
   * Tier 3: automatic on first peer attestation.
   */
  async admit(
    record: Omit<AttesterRecord, "statusHistory">,
    endorserPrivateKey?: HexString
  ): Promise<AttesterRecord> {

    // Validate tier-specific admission requirements
    this.validateAdmission(record);

    // For Tier 1: verify endorsement signature
    if (record.tier === 1) {
      if (!record.endorsedBy || !record.endorsementSignature) {
        throw new ProvusError(
          "ATTESTER_NOT_CREDENTIALED",
          "Tier 1 admission requires endorsement by an active Tier 0 attester",
          { attesterId: record.attesterId, tier: record.tier }
        );
      }

      const endorser = this.records.get(record.endorsedBy);
      if (!endorser || endorser.tier !== 0 || endorser.status !== "active") {
        throw new ProvusError(
          "ATTESTER_NOT_CREDENTIALED",
          "Endorser is not an active Tier 0 attester",
          { endorserId: record.endorsedBy }
        );
      }

      // Verify the endorsement signature
      const sigValid = await verify(
        { attesterId: record.attesterId, tier: record.tier, domains: record.credentialedDomains },
        record.endorsementSignature,
        record.endorsedBy
      );

      if (!sigValid) {
        throw new ProvusError(
          "INVALID_SIGNATURE",
          "Endorsement signature invalid",
          { attesterId: record.attesterId }
        );
      }
    }

    const full: AttesterRecord = { ...record, statusHistory: [] };
    this.records.set(record.attesterId, full);

    console.log(
      `[provus:registry] Admitted: ${record.attesterId.slice(0, 16)}… ` +
      `Tier ${record.tier} — ${record.credentialedDomains.join(", ") || "all domains"}`
    );

    return full;
  }

  /**
   * Check if an attester has authority to issue a specific attestation.
   *
   * TSD §5.5 Cross-tier constraints:
   *   ④ Domain gaps surface explicitly — no silent fallback to lower-tier weight
   */
  checkAuthority(
    attesterId: HexString,
    claimType: ClaimType,
    domain: Domain
  ): AuthorityCheckResult {
    const record = this.records.get(attesterId);

    // Attester not in registry
    if (!record) {
      return {
        authorized: false,
        reason: `Attester ${attesterId.slice(0, 16)}… is not registered on VeritasMesh`,
        effectiveTier: null,
        domainMatch: false,
        claimTypeMatch: false,
        tsdRef: "TSD §5 — attester must be registered before issuing attestations",
      };
    }

    // Attester is demoted or revoked
    if (record.status !== "active") {
      return {
        authorized: false,
        reason: `Attester is ${record.status}. ${
          record.status === "demoted"
            ? "Issued attestations have been re-weighted to Tier 2 standing."
            : "All issued attestations are invalid."
        }`,
        effectiveTier: null,
        domainMatch: false,
        claimTypeMatch: false,
        tsdRef: "TSD §5.5 ③ — attester demotion propagates",
      };
    }

    // Admission expired
    if (new Date(record.validUntil) < new Date()) {
      return {
        authorized: false,
        reason: `Attester admission expired at ${record.validUntil}`,
        effectiveTier: null,
        domainMatch: false,
        claimTypeMatch: false,
        tsdRef: "TSD §5 — all admissions carry validity windows",
      };
    }

    // Check minimum tier for claim type
    const minTier = CLAIM_MINIMUM_TIER[claimType];
    if (record.tier > minTier) {
      return {
        authorized: false,
        reason: `Claim type '${claimType}' requires minimum Tier ${minTier}. ` +
                `Attester is Tier ${record.tier}.`,
        effectiveTier: record.tier,
        domainMatch: false,
        claimTypeMatch: false,
        tsdRef: `TSD §5 — ${claimType} requires Tier ${minTier} authority`,
      };
    }

    // Domain check for Tier 1 attesters
    if (record.tier === 1) {
      const domainAuthorized = record.credentialedDomains.includes(domain);

      if (!domainAuthorized) {
        // TSD §5.4: "Domain gaps surface explicitly — no silent fallback"
        return {
          authorized: false,
          reason: `Attester is not credentialed for domain '${domain}'. ` +
                  `Credentialed domains: ${record.credentialedDomains.join(", ")}.`,
          effectiveTier: record.tier,
          domainMatch: false,
          claimTypeMatch: true,
          tsdRef: "TSD §5.5 ④ — domain gaps surface explicitly, no silent fallback",
        };
      }
    }

    // Tier 2: can only attest in operational_behavior
    if (record.tier === 2 && domain !== "operational_behavior") {
      return {
        authorized: false,
        reason: `Tier 2 attesters can only attest in the 'operational_behavior' domain. ` +
                `Attempted: '${domain}'.`,
        effectiveTier: record.tier,
        domainMatch: false,
        claimTypeMatch: true,
        tsdRef: "TSD §5.3 — Tier 2 operator attesters: operational behavior domain only",
      };
    }

    // Claim type check
    const allowedClaims = TIER_CLAIM_PERMISSIONS[record.tier];
    if (!allowedClaims.includes(claimType)) {
      return {
        authorized: false,
        reason: `Tier ${record.tier} attesters cannot issue '${claimType}' claims. ` +
                `Allowed: ${allowedClaims.join(", ")}.`,
        effectiveTier: record.tier,
        domainMatch: true,
        claimTypeMatch: false,
        tsdRef: `TSD §5 — Tier ${record.tier} claim type restrictions`,
      };
    }

    return {
      authorized: true,
      reason: `Authorized: Tier ${record.tier} attester, domain '${domain}', claim '${claimType}'`,
      effectiveTier: record.tier,
      domainMatch: true,
      claimTypeMatch: true,
      tsdRef: "TSD §5 — authority verified",
    };
  }

  /**
   * Demote an attester.
   * TSD §5.5 ③: "Attester demotion propagates — re-weights issued
   * attestations within the propagation SLA. Does not erase them."
   */
  demote(
    attesterId: HexString,
    reason: string,
    demotedBy: HexString
  ): AttesterRecord {
    const record = this.records.get(attesterId);
    if (!record) {
      throw new ProvusError(
        "IDENTITY_NOT_FOUND",
        `Attester ${attesterId} not found in registry`
      );
    }

    const event: AttesterStatusEvent = {
      previousStatus: record.status,
      newStatus: "demoted",
      reason,
      changedAt: now(),
      changedBy: demotedBy,
    };

    const updated: AttesterRecord = {
      ...record,
      status: "demoted",
      updatedAt: now(),
      statusHistory: [...record.statusHistory, event],
    };

    this.records.set(attesterId, updated);

    console.log(
      `[provus:registry] DEMOTED: ${attesterId.slice(0, 16)}… ` +
      `Reason: ${reason}. ` +
      `Issued attestations re-weighted to Tier 2 standing.`
    );

    return updated;
  }

  /**
   * Get an attester's effective tier.
   * Demoted attesters have their tier re-weighted to 2 for scoring purposes.
   * TSD §5.5 ③.
   */
  getEffectiveTier(attesterId: HexString): AttesterTier | null {
    const record = this.records.get(attesterId);
    if (!record) return null;
    if (record.status === "demoted") return 2;
    if (record.status === "revoked") return null;
    return record.tier;
  }

  get(attesterId: HexString): AttesterRecord | null {
    return this.records.get(attesterId) ?? null;
  }

  getAll(): AttesterRecord[] {
    return Array.from(this.records.values());
  }

  getTier0Attesters(): AttesterRecord[] {
    return this.getAll().filter((r) => r.tier === 0 && r.status === "active");
  }

  getTier1Attesters(domain?: Domain): AttesterRecord[] {
    return this.getAll().filter(
      (r) =>
        r.tier === 1 &&
        r.status === "active" &&
        (!domain || r.credentialedDomains.includes(domain))
    );
  }

  private validateAdmission(record: Omit<AttesterRecord, "statusHistory">): void {
    // Tier 1 must have at least one credentialed domain
    if (record.tier === 1 && record.credentialedDomains.length === 0) {
      throw new ProvusError(
        "ATTESTER_NOT_CREDENTIALED",
        "Tier 1 attesters must have at least one credentialed domain",
        { attesterId: record.attesterId }
      );
    }

    // Tier 2 cannot claim domain credentialing
    if (record.tier === 2 && record.credentialedDomains.length > 0) {
      throw new ProvusError(
        "ATTESTER_NOT_CREDENTIALED",
        "Tier 2 attesters cannot hold domain credentialing",
        { attesterId: record.attesterId, domains: record.credentialedDomains }
      );
    }

    // Validate domains are recognized
    const validDomains: Domain[] = [
      "infrastructure", "safety_evaluation", "regulatory_compliance",
      "financial_services", "healthcare", "operational_behavior",
    ];
    for (const domain of record.credentialedDomains) {
      if (!validDomains.includes(domain)) {
        throw new ProvusError(
          "ATTESTER_NOT_CREDENTIALED",
          `Unknown domain: ${domain}`,
          { domain }
        );
      }
    }
  }
}

// ── GENESIS REGISTRY ──────────────────────────────────────────────────────────

/**
 * Bootstrap a genesis registry with a single Tier 0 attester.
 * Used in the PoC and for testing.
 *
 * TSD §5.1: "Genesis attesters are the founding Tier 0 institutions.
 * Their admission is self-certifying at genesis."
 */
export async function createGenesisRegistry(
  genesis: { attesterId: HexString; name: string }
): Promise<{ registry: AttesterRegistry; genesisRecord: AttesterRecord }> {
  const registry = new AttesterRegistry();

  const genesisRecord = await registry.admit({
    attesterId: genesis.attesterId,
    name: genesis.name,
    tier: 0,
    credentialedDomains: [
      "infrastructure", "safety_evaluation", "regulatory_compliance",
      "financial_services", "healthcare", "operational_behavior",
    ],
    authorizedClaimTypes: [
      "capability", "behavior", "policy_compliance",
      "safety_evaluation", "scope_boundary",
    ],
    status: "active",
    credibilityScore: 1.0, // Genesis: full credibility
    admittedAt: now(),
    validUntil: inSeconds(365 * 24 * 60 * 60), // 1 year
    updatedAt: now(),
    endorsedBy: null,
    endorsementSignature: null,
  });

  return { registry, genesisRecord };
}
