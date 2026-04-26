/**
 * @provus/core — attestation.ts
 *
 * Attestation issuance, verification, and revocation. TSD Section 4.2.
 *
 * Four operations:
 *   createRequest()   — build an attestation request
 *   issue()           — attester issues a signed attestation record
 *   decline()         — attester declines with a signed reason record
 *   revoke()          — attester appends a revocation notice (never erases)
 *   verify()          — verify an attestation record's signature and validity
 */

import {
  sign,
  verify as cryptoVerify,
  contentAddress,
  generateId,
  now,
  inSeconds,
  isExpired,
  ageInSeconds,
} from "./crypto.js";
import type {
  AttestationRequest,
  AttestationRecord,
  DeclineRecord,
  DeclineReason,
  RevocationNotice,
  AgentIdentity,
  ClaimType,
  Domain,
  AttesterTier,
  HexString,
  PolicyWeights,
} from "./types.js";
import { ProvusError } from "./types.js";

// ── REQUEST ───────────────────────────────────────────────────────────────────

export interface CreateRequestConfig {
  subjectAgentId: HexString;
  claimType: ClaimType;
  domain: Domain;

  /**
   * The evidence artifact itself — any JSON-serializable object.
   * The request stores its content-addressed hash, not the artifact.
   * TSD: "The evidence itself is not embedded — it is referenced."
   */
  evidence: unknown;

  targetTier: AttesterTier;

  /**
   * Requested confidence level [0.0–1.0].
   * Higher signals willingness to provide more evidence or absorb higher cost.
   */
  requestedConfidence: number;
}

/**
 * Build an attestation request.
 * Pull-based: the agent/operator constructs and submits this.
 * The mesh routes it to an available credentialed attester.
 */
export function createRequest(
  config: CreateRequestConfig
): AttestationRequest {
  if (config.requestedConfidence < 0 || config.requestedConfidence > 1) {
    throw new ProvusError(
      "EVIDENCE_REF_INVALID",
      "requestedConfidence must be between 0.0 and 1.0",
      { requestedConfidence: config.requestedConfidence }
    );
  }

  return {
    requestId: generateId(),
    subjectAgentId: config.subjectAgentId,
    claimType: config.claimType,
    domain: config.domain,
    evidenceRef: contentAddress(config.evidence),
    targetTier: config.targetTier,
    requestedConfidence: config.requestedConfidence,
    requestedAt: now(),
  };
}

// ── ISSUANCE ──────────────────────────────────────────────────────────────────

export interface IssueConfig {
  /** The request being responded to. */
  request: AttestationRequest;

  /** The attester's identity. */
  attesterId: HexString;

  /** The attester's tier at time of issuance. Recorded — cannot be retroactively elevated. */
  attesterTier: AttesterTier;

  /**
   * The attester's actual confidence in the claim [0.0–1.0].
   * May differ from the requested confidence — the attester is honest
   * about their own uncertainty, not obligated to hit a target.
   * TSD: "Not boolean. Reflects depth of evidence and attester uncertainty."
   */
  confidenceScore: number;

  /**
   * How long this attestation is valid, in seconds.
   * All attestations expire. TSD: "No trust assertion is permanent."
   * Sensible defaults by tier:
   *   Tier 0: up to 1 year (31536000s)
   *   Tier 1: up to 6 months (15552000s)
   *   Tier 2: up to 90 days (7776000s)
   *   Tier 3: up to 30 days (2592000s)
   */
  validForSeconds: number;

  /** The attester's private key for signing. */
  attesterPrivateKey: HexString;
}

/**
 * Issue an attestation record.
 *
 * TSD Section 4.2: "The attester evaluates and issues an Attestation Record.
 * Attestation records are published to VeritasMesh — not held privately by
 * the attester. Once issued, the attester cannot unilaterally delete a record;
 * they can only issue a Revocation Notice."
 */
export async function issue(config: IssueConfig): Promise<AttestationRecord> {
  if (config.confidenceScore < 0 || config.confidenceScore > 1) {
    throw new ProvusError(
      "EVIDENCE_REF_INVALID",
      "confidenceScore must be between 0.0 and 1.0",
      { confidenceScore: config.confidenceScore }
    );
  }

  if (config.validForSeconds <= 0) {
    throw new ProvusError(
      "EVIDENCE_REF_INVALID",
      "validForSeconds must be positive",
      { validForSeconds: config.validForSeconds }
    );
  }

  const timestamp = now();

  // Build the record without the signature first — we sign the record itself
  const recordWithoutSig: Omit<AttestationRecord, "attesterSignature"> = {
    attestationId: generateId(),
    subjectAgentId: config.request.subjectAgentId,
    requestId: config.request.requestId,
    claimType: config.request.claimType,
    domain: config.request.domain,
    evidenceRef: config.request.evidenceRef,
    attesterId: config.attesterId,
    attesterTier: config.attesterTier,
    confidenceScore: config.confidenceScore,
    validFrom: timestamp,
    validUntil: inSeconds(config.validForSeconds),
    issuedAt: timestamp,
  };

  // Sign the canonical serialization of the record
  const attesterSignature = await sign(
    recordWithoutSig,
    config.attesterPrivateKey
  );

  return {
    ...recordWithoutSig,
    attesterSignature,
  };
}

// ── DECLINE ───────────────────────────────────────────────────────────────────

/**
 * Issue a signed decline record.
 *
 * TSD Section 4.2: "Declinations are not silent: a declined attestation
 * request is itself recorded, with a reason code. An agent that repeatedly
 * requests attestation for claims it cannot support is itself a signal."
 */
export async function decline(
  request: AttestationRequest,
  attesterId: HexString,
  attesterPrivateKey: HexString,
  reasonCode: DeclineReason,
  reasonDetail: string
): Promise<DeclineRecord> {
  const recordWithoutSig = {
    requestId: request.requestId,
    subjectAgentId: request.subjectAgentId,
    attesterId,
    reasonCode,
    reasonDetail,
    declinedAt: now(),
  };

  const attesterSignature = await sign(recordWithoutSig, attesterPrivateKey);

  return {
    ...recordWithoutSig,
    attesterSignature,
  };
}

// ── REVOCATION ────────────────────────────────────────────────────────────────

/**
 * Issue a revocation notice for an attestation.
 *
 * TSD Section 4.2: "The attester cannot unilaterally delete a record;
 * they can only issue a Revocation Notice, which is itself a signed record
 * pointing to the original. The original stays visible. Revocation adds a
 * flag — it does not erase. This preserves the audit trail."
 */
export async function revoke(
  attestationId: string,
  attesterId: HexString,
  attesterPrivateKey: HexString,
  reason: string
): Promise<RevocationNotice> {
  const noticeWithoutSig = {
    attestationId,
    attesterId,
    reason,
    revokedAt: now(),
  };

  const attesterSignature = await sign(noticeWithoutSig, attesterPrivateKey);

  return {
    ...noticeWithoutSig,
    attesterSignature,
  };
}

// ── VERIFICATION ──────────────────────────────────────────────────────────────

export interface AttestationVerificationResult {
  valid: boolean;
  errors: string[];
  expired: boolean;
  revoked: boolean;
  ageSeconds: number;
  confidenceScore: number;
  attesterTier: AttesterTier;
}

/**
 * Verify an attestation record.
 *
 * TSD Section 7.3: "Verifies a specific attestation record: checks the
 * attester's signature, confirms the attester's current tier standing,
 * checks for revocation notices."
 *
 * In the PoC this runs locally. In production this queries the mesh.
 */
export async function verifyAttestation(
  record: AttestationRecord,
  attesterPublicKey: HexString,
  revocationNotices: RevocationNotice[] = []
): Promise<AttestationVerificationResult> {
  const errors: string[] = [];

  // Check for revocation first — a revoked attestation fails immediately
  const isRevoked = revocationNotices.some(
    (n) => n.attestationId === record.attestationId
  );

  if (isRevoked) {
    return {
      valid: false,
      errors: ["Attestation has been revoked"],
      expired: isExpired(record.validUntil),
      revoked: true,
      ageSeconds: ageInSeconds(record.issuedAt),
      confidenceScore: record.confidenceScore,
      attesterTier: record.attesterTier,
    };
  }

  // Verify the attester's signature over the record (without the signature field)
  const { attesterSignature, ...recordWithoutSig } = record;
  const sigValid = await cryptoVerify(
    recordWithoutSig,
    attesterSignature,
    attesterPublicKey
  );

  if (!sigValid) {
    errors.push("Attester signature invalid");
  }

  // Check expiry
  const expired = isExpired(record.validUntil);
  if (expired) {
    errors.push(
      `Attestation expired at ${record.validUntil}`
    );
  }

  // Validate confidence score range
  if (record.confidenceScore < 0 || record.confidenceScore > 1) {
    errors.push(
      `Invalid confidence score: ${record.confidenceScore}`
    );
  }

  return {
    valid: errors.length === 0,
    errors,
    expired,
    revoked: false,
    ageSeconds: ageInSeconds(record.issuedAt),
    confidenceScore: record.confidenceScore,
    attesterTier: record.attesterTier,
  };
}

// ── FILTERING ─────────────────────────────────────────────────────────────────

/**
 * Filter a set of attestation records by policy weights.
 * Used by the trust query engine to apply relying party preferences.
 * TSD Section 4.3: "The relying party is sovereign."
 */
export function filterByPolicy(
  records: AttestationRecord[],
  policy: PolicyWeights,
  revocationNotices: RevocationNotice[] = []
): AttestationRecord[] {
  const revokedIds = new Set(revocationNotices.map((n) => n.attestationId));

  return records.filter((record) => {
    // Must not be revoked
    if (revokedIds.has(record.attestationId)) return false;

    // Must not be expired
    if (isExpired(record.validUntil)) return false;

    // Must meet minimum attester tier
    if (record.attesterTier > policy.minimumAttesterTier) return false;

    // Must meet minimum confidence score
    if (record.confidenceScore < policy.minimumConfidence) return false;

    // Must be within max record age
    if (ageInSeconds(record.issuedAt) > policy.maxRecordAgeSeconds) return false;

    return true;
  });
}
