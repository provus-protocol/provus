/**
 * @provus/core
 *
 * Protocol primitives for the Provus agent identity, attestation,
 * and reputation protocol.
 *
 * Three modules, clean boundaries:
 *   identity    — agent provisioning, key rotation, termination
 *   attestation — request, issuance, decline, revocation, verification
 *   trust       — query resolution, envelope construction, lineage
 *
 * Cryptographic operations are in crypto.ts — the interface is clean
 * enough that swapping the underlying implementation (e.g. to a Rust
 * core via WASM) does not touch the protocol modules.
 */

// ── TYPES ─────────────────────────────────────────────────────────────────────
export type {
  HexString,
  Timestamp,
  ProtocolVersion,
  Domain,
  ClaimType,
  AttesterTier,
  IdentityStatus,
  ProvisioningMode,
  CapabilityScope,
  AgentIdentity,
  OriginContext,
  RevocationAnchor,
  ProvenanceCertificate,
  AttestationRequest,
  AttestationRecord,
  DeclineRecord,
  DeclineReason,
  RevocationNotice,
  TrustQuery,
  PolicyWeights,
  TrustEnvelope,
  IncidentSeverity,
  IncidentVisibility,
  IncidentRecord,
  IncidentRebuttal,
} from "./types.js";

export { ProvusError } from "./types.js";

// ── CRYPTO ────────────────────────────────────────────────────────────────────
export {
  generateKeyPair,
  deriveAgentId,
  sign,
  verify,
  contentAddress,
  contentAddressBytes,
  canonicalize,
  generateId,
  now,
  inSeconds,
  isExpired,
  ageInSeconds,
} from "./crypto.js";

export type { KeyPair } from "./crypto.js";

// ── IDENTITY ──────────────────────────────────────────────────────────────────
export {
  provision,
  verifyCertificate,
  rotate,
  terminate,
} from "./identity.js";

export type {
  ProvisionConfig,
  ProvisionResult,
  CertificateVerificationResult,
  RotationResult,
  KeyRotationRecord,
  TerminationResult,
} from "./identity.js";

// ── ATTESTATION ───────────────────────────────────────────────────────────────
export {
  createRequest,
  issue,
  decline,
  revoke,
  verifyAttestation,
  filterByPolicy,
} from "./attestation.js";

export type {
  CreateRequestConfig,
  IssueConfig,
  AttestationVerificationResult,
} from "./attestation.js";

// ── CONSORTIUM ────────────────────────────────────────────────────────────────
export {
  createConsortiumAgreement,
  verifyConsortiumAgreement,
  GovernanceCouncil,
  conductAdmissionCeremony,
} from "./consortium.js";

export type {
  ConsortiumAgreement,
  GovernanceProposal,
  GovernanceSignature,
  GovernanceActionType,
  AdmissionCeremonyRecord,
} from "./consortium.js";

// ── REGISTRY ──────────────────────────────────────────────────────────────────
export {
  AttesterRegistry,
  createGenesisRegistry,
  TIER_CLAIM_PERMISSIONS,
  TIER1_REQUIRED_DOMAINS,
  CLAIM_MINIMUM_TIER,
} from "./registry.js";

export type {
  AttesterRecord,
  AttesterStatusEvent,
  AuthorityCheckResult,
} from "./registry.js";

// ── ENFORCEMENT ───────────────────────────────────────────────────────────────
export {
  enforceAttestation,
  enforceScopeInheritance,
  applyGraphScoring,
  propagateDemotion,
  checkTier2Eligibility,
} from "./enforcement.js";

export type {
  EnforcementResult,
  GraphScoringResult,
  ScopeInheritanceResult,
} from "./enforcement.js";

// ── TRUST ─────────────────────────────────────────────────────────────────────
export {
  DEFAULT_POLICY_WEIGHTS,
  createLocalStore,
  registerIdentity,
  storeAttestation,
  storeRevocation,
  resolveQuery,
  resolveLineage,
} from "./trust.js";

export type {
  LocalMeshStore,
  LineageResult,
} from "./trust.js";
