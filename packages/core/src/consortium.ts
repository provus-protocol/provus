/**
 * @provus/core — consortium.ts
 *
 * Genesis attester consortium tooling. TSD §5.1, §9.
 *
 * The genesis attester consortium is the social and institutional layer
 * that seeds the Provus trust graph. Without it, the protocol has no
 * root of trust — it is self-referential with no ground truth.
 *
 * This module handles:
 *
 * 1. Consortium agreement format
 *    A signed record that a Tier 0 institution commits to participate
 *    as a genesis attester. Commitment in principle — not a legal contract,
 *    but a cryptographically attributable statement of intent.
 *
 * 2. Multi-sig governance structure
 *    Decisions about Tier 0 admission and removal require M-of-N signatures
 *    from existing Tier 0 members. This module manages the vote aggregation.
 *
 * 3. Admission ceremony
 *    The sequence of operations that formally admits a new Tier 0 attester:
 *    - Institution generates a keypair
 *    - Existing Tier 0 members vote to admit
 *    - Quorum reached → admission record written to registry
 *    - Provenance Certificate for the institution issued
 *
 * TSD §5.1: "Admission to Tier 0 requires a governance process — not
 * Provus's unilateral decision. The protocol defines the admission
 * criteria and the removal criteria."
 */

import { sign, verify, generateKeyPair, generateId, now, inSeconds } from "./crypto.js";
import type { HexString } from "./types.js";

// ── CONSORTIUM AGREEMENT ──────────────────────────────────────────────────────

/**
 * A signed statement of intent from a Tier 0 candidate institution.
 *
 * This is not a legal contract — it is a cryptographically attributable
 * commitment in principle. The institution signs this record with their
 * private key, proving they hold the corresponding public key and
 * understand the commitments they are making.
 */
export interface ConsortiumAgreement {
  /** Version of the agreement format */
  version: "1.0";

  /** The agreeing institution's public key — their future identity on VeritasMesh */
  institutionPublicKey: HexString;

  /** Human-readable institution name */
  institutionName: string;

  /** Primary contact for the institution */
  contactEmail: string;

  /** Institution's jurisdiction (relevant for governance and legal context) */
  jurisdiction: string;

  /**
   * Domains this institution is willing to serve as a Tier 0 attester for.
   * Tier 0 attesters can attest across all domains, but this declares
   * their primary area of expertise and willingness.
   */
  primaryDomains: string[];

  /**
   * The institution's commitments by signing this agreement:
   *   1. Operate an Anchor node for the duration of their participation
   *   2. Participate in Tier 0 governance votes within 72 hours
   *   3. Maintain the private key corresponding to this public key securely
   *   4. Notify the consortium immediately if their key is compromised
   *   5. Accept the Tier 0 removal process if they violate these commitments
   */
  commitmentsAcknowledged: true;

  /** ISO 8601 — when this agreement was signed */
  signedAt: string;

  /** Ed25519 signature over the canonical record (without this field) */
  institutionSignature: HexString;
}

/**
 * Create and sign a consortium agreement.
 * Called by the institution during the onboarding process.
 */
export async function createConsortiumAgreement(
  params: {
    institutionName: string;
    contactEmail: string;
    jurisdiction: string;
    primaryDomains: string[];
  },
  institutionPrivateKey: HexString
): Promise<{ agreement: ConsortiumAgreement; publicKey: HexString }> {

  // Generate keypair if not provided separately
  // In production: institution generates keys in their own HSM
  const keys = await generateKeyPair();

  const recordWithoutSig: Omit<ConsortiumAgreement, "institutionSignature"> = {
    version: "1.0",
    institutionPublicKey: keys.publicKey,
    institutionName: params.institutionName,
    contactEmail: params.contactEmail,
    jurisdiction: params.jurisdiction,
    primaryDomains: params.primaryDomains,
    commitmentsAcknowledged: true,
    signedAt: now(),
  };

  const { sign: signFn } = await import("./crypto.js");
  const institutionSignature = await signFn(recordWithoutSig, keys.privateKey);

  return {
    agreement: { ...recordWithoutSig, institutionSignature },
    publicKey: keys.publicKey,
  };
}

/**
 * Verify a consortium agreement signature.
 * Called when processing an agreement submission.
 */
export async function verifyConsortiumAgreement(
  agreement: ConsortiumAgreement
): Promise<{ valid: boolean; reason: string }> {
  const { institutionSignature, ...recordWithoutSig } = agreement;

  const sigValid = await verify(
    recordWithoutSig,
    institutionSignature,
    agreement.institutionPublicKey
  );

  if (!sigValid) {
    return {
      valid: false,
      reason: "Institution signature invalid — agreement may have been tampered with",
    };
  }

  if (!agreement.commitmentsAcknowledged) {
    return {
      valid: false,
      reason: "commitmentsAcknowledged must be true",
    };
  }

  return { valid: true, reason: "Agreement signature valid" };
}

// ── MULTI-SIG GOVERNANCE ──────────────────────────────────────────────────────

export type GovernanceActionType =
  | "admit_tier0"
  | "remove_tier0"
  | "add_domain"
  | "protocol_upgrade";

/**
 * A governance proposal requiring M-of-N Tier 0 signatures.
 *
 * TSD §5.1: "Admission to Tier 0 requires a governance process.
 * The structure of this governance body depends on which institutions
 * commit as genesis attesters."
 */
export interface GovernanceProposal {
  proposalId: string;
  actionType: GovernanceActionType;
  description: string;

  /** The payload of the action (institution public key, domain name, etc.) */
  payload: Record<string, unknown>;

  /** Who proposed this */
  proposerId: HexString;

  /** Signatures collected so far */
  signatures: GovernanceSignature[];

  /** How many signatures are required to pass */
  quorumRequired: number;

  /** ISO 8601 — proposal creation time */
  createdAt: string;

  /** ISO 8601 — proposal expiry (proposals must be acted on within 7 days) */
  expiresAt: string;

  /** Current status */
  status: "open" | "passed" | "rejected" | "expired";
}

export interface GovernanceSignature {
  signerId: HexString;
  vote: "approve" | "reject";
  signature: HexString;
  signedAt: string;
}

export class GovernanceCouncil {
  private proposals: Map<string, GovernanceProposal> = new Map();
  private tier0Members: Set<HexString> = new Set();
  private quorumThreshold: number;

  constructor(genesisMembers: HexString[], quorumThreshold?: number) {
    for (const member of genesisMembers) {
      this.tier0Members.add(member);
    }
    // Default: simple majority
    this.quorumThreshold = quorumThreshold ?? Math.floor(genesisMembers.length / 2) + 1;
  }

  /**
   * Create a new governance proposal.
   */
  async createProposal(
    actionType: GovernanceActionType,
    description: string,
    payload: Record<string, unknown>,
    proposerId: HexString,
    proposerPrivateKey: HexString
  ): Promise<GovernanceProposal> {
    if (!this.tier0Members.has(proposerId)) {
      throw new Error(`Proposer ${proposerId.slice(0, 16)}… is not a Tier 0 council member`);
    }

    const proposal: Omit<GovernanceProposal, "signatures"> = {
      proposalId: generateId(),
      actionType,
      description,
      payload,
      proposerId,
      quorumRequired: this.quorumThreshold,
      createdAt: now(),
      expiresAt: inSeconds(7 * 24 * 60 * 60), // 7 days
      status: "open",
    };

    // Proposer auto-votes to approve
    const proposerSig = await sign(proposal, proposerPrivateKey);

    const full: GovernanceProposal = {
      ...proposal,
      signatures: [{
        signerId: proposerId,
        vote: "approve",
        signature: proposerSig,
        signedAt: now(),
      }],
    };

    this.proposals.set(full.proposalId, full);
    this.checkQuorum(full.proposalId);

    console.log(
      `[provus:governance] Proposal created: ${full.proposalId.slice(0, 12)}… ` +
      `(${actionType}) — needs ${this.quorumThreshold} approvals`
    );

    return this.proposals.get(full.proposalId)!;
  }

  /**
   * Cast a vote on an open proposal.
   */
  async vote(
    proposalId: string,
    voterId: HexString,
    voterPrivateKey: HexString,
    vote: "approve" | "reject"
  ): Promise<GovernanceProposal> {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) throw new Error(`Proposal ${proposalId} not found`);
    if (proposal.status !== "open") throw new Error(`Proposal is ${proposal.status}`);
    if (!this.tier0Members.has(voterId)) {
      throw new Error(`Voter ${voterId.slice(0, 16)}… is not a Tier 0 council member`);
    }

    // Check for expired proposals
    if (new Date(proposal.expiresAt) < new Date()) {
      proposal.status = "expired";
      this.proposals.set(proposalId, proposal);
      throw new Error("Proposal has expired");
    }

    // Prevent double-voting
    const alreadyVoted = proposal.signatures.some((s) => s.signerId === voterId);
    if (alreadyVoted) throw new Error(`Voter ${voterId.slice(0, 16)}… has already voted`);

    const voterSig = await sign(
      { proposalId, vote, voterId, votedAt: now() },
      voterPrivateKey
    );

    proposal.signatures.push({
      signerId: voterId,
      vote,
      signature: voterSig,
      signedAt: now(),
    });

    this.proposals.set(proposalId, proposal);
    this.checkQuorum(proposalId);

    const updated = this.proposals.get(proposalId)!;
    const approvals = updated.signatures.filter((s) => s.vote === "approve").length;

    console.log(
      `[provus:governance] Vote cast: ${vote} on ${proposalId.slice(0, 12)}… ` +
      `(${approvals}/${this.quorumThreshold} approvals)`
    );

    return updated;
  }

  private checkQuorum(proposalId: string): void {
    const proposal = this.proposals.get(proposalId);
    if (!proposal || proposal.status !== "open") return;

    const approvals = proposal.signatures.filter((s) => s.vote === "approve").length;
    const rejections = proposal.signatures.filter((s) => s.vote === "reject").length;

    if (approvals >= this.quorumThreshold) {
      proposal.status = "passed";
      console.log(
        `[provus:governance] ✓ PASSED: ${proposalId.slice(0, 12)}… ` +
        `(${approvals}/${this.quorumThreshold} approvals)`
      );
    } else if (rejections > this.tier0Members.size - this.quorumThreshold) {
      proposal.status = "rejected";
      console.log(`[provus:governance] ✗ REJECTED: ${proposalId.slice(0, 12)}…`);
    }

    this.proposals.set(proposalId, proposal);
  }

  getProposal(proposalId: string): GovernanceProposal | null {
    return this.proposals.get(proposalId) ?? null;
  }

  getOpenProposals(): GovernanceProposal[] {
    return Array.from(this.proposals.values()).filter((p) => p.status === "open");
  }

  getMembers(): HexString[] {
    return Array.from(this.tier0Members);
  }

  addMember(publicKey: HexString): void {
    this.tier0Members.add(publicKey);
    // Recalculate quorum threshold on membership change
    this.quorumThreshold = Math.floor(this.tier0Members.size / 2) + 1;
  }
}

// ── ADMISSION CEREMONY ────────────────────────────────────────────────────────

/**
 * The formal admission ceremony for a new Tier 0 attester.
 *
 * TSD §5.1: "Admission to Tier 0 requires a governance process."
 *
 * Sequence:
 *   1. Candidate submits ConsortiumAgreement
 *   2. Existing council member proposes admission
 *   3. Council votes — quorum required
 *   4. On pass: admission record generated and signed by council
 *   5. Candidate's public key admitted to registry
 */
export interface AdmissionCeremonyRecord {
  ceremonyId: string;
  candidatePublicKey: HexString;
  candidateName: string;
  agreement: ConsortiumAgreement;
  governanceProposalId: string;
  admittedAt: string;

  /**
   * Signatures from quorum of existing Tier 0 members endorsing the admission.
   * This is the cryptographic proof that the admission was legitimate.
   */
  endorsingSignatures: Array<{
    endorserId: HexString;
    signature: HexString;
    signedAt: string;
  }>;
}

export async function conductAdmissionCeremony(
  agreement: ConsortiumAgreement,
  proposal: GovernanceProposal,
  endorserKeys: Array<{ publicKey: HexString; privateKey: HexString }>
): Promise<AdmissionCeremonyRecord> {

  if (proposal.status !== "passed") {
    throw new Error(
      `Cannot conduct admission ceremony: proposal status is '${proposal.status}'. ` +
      `Proposal must have passed governance vote.`
    );
  }

  const ceremonyWithoutSigs: Omit<AdmissionCeremonyRecord, "endorsingSignatures"> = {
    ceremonyId: generateId(),
    candidatePublicKey: agreement.institutionPublicKey,
    candidateName: agreement.institutionName,
    agreement,
    governanceProposalId: proposal.proposalId,
    admittedAt: now(),
  };

  // Collect endorsing signatures from approving Tier 0 members
  const endorsingSignatures = [];
  for (const endorser of endorserKeys) {
    const sig = await sign(ceremonyWithoutSigs, endorser.privateKey);
    endorsingSignatures.push({
      endorserId: endorser.publicKey,
      signature: sig,
      signedAt: now(),
    });
  }

  const record: AdmissionCeremonyRecord = {
    ...ceremonyWithoutSigs,
    endorsingSignatures,
  };

  console.log(
    `[provus:consortium] ADMISSION CEREMONY COMPLETE: ${agreement.institutionName}\n` +
    `  Public key: ${agreement.institutionPublicKey.slice(0, 16)}…\n` +
    `  Endorsed by: ${endorsingSignatures.length} Tier 0 members\n` +
    `  Ceremony ID: ${record.ceremonyId}`
  );

  return record;
}
