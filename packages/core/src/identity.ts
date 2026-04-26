/**
 * @provus/core — identity.ts
 *
 * Agent identity lifecycle. TSD Section 3.1 and Section 4.1.
 *
 * Three operations:
 *   provision()   — agent birth, produces a Provenance Certificate
 *   rotate()      — key rotation with cryptographic lineage link
 *   terminate()   — operational decommission (not revocation)
 */

import {
  generateKeyPair,
  deriveAgentId,
  sign,
  verify,
  generateId,
  now,
} from "./crypto.js";
import type {
  AgentIdentity,
  ProvenanceCertificate,
  CapabilityScope,
  ProvisioningMode,
  HexString,
} from "./types.js";
import { ProvusError } from "./types.js";

// ── PROVISIONING ──────────────────────────────────────────────────────────────

export interface ProvisionConfig {
  /**
   * Orchestrator identifier. Recorded in the identity's origin context.
   */
  orchestratorId: string;

  /**
   * The maximum capability scope for this agent.
   * TSD: "Cannot be expanded post-provisioning."
   */
  capabilityScope: CapabilityScope;

  /**
   * The intended task description. Informational — recorded in origin context.
   */
  intendedScope: string;

  /**
   * Provisioning mode. Affects attestation weight downstream.
   * Default: "orchestrator" (PoC mode — keys generated here).
   * Production high-assurance: "enclave".
   */
  mode?: ProvisioningMode;

  /**
   * If this is a sub-agent, provide the parent's identity and private key
   * so the parent can co-sign the Provenance Certificate.
   * TSD: "Child agents inherit at most the parent's tier standing."
   */
  parent?: {
    identity: AgentIdentity;
    privateKey: HexString;
  };
}

export interface ProvisionResult {
  /** The agent's private key. In production enclave mode, never leaves the enclave. */
  privateKey: HexString;

  /** The agent's public identity record. */
  identity: AgentIdentity;

  /** The signed birth record. Present this to the registry. */
  certificate: ProvenanceCertificate;
}

/**
 * Provision a new agent identity.
 *
 * TSD Section 4.1: "When an agent is instantiated, the first act must be
 * key generation and identity registration. An agent that acts before it
 * has a registered identity is invisible to the trust layer."
 *
 * The orchestrator's private key signs the Provenance Certificate.
 * In the PoC, we use a dedicated orchestrator keypair.
 */
export async function provision(
  orchestratorPrivateKey: HexString,
  config: ProvisionConfig
): Promise<ProvisionResult> {
  const mode = config.mode ?? "orchestrator";

  // Generate the agent's keypair
  const agentKeyPair = await generateKeyPair();
  const agentId = deriveAgentId(agentKeyPair.publicKey);

  const timestamp = now();

  // Build the lineage chain
  // TSD: "The cryptographic chain of parent agent identifiers linking
  // an agent to a human-operated provisioning event."
  const lineageChain: HexString[] = config.parent
    ? [...config.parent.identity.lineageChain, config.parent.identity.agentId]
    : [];

  // Validate scope inheritance
  // TSD: "A child agent can inherit at most the parent's tier standing
  // within the parent's credentialed domain."
  if (config.parent) {
    const parentScope = config.parent.identity.capabilityScope;
    const invalidCaps = config.capabilityScope.filter(
      (cap) => !parentScope.includes(cap)
    );
    if (invalidCaps.length > 0) {
      throw new ProvusError(
        "SCOPE_EXCEEDED",
        `Child agent cannot claim capabilities not held by parent: ${invalidCaps.join(", ")}`,
        { parentScope, requestedScope: config.capabilityScope, invalidCaps }
      );
    }
  }

  // Construct the identity record
  const identity: AgentIdentity = {
    agentId,
    publicKey: agentKeyPair.publicKey,
    capabilityScope: config.capabilityScope,
    originContext: {
      orchestratorId: config.orchestratorId,
      parentAgentId: config.parent?.identity.agentId ?? null,
      intendedScope: config.intendedScope,
      protocolVersion: "0.1.0",
      provisionedAt: timestamp,
    },
    lineageChain,
    revocationAnchor: {
      registryId: generateId(),
      status: "clear",
      checkedAt: timestamp,
    },
    provisioningMode: mode,
    status: "active",
    createdAt: timestamp,
    updatedAt: timestamp,
  };

  // Orchestrator signs the identity record
  const orchestratorSignature = await sign(identity, orchestratorPrivateKey);

  // Parent co-signs if this is a sub-agent
  let parentSignature: HexString | null = null;
  if (config.parent) {
    // Parent signs the identity record too — binding the child to the parent's lineage
    parentSignature = await sign(identity, config.parent.privateKey);
  }

  const certificate: ProvenanceCertificate = {
    identity,
    orchestratorSignature,
    parentSignature,
    issuedAt: timestamp,
    protocolVersion: "0.1.0",
  };

  return {
    privateKey: agentKeyPair.privateKey,
    identity,
    certificate,
  };
}

// ── CERTIFICATE VERIFICATION ──────────────────────────────────────────────────

/**
 * Verify a Provenance Certificate.
 *
 * Checks:
 *  1. The agent ID is correctly derived from the public key
 *  2. The orchestrator's signature is valid over the identity record
 *  3. The parent's co-signature is valid (if present)
 *  4. The lineage chain is consistent with the parent reference
 */
export async function verifyCertificate(
  certificate: ProvenanceCertificate,
  orchestratorPublicKey: HexString,
  parentPublicKey?: HexString
): Promise<CertificateVerificationResult> {
  const { identity } = certificate;
  const errors: string[] = [];

  // 1. Verify agent ID derivation
  const expectedAgentId = deriveAgentId(identity.publicKey);
  if (expectedAgentId !== identity.agentId) {
    errors.push(
      `Agent ID mismatch: expected ${expectedAgentId}, got ${identity.agentId}`
    );
  }

  // 2. Verify orchestrator signature
  const orchestratorSigValid = await verify(
    identity,
    certificate.orchestratorSignature,
    orchestratorPublicKey
  );
  if (!orchestratorSigValid) {
    errors.push("Orchestrator signature invalid");
  }

  // 3. Verify parent co-signature if present
  if (certificate.parentSignature !== null) {
    if (!parentPublicKey) {
      errors.push("Parent signature present but no parent public key provided");
    } else {
      const parentSigValid = await verify(
        identity,
        certificate.parentSignature,
        parentPublicKey
      );
      if (!parentSigValid) {
        errors.push("Parent co-signature invalid");
      }
    }
  }

  // 4. Verify lineage chain consistency
  if (identity.originContext.parentAgentId !== null) {
    const parentInChain = identity.lineageChain.includes(
      identity.originContext.parentAgentId
    );
    if (!parentInChain) {
      errors.push("Parent agent ID not found in lineage chain");
    }
    if (certificate.parentSignature === null) {
      errors.push("Sub-agent certificate missing parent co-signature");
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    agentId: identity.agentId,
    lineageDepth: identity.lineageChain.length,
  };
}

export interface CertificateVerificationResult {
  valid: boolean;
  errors: string[];
  agentId: HexString;
  lineageDepth: number;
}

// ── KEY ROTATION ──────────────────────────────────────────────────────────────

export interface RotationResult {
  /** The new private key. The old key is still valid for historical verification. */
  newPrivateKey: HexString;

  /** The updated identity record with the new public key. */
  updatedIdentity: AgentIdentity;

  /**
   * The rotation record, signed by both old and new keys.
   * This is the cryptographic link that proves continuity.
   * TSD: "Links new key to prior key cryptographically. Does not reset reputation."
   */
  rotationRecord: KeyRotationRecord;
}

export interface KeyRotationRecord {
  agentId: HexString;
  previousPublicKey: HexString;
  newPublicKey: HexString;
  reason: string;

  /** Signature by the OLD private key — proves the rotation was authorized */
  previousKeySignature: HexString;

  /** Signature by the NEW private key — proves possession of the new key */
  newKeySignature: HexString;

  rotatedAt: string;
}

/**
 * Rotate an agent's signing key.
 *
 * TSD Section 7.1: "Key rotation for a live agent. Links new key to prior
 * key cryptographically. Does not reset reputation."
 *
 * The old key remains valid for verifying historical signatures.
 * Relying parties can reject actions signed by the old key after the
 * rotation timestamp.
 */
export async function rotate(
  identity: AgentIdentity,
  currentPrivateKey: HexString,
  reason: string
): Promise<RotationResult> {
  if (identity.status !== "active") {
    throw new ProvusError(
      "IDENTITY_INACTIVE",
      `Cannot rotate key for ${identity.status} agent`,
      { agentId: identity.agentId, status: identity.status }
    );
  }

  const newKeyPair = await generateKeyPair();
  const timestamp = now();

  // Build the rotation record — signed by both keys to prove continuity
  const rotationPayload = {
    agentId: identity.agentId,
    previousPublicKey: identity.publicKey,
    newPublicKey: newKeyPair.publicKey,
    reason,
    rotatedAt: timestamp,
  };

  const previousKeySignature = await sign(rotationPayload, currentPrivateKey);
  const newKeySignature = await sign(rotationPayload, newKeyPair.privateKey);

  const rotationRecord: KeyRotationRecord = {
    ...rotationPayload,
    previousKeySignature,
    newKeySignature,
  };

  const updatedIdentity: AgentIdentity = {
    ...identity,
    publicKey: newKeyPair.publicKey,
    // agentId does NOT change — it was derived from the original key
    // and represents the stable identity, not the current signing key
    updatedAt: timestamp,
  };

  return {
    newPrivateKey: newKeyPair.privateKey,
    updatedIdentity,
    rotationRecord,
  };
}

// ── TERMINATION ───────────────────────────────────────────────────────────────

/**
 * Terminate an agent identity.
 *
 * TSD Section 7.1: "Decommissions the agent. Marks identity record as
 * inactive. Not revocation — termination is an operational fact."
 *
 * A terminated agent's record persists and is queryable.
 * Revocation is a trust judgment made by the governance layer.
 * Termination is an operational fact recorded by the operator.
 */
export async function terminate(
  identity: AgentIdentity,
  operatorPrivateKey: HexString,
  reason: string
): Promise<TerminationResult> {
  if (identity.status !== "active") {
    throw new ProvusError(
      "IDENTITY_INACTIVE",
      `Agent is already ${identity.status}`,
      { agentId: identity.agentId }
    );
  }

  const timestamp = now();

  const terminatedIdentity: AgentIdentity = {
    ...identity,
    status: "terminated",
    updatedAt: timestamp,
  };

  const terminationRecord = {
    agentId: identity.agentId,
    reason,
    terminatedAt: timestamp,
    finalPublicKey: identity.publicKey,
  };

  const operatorSignature = await sign(terminationRecord, operatorPrivateKey);

  return {
    terminatedIdentity,
    terminationRecord: {
      ...terminationRecord,
      operatorSignature,
    },
  };
}

export interface TerminationResult {
  terminatedIdentity: AgentIdentity;
  terminationRecord: {
    agentId: HexString;
    reason: string;
    terminatedAt: string;
    finalPublicKey: HexString;
    operatorSignature: HexString;
  };
}
