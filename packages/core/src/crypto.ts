/**
 * @provus/core — crypto.ts
 *
 * Cryptographic primitives for the Provus protocol.
 * All operations behind clean interfaces — implementation is swappable.
 *
 * Algorithms:
 *   Identity:   Ed25519 (via @noble/ed25519)
 *   Hashing:    SHA-256 (via @noble/hashes)
 *   Encoding:   hex throughout — no base64, no ambiguity
 *
 * MonadBFT uses BLS12-381 for aggregated QCs and ECDSA for individual
 * message integrity. When anchoring to Monad, the Anchor consensus layer
 * will use those primitives. The Provus identity and attestation layer
 * uses Ed25519 — fast, well-audited, and sufficient for our signing needs.
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import type { HexString } from "./types.js";

// ── KEY GENERATION ────────────────────────────────────────────────────────────

/**
 * A keypair used for agent or attester identity.
 * Private key is 32 bytes. Public key is 32 bytes (Ed25519 compressed point).
 */
export interface KeyPair {
  privateKey: HexString;
  publicKey: HexString;
}

/**
 * Generate a new Ed25519 keypair.
 * In production enclave mode, the private key never leaves the enclave.
 * In orchestrator mode (PoC), it is held in memory by the provisioning process.
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const privateKeyBytes = ed.utils.randomPrivateKey();
  const publicKeyBytes = await ed.getPublicKeyAsync(privateKeyBytes);
  return {
    privateKey: bytesToHex(privateKeyBytes),
    publicKey: bytesToHex(publicKeyBytes),
  };
}

// ── AGENT IDENTITY ────────────────────────────────────────────────────────────

/**
 * Derive the agent ID from a public key.
 * agentId = SHA-256(publicKeyBytes)
 *
 * TSD Section 3.1: "SHA-256 hash of the agent's public key.
 * Globally unique, deterministic, stable."
 */
export function deriveAgentId(publicKey: HexString): HexString {
  const pubKeyBytes = hexToBytes(publicKey);
  return bytesToHex(sha256(pubKeyBytes));
}

// ── SIGNING ───────────────────────────────────────────────────────────────────

/**
 * Sign a message with an Ed25519 private key.
 * The message is canonically serialized before signing.
 * Returns a hex-encoded 64-byte signature.
 */
export async function sign(
  message: unknown,
  privateKey: HexString
): Promise<HexString> {
  const messageBytes = utf8ToBytes(canonicalize(message));
  const privKeyBytes = hexToBytes(privateKey);
  const signatureBytes = await ed.signAsync(messageBytes, privKeyBytes);
  return bytesToHex(signatureBytes);
}

/**
 * Verify an Ed25519 signature.
 * Returns true if the signature is valid for the message and public key.
 *
 * TSD Section 4.2: "Every attestation record is signed with the attester's
 * private key. Relay nodes validate the attester signature and confirm the
 * attester's current tier standing."
 */
export async function verify(
  message: unknown,
  signature: HexString,
  publicKey: HexString
): Promise<boolean> {
  try {
    const messageBytes = utf8ToBytes(canonicalize(message));
    const sigBytes = hexToBytes(signature);
    const pubKeyBytes = hexToBytes(publicKey);
    return await ed.verifyAsync(sigBytes, messageBytes, pubKeyBytes);
  } catch {
    return false;
  }
}

// ── CONTENT ADDRESSING ────────────────────────────────────────────────────────

/**
 * Compute a content-addressed reference for an evidence artifact.
 * evidenceRef = SHA-256(canonicalize(content))
 *
 * TSD Section 3.2: "Content-addressed hash (SHA-256) of the supporting
 * evidence artifact. Not embedded — referenced."
 *
 * This means the attestation record stays lightweight regardless of
 * evidence size. The evidence can be independently verified by anyone
 * who has the artifact.
 */
export function contentAddress(content: unknown): HexString {
  const contentBytes = utf8ToBytes(canonicalize(content));
  return bytesToHex(sha256(contentBytes));
}

/**
 * Compute a content-addressed reference from raw bytes.
 * Used when the evidence artifact is a file, not a JSON object.
 */
export function contentAddressBytes(bytes: Uint8Array): HexString {
  return bytesToHex(sha256(bytes));
}

// ── CANONICAL SERIALIZATION ───────────────────────────────────────────────────

/**
 * Canonical JSON serialization for signing.
 *
 * Keys are sorted alphabetically at every level. This ensures that the
 * same logical object always produces the same byte sequence, regardless
 * of insertion order. This is the foundation of tamper-evidence — any
 * modification to a signed record changes the canonical form and
 * invalidates the signature.
 *
 * TSD: "Published records cannot be silently modified — only superseded
 * by signed follow-on records."
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const items = value.map(canonicalize);
    return `[${items.join(",")}]`;
  }

  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map(
    (key) => `${JSON.stringify(key)}:${canonicalize(obj[key])}`
  );
  return `{${pairs.join(",")}}`;
}

// ── UTILITIES ─────────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically random ID string.
 * Used for requestId, attestationId, incidentId, etc.
 * Format: hex string of 16 random bytes (32 hex chars).
 */
export function generateId(): string {
  return bytesToHex(ed.utils.randomPrivateKey().slice(0, 16));
}

/**
 * Current ISO 8601 timestamp.
 */
export function now(): string {
  return new Date().toISOString();
}

/**
 * Timestamp N seconds from now.
 */
export function inSeconds(seconds: number): string {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

/**
 * Check if a timestamp is in the past (expired).
 */
export function isExpired(timestamp: string): boolean {
  return new Date(timestamp) < new Date();
}

/**
 * Age of a timestamp in seconds.
 */
export function ageInSeconds(timestamp: string): number {
  return (Date.now() - new Date(timestamp).getTime()) / 1000;
}
