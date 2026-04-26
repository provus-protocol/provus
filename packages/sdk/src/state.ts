/**
 * @provus/sdk — state.ts
 *
 * In-memory state bridge between the HTTP layer and the core protocol.
 *
 * In production this becomes a persistence adapter — the interface stays
 * identical whether the backing store is in-memory, Redis, or anchored
 * to VeritasMesh directly. For now: in-memory, fast, sufficient for the SDK demo.
 *
 * Holds:
 *   - LocalMeshStore (identities, attestations, revocations)
 *   - Orchestrator keypair (signs Provenance Certificates)
 *   - Pending attestation requests (requestId → request)
 *   - Attester registry (attesterId → keypair, for PoC simulation)
 *   - Incident records
 *   - Operator rebuttals
 */

import {
  createLocalStore,
  generateKeyPair,
  type LocalMeshStore,
  type KeyPair,
  type AttestationRequest,
  type AttestationRecord,
  type IncidentRecord,
  type IncidentRebuttal,
  type RevocationNotice,
} from "@provus/core";

export interface ProvusState {
  store: LocalMeshStore;
  orchestrator: KeyPair;
  pendingRequests: Map<string, AttestationRequest>;
  attesters: Map<string, KeyPair>;         // attesterId (publicKey) → keypair
  incidents: Map<string, IncidentRecord>;  // incidentId → record
  rebuttals: Map<string, IncidentRebuttal[]>; // incidentId → rebuttals
  initialized: boolean;
}

let _state: ProvusState | null = null;

/**
 * Initialize the SDK state.
 * Called once at server startup.
 */
export async function initState(): Promise<ProvusState> {
  if (_state) return _state;

  const orchestrator = await generateKeyPair();

  // Seed a default Tier 2 attester for the PoC
  // In production: attesters are credentialed through VeritasMesh admission
  const defaultAttester = await generateKeyPair();

  const attesters = new Map<string, KeyPair>();
  attesters.set(defaultAttester.publicKey, defaultAttester);

  _state = {
    store: createLocalStore(),
    orchestrator,
    pendingRequests: new Map(),
    attesters,
    incidents: new Map(),
    rebuttals: new Map(),
    initialized: true,
  };

  console.log("[provus:state] Initialized");
  console.log(`[provus:state] Orchestrator: ${orchestrator.publicKey.slice(0, 16)}…`);
  console.log(`[provus:state] Default attester: ${defaultAttester.publicKey.slice(0, 16)}… (Tier 2)`);

  return _state;
}

export function getState(): ProvusState {
  if (!_state) throw new Error("State not initialized — call initState() first");
  return _state;
}

/**
 * Get the first available attester keypair.
 * In production: mesh routes to a credentialed attester by tier and domain.
 */
export function getDefaultAttester(state: ProvusState): KeyPair {
  const first = state.attesters.values().next().value;
  if (!first) throw new Error("No attesters registered");
  return first;
}
