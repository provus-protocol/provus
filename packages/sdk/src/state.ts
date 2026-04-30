/**
 * @provus/sdk — state.ts
 *
 * In-memory state bridge between the HTTP layer and the core protocol.
 *
 * v0.6.0 additions:
 *   - AttesterRegistry — tier enforcement and domain binding
 *   - ScopeCache — <10ms hot path for scope.check (TSD §7.4)
 *   - Registry-aware attester routing — routes by tier and domain
 */

import {
  createLocalStore,
  generateKeyPair,
  createGenesisRegistry,
  type LocalMeshStore,
  type KeyPair,
  type AttestationRequest,
  type IncidentRecord,
  type IncidentRebuttal,
  type AttesterRegistry,
  type Domain,
  type ClaimType,
  type AttesterTier,
  type CapabilityScope,
} from "@provus/core";

// ── SCOPE CACHE ───────────────────────────────────────────────────────────────

/**
 * Local capability cache for scope.check.
 *
 * TSD §7.4: "scope.check must return in <10ms for a cache-warm call."
 *
 * Maps agentId → their current capability scope.
 * Invalidated on identity update, termination, key rotation.
 */
export class ScopeCache {
  private cache: Map<string, { scope: CapabilityScope; cachedAt: number }> = new Map();
  private readonly TTL_MS = 60_000; // 1 minute

  set(agentId: string, scope: CapabilityScope): void {
    this.cache.set(agentId, { scope, cachedAt: Date.now() });
  }

  get(agentId: string): CapabilityScope | null {
    const entry = this.cache.get(agentId);
    if (!entry) return null;
    if (Date.now() - entry.cachedAt > this.TTL_MS) {
      this.cache.delete(agentId);
      return null;
    }
    return entry.scope;
  }

  invalidate(agentId: string): void {
    this.cache.delete(agentId);
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }
}

// ── ATTESTER ROUTING ──────────────────────────────────────────────────────────

export interface RegisteredAttester {
  keypair: KeyPair;
  tier: AttesterTier;
  domains: Domain[];
  name: string;
}

/**
 * Route an attestation request to the best available attester.
 *
 * TSD §7.4: "Attestation routing — attester selection,
 * unavailability fallback, operator preference."
 *
 * TSD §4.2: "The runtime specifies the tier and domain, and the mesh
 * routes to an available credentialed attester."
 */
export function routeAttestation(
  attesters: RegisteredAttester[],
  targetTier: AttesterTier,
  domain: Domain,
  registry: AttesterRegistry
): RegisteredAttester | null {
  // Step 1: exact match — right tier, credentialed for domain
  const exact = attesters.filter((a) => {
    if (a.tier !== targetTier) return false;
    const check = registry.checkAuthority(a.keypair.publicKey, "behavior", domain);
    return check.authorized;
  });
  if (exact.length > 0) return exact[0];

  // Step 2: tier match, any domain (fallback)
  const tierMatch = attesters.filter((a) => a.tier === targetTier);
  if (tierMatch.length > 0) return tierMatch[0];

  // Step 3: any available attester (last resort)
  return attesters[0] ?? null;
}

// ── STATE ─────────────────────────────────────────────────────────────────────

export interface ProvusState {
  store: LocalMeshStore;
  orchestrator: KeyPair;
  pendingRequests: Map<string, AttestationRequest>;
  attesters: RegisteredAttester[];
  registry: AttesterRegistry;
  scopeCache: ScopeCache;
  incidents: Map<string, IncidentRecord>;
  rebuttals: Map<string, IncidentRebuttal[]>;
  initialized: boolean;
}

let _state: ProvusState | null = null;

export async function initState(): Promise<ProvusState> {
  if (_state) return _state;

  const orchestrator = await generateKeyPair();

  // Bootstrap genesis registry — orchestrator is Tier 0
  const { registry } = await createGenesisRegistry({
    attesterId: orchestrator.publicKey,
    name: "Provus SDK Orchestrator (PoC genesis)",
  });

  // Default Tier 2 attester
  const defaultAttesterKeys = await generateKeyPair();

  await registry.admit({
    attesterId: defaultAttesterKeys.publicKey,
    name: "SDK Default Attester (Tier 2)",
    tier: 2,
    credentialedDomains: [],
    authorizedClaimTypes: ["behavior", "capability"],
    status: "active",
    credibilityScore: 0.7,
    admittedAt: new Date().toISOString(),
    validUntil: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString(),
    updatedAt: new Date().toISOString(),
    endorsedBy: null,
    endorsementSignature: null,
  });

  const attesters: RegisteredAttester[] = [
    {
      keypair: defaultAttesterKeys,
      tier: 2,
      domains: ["operational_behavior"],
      name: "SDK Default Attester",
    },
  ];

  _state = {
    store: createLocalStore(),
    orchestrator,
    pendingRequests: new Map(),
    attesters,
    registry,
    scopeCache: new ScopeCache(),
    incidents: new Map(),
    rebuttals: new Map(),
    initialized: true,
  };

  console.log("[provus:state] Initialized v0.6.0");
  console.log(`[provus:state] Orchestrator (Tier 0): ${orchestrator.publicKey.slice(0, 16)}…`);
  console.log(`[provus:state] Default attester (Tier 2): ${defaultAttesterKeys.publicKey.slice(0, 16)}…`);
  console.log(`[provus:state] Registry: active | Scope cache: active (TTL 60s)`);

  return _state;
}

export function getState(): ProvusState {
  if (!_state) throw new Error("State not initialized — call initState() first");
  return _state;
}

export function getAttesterForRequest(
  state: ProvusState,
  targetTier: AttesterTier,
  domain: Domain
): RegisteredAttester | null {
  return routeAttestation(state.attesters, targetTier, domain, state.registry);
}
