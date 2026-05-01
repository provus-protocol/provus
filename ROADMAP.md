# Provus Roadmap

Agent identity, attestation & reputation protocol.
VeritasMesh — the decentralized attester network it operates over.

This roadmap tracks the build sequence from proof of concept to production protocol.
It is a living document — updated as milestones are reached and priorities shift.

---

## ✅ v0.1.0 — Foundation (complete)

**Protocol architecture**
- [x] Data model — agent identity schema, attestation structure, reputation scoring inputs
- [x] Protocol layer — four operations: provisioning, attestation issuance, trust query, incident recording
- [x] Attester tier model — four tiers, six domains, cross-tier constraints
- [x] VeritasMesh topology — Anchor, Relay, Edge, Observer node types
- [x] SDK surface specification — runtime, operator, query interfaces
- [x] Threat model — nine vectors analyzed, out-of-scope items declared
- [x] Sustainability model — hybrid staged fee model, governance token design

**Implementation**
- [x] `@provus/core` — Ed25519 identity, SHA-256 content addressing, attestation flow, trust query engine
- [x] `@provus/sdk` — 18 HTTP endpoints across three surfaces (Fastify + Zod)
- [x] End-to-end demo — full protocol happy path, real cryptography
- [x] OpenAPI 3.1 specification — validated, all endpoints documented
- [x] Postman collection — 18 requests, importable immediately

**Documentation**
- [x] Technical Specification Document (TSD) — 12 sections, 721 paragraphs
- [x] MIT license, contributing guidelines, repository structure

---

## ✅ v0.2.0 — VeritasMesh Edge Node (complete)

- [x] `@provus/node` — Edge node implementation
- [x] Edge → Relay record submission (HTTP + retry queue)
- [x] Local attestation cache with TTL enforcement
- [x] Heartbeat protocol (Edge → Relay, 30-second cadence)
- [x] Degraded mode — serve stale cache with staleness flag when Relay unreachable
- [x] SQLite-backed persistent store (sql.js — no native bindings)

---

## ✅ v0.3.0 — VeritasMesh Relay Node (complete)

- [x] Relay node implementation — domain-scoped record store
- [x] Full mesh index — record location across all domains
- [x] Relay → Relay lateral propagation (same-domain peers)
- [x] Relay → Anchor upstream propagation
- [x] Multi-domain fan-out for cross-domain trust queries
- [x] High-severity revocation fast path (< 5 seconds, Anchor → all Relays)
- [x] Edge registry — heartbeat tracking with degraded/offline thresholds

---

## ✅ v0.4.0 — Anchor Consensus Layer (complete)

- [x] Anchor node implementation — write-authoritative, sync-authoritative
- [x] Threshold consensus engine (PoC — floor(N/2)+1 majority)
- [x] MonadBFT production hook — interface ready for integration
- [x] Authoritative query path — bypasses Relay, resolves from confirmed ledger only
- [x] Read-only degraded mode during quorum loss
- [x] Revocation fast path — Anchor → all Relays, target < 5 seconds

---

## ✅ v0.5.0 — Attester Tier Enforcement (complete)

- [x] `AttesterRegistry` — on-mesh credentialing records and admission logic
- [x] Domain binding enforcement — Tier 1 authority scoped to credentialed domain
- [x] Anti-collusion graph scoring — penalize tightly clustered peer attestation rings
- [x] Floor rule — peer-only attestations capped at 0.1 trust score
- [x] Demotion propagation — issued attestations re-weighted on attester demotion
- [x] Scope inheritance enforcement — child scope bounded by parent scope
- [x] Tier 2 eligibility check — 90-day tenure, Tier 1 touch point, zero open incidents

---

## ✅ v0.6.0 — SDK Hardening (complete)

- [x] `ScopeCache` — local capability cache for < 10ms scope.check (TSD §7.4)
- [x] Registry-aware attestation routing — routes by tier and domain
- [x] Tier enforcement on every attestation issuance
- [x] SDK versioning — `X-Provus-Version` header, `/version` endpoint, compatibility check
- [x] `version.ts` — feature flags, uptime, protocol version

---

## 🔨 v1.0.0 — Production (in progress)

Genesis attester consortium live. VeritasMesh mainnet. First external operators.

**Completed in this milestone**
- [x] `SECURITY.md` — threat model summary, known limitations, responsible disclosure
- [x] `consortium.ts` — signed agreement format, multi-sig governance, admission ceremony
- [x] `billing.ts` — usage tracking, Phase 1 fee model wired, Phase 2 ready

**Remaining**
- [ ] MonadBFT consensus integration (Monad dependency decision)
- [ ] Tier 0 governance body structure (requires genesis attester parties named)
- [ ] Genesis attester consortium — commitments from ≥2 Tier 0 institutions
- [ ] Security audit — third-party audit of core protocol and node implementations
- [ ] VeritasMesh mainnet — Anchor nodes live, Relay nodes operational
- [ ] First external operator — first non-founding Tier 2 operator on-mesh
- [ ] Docker images — Edge, Relay, Anchor node deployment packages
- [ ] Language clients — Python, Go (TypeScript already native)
- [ ] Documentation site — hosted API reference from OpenAPI spec

---

## Open problems (tracked)

| Problem | Status | Prerequisite |
|---------|--------|--------------|
| Tier 0 governance body structure | Deferred | Genesis attester parties named |
| Anchor consensus mechanism | Decision pending | Monad dependency decision |
| Relay SLA enforcement consequences | Specified | Implementation in v1.0 |
| Multi-domain fan-out cost | Load modeling needed | Production traffic data |
| SDK versioning model | ✅ Done (v0.6.0) | — |
| `scope.check` performance budget | ✅ Done (v0.6.0) | — |
| Attestation routing logic | ✅ Done (v0.6.0) | — |

---

## Pre-funding milestones

- [x] Technical specification document
- [x] Threat model
- [x] Sustainability model
- [x] Working proof of concept
- [x] Public repository
- [ ] Genesis attester consortium — ≥2 Tier 0 commitments in principle

---

## Post-v1.0 roadmap

**v1.1 — Language clients**
Python and Go SDK clients generated from the OpenAPI spec.
Enables non-TypeScript agent runtimes to participate in VeritasMesh.

**v1.2 — Governance token**
Non-transferable governance token for Tier 0 and Tier 1 members.
Voting rights on protocol upgrades, domain taxonomy, fee structure.

**v1.3 — Compliance layer**
EU AI Act alignment. Auditor export formats. Regulatory reporting endpoints.
Positions Provus as the compliance-compatible trust layer before mandate.

**v2.0 — MonadBFT mainnet**
Full MonadBFT consensus integration. Production-grade Byzantine fault tolerance.
Public VeritasMesh mainnet. Open attester admission.

---

*Provus Protocol — building the trust infrastructure layer for the agent era.*
*github.com/provus-protocol/provus*
