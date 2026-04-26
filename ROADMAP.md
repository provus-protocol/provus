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

## 🔨 v0.2.0 — VeritasMesh Edge Node

The first real network participant. An Edge node is what Tier 2 operators run.
It connects to the mesh, holds its own agent records, submits attestations upstream,
and caches query results locally.

**Build targets**
- [ ] `@provus/node` — Edge node implementation
- [ ] Edge → Relay record submission (HTTP + retry queue)
- [ ] Local attestation cache with TTL enforcement
- [ ] Heartbeat protocol (Edge → Relay, 30-second cadence)
- [ ] Degraded mode — serve stale cache with staleness flag when Relay unreachable
- [ ] Node configuration file — Relay endpoint, operator identity, cache settings
- [ ] Docker image for Edge node deployment

---

## 🔨 v0.3.0 — VeritasMesh Relay Node

The workhorse of the mesh. Relay nodes are operated by Tier 1 institutional attesters.
They serve query traffic, hold domain-scoped record stores, and propagate records
upward to Anchor nodes.

**Build targets**
- [ ] Relay node implementation — domain-scoped record store
- [ ] Full mesh index — record location across all domains
- [ ] Relay → Relay lateral propagation (same-domain peers)
- [ ] Relay → Anchor upstream propagation
- [ ] Multi-domain fan-out for cross-domain trust queries
- [ ] Relay SLA monitoring and heartbeat enforcement
- [ ] High-severity revocation push path (target: <5 seconds, Anchor → all Relays)

---

## 🔨 v0.4.0 — Anchor Consensus Layer

The authoritative ledger. Anchor nodes reach consensus on the canonical record set.
This is where the MonadBFT dependency becomes concrete.

**Build targets**
- [ ] Anchor node implementation — write-authoritative, sync-authoritative
- [ ] MonadBFT consensus integration (anchor to Monad for production)
- [ ] Anchor quorum protocol — multi-institution consensus
- [ ] Authoritative query path — bypasses Relay, goes to Anchor cluster
- [ ] Read-only degraded mode during quorum loss
- [ ] Anchor → Relay record propagation (standard path + revocation fast path)

---

## 🔨 v0.5.0 — Attester Tier Enforcement

The trust hierarchy made real. Attesters are credentialed, domains are enforced,
and the tier model governs what each attester can claim.

**Build targets**
- [ ] Attester registry — on-mesh credentialing records
- [ ] Domain binding enforcement — Tier 1 authority scoped to credentialed domain
- [ ] Tier 2 admission threshold enforcement — 90-day activity, Tier 1 touch point
- [ ] Demotion propagation — re-weight issued attestations when attester is demoted
- [ ] Anti-collusion graph scoring — penalize tightly clustered peer attestation rings
- [ ] Scope granularity taxonomy — 3 levels, minimum per trust tier

---

## 🔨 v0.6.0 — SDK Hardening & Developer Experience

Make the SDK production-ready and developer-friendly enough for external integrations.

**Build targets**
- [ ] SDK versioning — semantic versioning, deprecation timelines, backwards compatibility
- [ ] `scope.check` performance — <10ms cache-warm, local caching spec
- [ ] Attestation routing logic — attester selection, unavailability fallback
- [ ] SDK compliance test suite — runtimes self-certify compliance
- [ ] Language clients — Python, Go (TypeScript already native)
- [ ] Documentation site — hosted API reference from OpenAPI spec

---

## 🔨 v1.0.0 — Production Protocol

Genesis attester consortium live. VeritasMesh mainnet. First external operators.

**Milestones**
- [ ] Tier 0 governance body — admission criteria, multi-sig structure, removal process
- [ ] Genesis attester consortium — commitments from ≥2 Tier 0 institutions
- [ ] Sustainability model live — Phase 1 fee model, attester incentives active
- [ ] Security audit — third-party audit of core protocol and node implementations
- [ ] VeritasMesh mainnet — Anchor nodes live, Relay nodes operational
- [ ] First external operator — first non-founding Tier 2 operator on-mesh

---

## Open problems (tracked)

These are unresolved design decisions. Each has a defined prerequisite before it can close.

| Problem | Status | Prerequisite |
|---------|--------|--------------|
| Tier 0 governance body structure | Deferred | Genesis attester parties named |
| Anchor consensus mechanism | Decision pending | Monad dependency decision |
| Relay SLA enforcement consequences | Pre-v0.3.0 | Relay node implementation |
| Multi-domain fan-out cost | Pre-v0.3.0 | Load modeling |
| SDK versioning model | Pre-v0.6.0 | First external SDK consumer |
| `scope.check` performance budget | Pre-v0.6.0 | Production load testing |
| Attestation routing logic | Pre-v0.6.0 | Attester registry implementation |

---

## Pre-funding milestones

Required before Monad and tier-1 VC conversations begin:

- [x] Technical specification document
- [x] Threat model
- [x] Sustainability model
- [ ] Genesis attester consortium — ≥2 Tier 0 commitments in principle
- [ ] Working proof of concept — ✅ done
- [ ] Public repository — ✅ done

---

*Provus Protocol — building the trust infrastructure layer for the agent era.*
*github.com/provus-protocol/provus*
