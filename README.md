# Provus

**Agent identity, attestation, and reputation protocol.**
**VeritasMesh** — the decentralized attester network it operates over.

---

## What this is

Provus is the trust infrastructure layer for autonomous AI agent pipelines.

As agents proliferate — acting on behalf of humans and organizations, delegating tasks to sub-agents, interacting with external services — there is no standard mechanism to answer three foundational questions:

- **Who is this agent?** Cryptographically rooted identity, traceable to a human-operated provisioning event.
- **What has it been verified to do?** Structured attestation from credentialed attesters, with evidence references and validity windows.
- **What does its history tell us?** Reputation scoring from auditable on-mesh records, computed at query time under the relying party's own policy weights.

Provus addresses all three. VeritasMesh provides the decentralized infrastructure over which identity records, attestation records, and reputation inputs are published, replicated, and queried — without a central authority.

---

## Run the demo

```bash
git clone https://github.com/provus-protocol/provus
cd provus
npm install
node examples/basic-flow/demo.mjs
```

The demo runs the complete protocol happy path end-to-end:

1. Provision an agent identity → Provenance Certificate
2. Verify the certificate cryptographically
3. Build and submit an attestation request
4. Issue a signed attestation record
5. Resolve a trust query → Trust Envelope
6. Independently verify the attestation
7. Resolve the agent's lineage chain

**No simulated cryptography.** Real Ed25519 signatures and SHA-256 hashing throughout. The same primitives run in production.

---

## Repository structure

```
provus/
├── packages/
│   ├── core/          ← protocol primitives (identity, attestation, trust)
│   ├── sdk/           ← SDK surfaces (runtime, operator, query interfaces)
│   └── node/          ← VeritasMesh node implementation (coming)
├── examples/
│   └── basic-flow/    ← end-to-end demo
└── docs/
    └── architecture/  ← technical specification document
```

---

## Protocol overview

### Data model
- **Agent identity** — Ed25519 keypair, capability scope, origin provenance, lineage chain, revocation anchor
- **Attestation record** — typed claim, domain, content-addressed evidence reference, confidence score (probabilistic, not boolean), validity window
- **Trust envelope** — recommended scope, confidence interval, freshness timestamp, expiry

### Protocol operations
- **Provisioning** — agent birth, Provenance Certificate, mandatory before first action
- **Attestation issuance** — pull-based, append-only, decline records included, revocation appends not erases
- **Trust query** — local resolution, no central oracle, relying party is sovereign
- **Incident recording** — three visibility tiers (public / consortium / private), rebuttal append model

### Attester tier model
| Tier | Type | Authority |
|------|------|-----------|
| 0 | Human trust anchors | Genesis — governed admission |
| 1 | Institutional attesters | Domain-credentialed claims |
| 2 | Operator attesters | Operational behavior |
| 3 | Peer agent attesters | Probabilistic only |

### VeritasMesh topology
Four node types mirroring the attester tier model: **Anchor** (Tier 0, write-authoritative), **Relay** (Tier 1, domain-scoped, query-serving), **Edge** (Tier 2, lightweight), **Observer** (read-only).

Consistency model: writes prefer consistency, reads prefer availability with explicit staleness flagging. High-severity revocations use a dedicated push path targeting <5 second full propagation.

---

## Technical specification

The full Technical Specification Document (TSD v0.1) is available in `docs/architecture/`. It covers the complete data model, protocol operations, attester tier model, mesh topology, SDK surface, threat model, and sustainability model.

---

## Status

**v0.1.0 — Architecture and core primitives.**

- [x] Data model (types, canonical serialization)
- [x] Cryptographic primitives (Ed25519 identity, SHA-256 content addressing)
- [x] Identity lifecycle (provision, rotate, terminate)
- [x] Attestation flow (request, issue, decline, revoke, verify)
- [x] Trust query engine (local resolution, trust envelope, lineage)
- [x] End-to-end demo
- [ ] SDK surface (runtime, operator, query interfaces over HTTP)
- [ ] VeritasMesh node implementation (Edge, Relay, Anchor)
- [ ] Attester tier enforcement
- [ ] Monad anchor consensus integration
- [ ] Genesis attester consortium

---

## Contact

Building the trust infrastructure layer for the agent era.

For genesis attester enquiries, technical collaboration, or funding conversations,
open an issue or see [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](./LICENSE).

---

*Provus v0.1.0 — Early pre-release. Architecture and core primitives.*
