# Contributing to Provus

Provus is an early-stage protocol. Contributions are welcome, but because this is
infrastructure — not application software — the bar for changes to the core protocol
is deliberately high. Read this document before opening a pull request.

---

## What kind of contributions are welcome

**Welcome:**
- Bug reports with reproducible test cases
- Documentation improvements and corrections
- Example implementations and integrations
- Performance improvements that don't change protocol behavior
- Test coverage additions

**Requires prior discussion (open an issue first):**
- Changes to the data model (types.ts)
- Changes to the cryptographic primitives (crypto.ts)
- Changes to protocol operation semantics (identity.ts, attestation.ts, trust.ts)
- New SDK surface methods
- New domains or claim types

**Not accepted without a protocol RFC:**
- Changes to the attester tier model
- Changes to the trust envelope format
- Changes to canonical serialization
- Anything that would break backwards compatibility

---

## Development setup

```bash
git clone https://github.com/provus-protocol/provus
cd provus
npm install
node examples/basic-flow/demo.mjs   # should run clean
```

---

## Code principles

**Every line maps to the TSD.** If you're adding or changing protocol behavior,
the Technical Specification Document (`docs/architecture/`) is the source of truth.
Code that can't be traced to a TSD section needs a spec change first.

**Real cryptography only.** No mocked signatures, no simulated key generation,
no placeholder hashes. If it touches the protocol, it uses the same primitives
that run in production.

**Comments cite the spec.** Protocol-critical code should reference the relevant
TSD section. Example: `// TSD §4.2: "Declinations are not silent."`

**Clean module boundaries.** `core` has no dependency on `sdk` or `node`.
`sdk` depends on `core`. `node` depends on both. Do not break this.

---

## Commit message format

```
type(scope): short description

Longer explanation if needed. Reference the TSD section if relevant.

TSD ref: §4.2 — Attestation issuance
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`
Scopes: `core`, `sdk`, `node`, `examples`, `docs`

---

## Opening an issue

For bugs: include the Node.js version, the exact error, and a minimal reproduction.
For protocol questions: reference the relevant TSD section and explain what you
think is ambiguous or incorrect.

For everything else: just be direct about what you're trying to do and why.

---

## Contact

For genesis attester enquiries, technical collaboration, or funding conversations,
reach out before opening a public issue. Some conversations are better had directly.

---

*Provus Protocol — building the trust infrastructure layer for the agent era.*
