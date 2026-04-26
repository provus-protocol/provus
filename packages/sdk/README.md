# @provus/sdk

SDK surface implementation — coming in v0.2.0.

Three interfaces over HTTP:
- **Runtime interface** — what a compliant agent runtime must implement
- **Operator interface** — fleet management, attestation coverage, incident response
- **Query interface** — trust resolution, verification, lineage

See `packages/core` for the protocol primitives these wrap.
See the TSD in `docs/architecture/` for the full specification.
