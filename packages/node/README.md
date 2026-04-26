# @provus/node

VeritasMesh node implementation — coming in v0.3.0.

Three node types:
- **Edge node** — lightweight Tier 2 operator node
- **Relay node** — Tier 1 domain-scoped record store and query server
- **Anchor node** — Tier 0 write-authoritative consensus node

Anchor consensus anchors to MonadBFT. See the TSD for the full mesh topology specification.
