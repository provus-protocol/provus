# @provus/sdk

HTTP server exposing the three Provus SDK surfaces over REST. Built on Fastify with Zod validation.

---

## Surfaces

| Surface | Routes | Consumer |
|---------|--------|----------|
| **Runtime** | `/identity/*` · `/attest/*` · `/scope/*` · `/incident/*` | Agent runtimes |
| **Operator** | `/operator/*` | Fleet operators |
| **Query** | `/trust/*` | Relying parties |

---

## API specification

Full OpenAPI 3.1 spec: [`openapi.yaml`](./openapi.yaml)

Every endpoint is documented with request/response schemas, examples, and TSD references.

### Explore interactively

Paste `openapi.yaml` into [editor.swagger.io](https://editor.swagger.io) to browse and call every endpoint from the browser.

### Postman

Import [`provus-postman-collection.json`](./provus-postman-collection.json) into Postman.
18 requests across 8 folders — ready to use immediately against a local server.

---

## Run locally

```bash
# From the repo root
npm install

# Build core first
cd packages/core && npx tsc && cd ../..

# Build and start the SDK server
cd packages/sdk && npx tsc && node dist/server.js
```

Server starts on `http://localhost:3000`.

```bash
# Quick health check
curl http://localhost:3000/health

# Provision an agent
curl -X POST http://localhost:3000/identity/provision \
  -H "Content-Type: application/json" \
  -d '{
    "orchestratorId": "my-orchestrator",
    "capabilityScope": ["filesystem:read", "llm:inference"],
    "intendedScope": "Research agent",
    "mode": "orchestrator"
  }'
```

---

## Endpoints

### Runtime — Identity
- `POST /identity/provision` — provision agent, issue Provenance Certificate
- `GET  /identity/:agentId` — get identity record
- `POST /identity/:agentId/terminate` — operational decommission

### Runtime — Attestation
- `POST /attest/request` — submit attestation request
- `GET  /attest/status/:requestId` — poll request status
- `GET  /attest/list/:agentId` — list all attestations for an agent

### Runtime — Scope
- `POST /scope/check` — synchronous gate before any agent action

### Runtime — Incident
- `POST /incident/record` — record deviation event
- `POST /incident/:incidentId/acknowledge` — acknowledge receipt

### Operator
- `GET  /operator/agents` — fleet summary
- `GET  /operator/agents/:agentId/audit` — full audit record (exportable)
- `GET  /operator/attestations/coverage` — gaps and expiry warnings
- `GET  /operator/incidents` — fleet-wide incident list
- `POST /operator/incidents/:incidentId/rebut` — submit signed rebuttal

### Query
- `POST /trust/query` — standard trust resolution → Trust Envelope
- `POST /trust/query/authoritative` — bypasses cache, goes to Anchor cluster
- `POST /trust/batch` — multi-agent trust resolution for orchestrators
- `GET  /trust/verify/:attestationId` — independent attestation verification
- `GET  /trust/lineage/:agentId` — full identity lineage chain
- `GET  /trust/mesh/status` — mesh health dashboard

---

## Architecture

See [`packages/core`](../core) for the protocol primitives this SDK wraps.
See [`docs/architecture/`](../../docs/architecture/) for the Technical Specification Document.

**TSD reference:** All endpoint descriptions cite the relevant TSD section.
The SDK does not make trust decisions — it provides structured evidence.
The relying party is sovereign. (TSD §4.3)
