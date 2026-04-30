/**
 * @provus/sdk — server.ts
 *
 * Provus SDK HTTP server.
 * Wires Fastify, routes, middleware, and error handling.
 *
 * Three route prefixes mirror the three SDK surfaces from TSD §7:
 *   /identity/*   — runtime interface (identity lifecycle)
 *   /attest/*     — runtime interface (attestation hooks)
 *   /scope/*      — runtime interface (scope enforcement)
 *   /incident/*   — runtime interface (incident hooks)
 *   /operator/*   — operator interface
 *   /trust/*      — query interface
 */

import { versionPlugin, SDK_VERSION } from "./version.js";
import Fastify from "fastify";
import cors from "@fastify/cors";
import { initState } from "./state.js";
import { runtimeRoutes } from "./routes/runtime.js";
import { operatorRoutes } from "./routes/operator.js";
import { queryRoutes } from "./routes/query.js";

const PORT = Number(process.env.PORT ?? 3000);
const HOST = process.env.HOST ?? "0.0.0.0";

async function buildServer() {
  const app = Fastify({
    logger: {
      transport: {
        target: "pino-pretty",
        options: { colorize: true },
      },
    },
  });

  // ── CORS ───────────────────────────────────────────────────────────────────
  await app.register(cors, { origin: true });
  await app.register(versionPlugin);
  // ── HEALTH ─────────────────────────────────────────────────────────────────
  app.get("/", async () => ({
    name: "Provus SDK",
    version: SDK_VERSION,
    description: "Agent identity, attestation & reputation protocol",
    network: "VeritasMesh (local PoC mode)",
    surfaces: {
      runtime: "/identity/* · /attest/* · /scope/* · /incident/*",
      operator: "/operator/*",
      query: "/trust/*",
    },
    docs: "https://github.com/provus-protocol/provus",
    tsd: "docs/architecture/",
    status: "operational",
  }));

  app.get("/health", async () => ({
    status: "ok",
    timestamp: new Date().toISOString(),
  }));

  // ── ROUTES ─────────────────────────────────────────────────────────────────
  await app.register(runtimeRoutes);
  await app.register(operatorRoutes);
  await app.register(queryRoutes);

  // ── ERROR HANDLER ──────────────────────────────────────────────────────────
  app.setErrorHandler((error, req, reply) => {
    app.log.error(error);

    // Zod validation errors come through as 400
    if (error.statusCode === 400) {
      return reply.status(400).send({
        error: "Bad Request",
        message: error.message,
      });
    }

    // Protocol errors from @provus/core
    if ((error as any).code && (error as any).context) {
      return reply.status(422).send({
        error: "Protocol Error",
        code: (error as any).code,
        message: error.message,
        context: (error as any).context,
      });
    }

    return reply.status(500).send({
      error: "Internal Server Error",
      message: "An unexpected error occurred",
    });
  });

  return app;
}

async function start() {
  const app = await buildServer();

  // Initialize protocol state before accepting requests
  await initState();

  await app.listen({ port: PORT, host: HOST });

  console.log("\n");
  console.log("  ██████╗ ██████╗  ██████╗ ██╗   ██╗██╗   ██╗███████╗");
  console.log("  ██╔══██╗██╔══██╗██╔═══██╗██║   ██║██║   ██║██╔════╝");
  console.log("  ██████╔╝██████╔╝██║   ██║██║   ██║██║   ██║███████╗");
  console.log("  ██╔═══╝ ██╔══██╗██║   ██║╚██╗ ██╔╝██║   ██║╚════██║");
  console.log("  ██║     ██║  ██║╚██████╔╝ ╚████╔╝ ╚██████╔╝███████║");
  console.log("  ╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═══╝   ╚═════╝ ╚══════╝");
  console.log(`\n  SDK running on http://${HOST}:${PORT}`);
  console.log(`  Network: VeritasMesh (local PoC mode)`);
  console.log(`\n  Surfaces:`);
  console.log(`    Runtime  → POST /identity/provision`);
  console.log(`               POST /attest/request`);
  console.log(`               POST /scope/check`);
  console.log(`               POST /incident/record`);
  console.log(`    Operator → GET  /operator/agents`);
  console.log(`               GET  /operator/attestations/coverage`);
  console.log(`               GET  /operator/incidents`);
  console.log(`    Query    → POST /trust/query`);
  console.log(`               POST /trust/batch`);
  console.log(`               GET  /trust/verify/:attestationId`);
  console.log(`               GET  /trust/lineage/:agentId`);
  console.log(`\n  Health   → GET  /health`);
  console.log(`  Mesh     → GET  /trust/mesh/status\n`);
}

start().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});

export { buildServer };
