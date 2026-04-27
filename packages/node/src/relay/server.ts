/**
 * @provus/node — relay/server.ts
 *
 * VeritasMesh Relay node entry point.
 *
 * TSD §6.1: "Relay nodes — operated by Tier 1 institutional attesters.
 * Domain-scoped record store + full mesh index. Serve query traffic.
 * Propagate up to Anchors, lateral to peers."
 */

import Fastify from "fastify";
import cors from "@fastify/cors";
import { loadRelayConfig } from "./config.js";
import { RelayStore } from "./store.js";
import { PropagationManager } from "./propagation.js";
import { relayRoutes } from "./routes.js";

async function start() {
  const config = loadRelayConfig();

  const app = Fastify({
    logger: {
      transport: { target: "pino-pretty", options: { colorize: true } },
    },
  });

  await app.register(cors, { origin: true });

  app.get("/health", async () => ({
    status: "ok",
    node: "relay",
    tier: 1,
    domain: config.domain,
    timestamp: new Date().toISOString(),
  }));

  // ── INITIALIZE ─────────────────────────────────────────────────────────────
  const store = new RelayStore(config);
  await store.initialize();

  const propagation = new PropagationManager(config, store);

  // ── ROUTES ─────────────────────────────────────────────────────────────────
  await app.register(relayRoutes, { config, store, propagation });

  // ── GRACEFUL SHUTDOWN ──────────────────────────────────────────────────────
  const shutdown = async (signal: string) => {
    console.log(`\n[provus:relay] ${signal} — shutting down`);
    propagation.stop();
    await app.close();
    store.close();
    process.exit(0);
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  // ── START ──────────────────────────────────────────────────────────────────
  await app.listen({ port: config.port, host: config.host });

  console.log("\n");
  console.log("  ██████╗ ██████╗  ██████╗ ██╗   ██╗██╗   ██╗███████╗");
  console.log("  ██╔══██╗██╔══██╗██╔═══██╗██║   ██║██║   ██║██╔════╝");
  console.log("  ██████╔╝██████╔╝██║   ██║██║   ██║██║   ██║███████╗");
  console.log("  ██╔═══╝ ██╔══██╗██║   ██║╚██╗ ██╔╝██║   ██║╚════██║");
  console.log("  ██║     ██║  ██║╚██████╔╝ ╚████╔╝ ╚██████╔╝███████║");
  console.log("  ╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═══╝   ╚═════╝ ╚══════╝");
  console.log(`\n  Relay node — http://${config.host}:${config.port}`);
  console.log(`  Tier 1 — ${config.operatorId}`);
  console.log(`  Domain: ${config.domain}`);
  console.log(`\n  Edge intake:`);
  console.log(`    POST /relay/identity`);
  console.log(`    POST /relay/attestation`);
  console.log(`    POST /relay/revocation`);
  console.log(`    POST /relay/incident`);
  console.log(`    POST /relay/heartbeat`);
  console.log(`  Query serving:`);
  console.log(`    POST /relay/trust/query`);
  console.log(`    GET  /relay/trust/verify/:attestationId`);
  console.log(`    GET  /relay/trust/lineage/:agentId`);
  console.log(`  Status:`);
  console.log(`    GET  /relay/status`);
  console.log(`    GET  /relay/edges`);
  console.log(`    GET  /relay/propagation/status\n`);

  // Start propagation after server is listening
  propagation.start();
}

start().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});
