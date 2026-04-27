/**
 * @provus/node — edge.ts
 *
 * VeritasMesh Edge node entry point.
 *
 * TSD §6.1: "Edge nodes — operated by Tier 2 operators. Lightweight.
 * Own-agent records + recent query cache. Submit upward to Relay.
 * Low operational overhead by design — no dedicated infrastructure
 * engineering required."
 */

import Fastify from "fastify";
import cors from "@fastify/cors";
import { loadConfig } from "./config.js";
import { EdgeStore } from "./store/db.js";
import { SubmissionQueue } from "./queue/manager.js";
import { HeartbeatManager } from "./heartbeat/manager.js";
import { edgeRoutes } from "./routes/edge.js";
import { generateKeyPair } from "@provus/core";

async function start() {
  const config = loadConfig();

  const app = Fastify({
    logger: {
      transport: {
        target: "pino-pretty",
        options: { colorize: true },
      },
    },
  });

  await app.register(cors, { origin: true });

  // ── HEALTH ─────────────────────────────────────────────────────────────────
  app.get("/health", async () => ({
    status: "ok",
    node: "edge",
    tier: 2,
    timestamp: new Date().toISOString(),
  }));

  // ── INITIALIZE COMPONENTS ──────────────────────────────────────────────────
  const store = new EdgeStore(config);
  await store.initialize(); // async — loads SQLite wasm + disk data
  const queue = new SubmissionQueue(config, store);
  const heartbeat = new HeartbeatManager(config, store, queue);

  // Generate operator and attester keypairs
  // In production: load from secure key store / HSM
  const orchestratorKeys = await generateKeyPair();
  const attesterKeys = await generateKeyPair();

  console.log(`\n[provus:edge] Operator: ${config.operatorId}`);
  console.log(`[provus:edge] Orchestrator: ${orchestratorKeys.publicKey.slice(0, 16)}…`);
  console.log(`[provus:edge] Default attester: ${attesterKeys.publicKey.slice(0, 16)}… (Tier 2)`);
  console.log(`[provus:edge] Relay: ${config.relayEndpoint}`);
  console.log(`[provus:edge] DB: ${config.dbPath}`);

  // ── ROUTES ─────────────────────────────────────────────────────────────────
  await app.register(edgeRoutes, {
    config,
    store,
    heartbeat,
    queue,
    orchestratorPrivateKey: orchestratorKeys.privateKey,
    defaultAttesterPrivateKey: attesterKeys.privateKey,
    defaultAttesterPublicKey: attesterKeys.publicKey,
  });

  // ── GRACEFUL SHUTDOWN ──────────────────────────────────────────────────────
  const shutdown = async (signal: string) => {
    console.log(`\n[provus:edge] ${signal} received — shutting down`);
    heartbeat.stop();
    await app.close();
    store.close();
    console.log("[provus:edge] Shutdown complete");
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
  console.log(`\n  Edge node running on http://${config.host}:${config.port}`);
  console.log(`  Tier 2 — ${config.operatorId}`);
  console.log(`\n  Routes:`);
  console.log(`    POST /edge/identity/provision`);
  console.log(`    GET  /edge/identity/:agentId`);
  console.log(`    POST /edge/attest/request`);
  console.log(`    GET  /edge/attest/list/:agentId`);
  console.log(`    POST /edge/trust/query`);
  console.log(`    GET  /edge/node/status`);
  console.log(`    GET  /edge/node/queue`);
  console.log(`    POST /edge/node/flush`);
  console.log(`\n  Health → GET /health\n`);

  // Start heartbeat after server is up
  heartbeat.start();
}

start().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});
