/**
 * @provus/node — anchor/server.ts
 *
 * VeritasMesh Anchor node entry point.
 *
 * TSD §6.1: "Anchor nodes — operated by Tier 0 attesters.
 * Write-authoritative + sync-authoritative. Full record of all
 * Tier 0/1 attestations + high-severity incidents + revocations.
 * Not on query path. 3–7 nodes at genesis. Must maintain quorum."
 *
 * Production consensus: MonadBFT (arXiv:2502.20692)
 *   - n=3f+1, tolerates f<n/3 Byzantine failures
 *   - ~800ms full finality
 *   - No-tail-forking (NTF) guarantee
 *   - Linear message complexity
 *
 * PoC consensus: threshold majority (floor(N/2)+1)
 */

import Fastify from "fastify";
import cors from "@fastify/cors";
import { loadAnchorConfig } from "./config.js";
import { AnchorStore } from "./store.js";
import { ConsensusEngine } from "./consensus.js";
import { anchorRoutes } from "./routes.js";

async function start() {
  const config = loadAnchorConfig();

  const app = Fastify({
    logger: {
      transport: { target: "pino-pretty", options: { colorize: true } },
    },
  });

  await app.register(cors, { origin: true });

  app.get("/health", async () => ({
    status: "ok",
    node: "anchor",
    tier: 0,
    nodeId: config.nodeId,
    timestamp: new Date().toISOString(),
  }));

  // ── INITIALIZE ─────────────────────────────────────────────────────────────
  const store = new AnchorStore(config);
  await store.initialize();

  const consensus = new ConsensusEngine(config, store);

  // ── ROUTES ─────────────────────────────────────────────────────────────────
  await app.register(anchorRoutes, { config, store, consensus });

  // ── GRACEFUL SHUTDOWN ──────────────────────────────────────────────────────
  const shutdown = async (signal: string) => {
    console.log(`\n[provus:anchor] ${signal} — shutting down`);
    consensus.stop();
    await app.close();
    store.close();
    process.exit(0);
  };

  process.on("SIGINT",  () => shutdown("SIGINT"));
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
  console.log(`\n  Anchor node — http://${config.host}:${config.port}`);
  console.log(`  Tier 0 — ${config.operatorId} (${config.nodeId})`);
  console.log(`  Cluster: ${config.clusterEndpoints.length} node(s), quorum: ${config.quorumThreshold}`);
  console.log(`  Relays: ${config.relayEndpoints.length} connected`);
  console.log(`\n  Record intake:`);
  console.log(`    POST /anchor/records`);
  console.log(`    POST /anchor/consensus/vote`);
  console.log(`    POST /anchor/sync`);
  console.log(`  Revocation fast path:`);
  console.log(`    POST /anchor/revocation     (→ all Relays, target <5s)`);
  console.log(`  Authoritative queries:`);
  console.log(`    POST /anchor/trust/query    (bypasses cache + Relay)`);
  console.log(`  Status:`);
  console.log(`    GET  /anchor/status`);
  console.log(`    GET  /anchor/ledger`);
  console.log(`    GET  /anchor/pending`);
  console.log(`\n  Consensus: ${
    config.clusterEndpoints.length === 1
      ? "single-node PoC"
      : `threshold ${config.quorumThreshold}/${config.clusterEndpoints.length} (PoC)`
  }`);
  console.log(`  Production path: MonadBFT — n=3f+1, <800ms finality, NTF\n`);

  // Start consensus engine after server is listening
  consensus.start();
}

start().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});
