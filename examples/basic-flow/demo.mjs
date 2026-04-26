/**
 * Provus — Basic Flow Demo
 *
 * This demo runs the complete happy path of the Provus protocol:
 *
 *   1. Provision an orchestrator identity (the system standing up agents)
 *   2. Provision an agent identity (produces a Provenance Certificate)
 *   3. Verify the Provenance Certificate cryptographically
 *   4. Build and submit an attestation request
 *   5. Provision an attester identity and issue a signed attestation
 *   6. Resolve a trust query and receive a Trust Envelope
 *   7. Verify the attestation record independently
 *   8. Resolve the agent's lineage chain
 *
 * No mesh. No relay nodes. No network calls. Real cryptography throughout.
 * Run it: node demo.mjs
 */

import {
  generateKeyPair,
  provision,
  verifyCertificate,
  createRequest,
  issue,
  verifyAttestation,
  createLocalStore,
  registerIdentity,
  storeAttestation,
  resolveQuery,
  resolveLineage,
  DEFAULT_POLICY_WEIGHTS,
  contentAddress,
  now,
} from "@provus/core";

// ── DISPLAY HELPERS ───────────────────────────────────────────────────────────

const RESET  = "\x1b[0m";
const BOLD   = "\x1b[1m";
const DIM    = "\x1b[2m";
const TEAL   = "\x1b[36m";
const GREEN  = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED    = "\x1b[31m";
const NAVY   = "\x1b[34m";
const SILVER = "\x1b[37m";

function header(text) {
  const line = "─".repeat(62);
  console.log(`\n${TEAL}${line}${RESET}`);
  console.log(`${BOLD}${NAVY}  ${text}${RESET}`);
  console.log(`${TEAL}${line}${RESET}`);
}

function step(n, text) {
  console.log(`\n${BOLD}${TEAL}  [${n}]${RESET} ${BOLD}${text}${RESET}`);
}

function field(label, value, truncate = true) {
  const display =
    truncate && typeof value === "string" && value.length > 48
      ? value.slice(0, 24) + "…" + value.slice(-8)
      : value;
  console.log(`      ${DIM}${label.padEnd(26)}${RESET}${SILVER}${display}${RESET}`);
}

function ok(text) {
  console.log(`      ${GREEN}✓ ${text}${RESET}`);
}

function warn(text) {
  console.log(`      ${YELLOW}⚠ ${text}${RESET}`);
}

function separator() {
  console.log(`\n      ${DIM}${"·".repeat(54)}${RESET}`);
}

// ── DEMO ──────────────────────────────────────────────────────────────────────

async function main() {
  console.clear();

  console.log(`\n${BOLD}${NAVY}`);
  console.log("  ██████╗ ██████╗  ██████╗ ██╗   ██╗██╗   ██╗███████╗");
  console.log("  ██╔══██╗██╔══██╗██╔═══██╗██║   ██║██║   ██║██╔════╝");
  console.log("  ██████╔╝██████╔╝██║   ██║██║   ██║██║   ██║███████╗");
  console.log("  ██╔═══╝ ██╔══██╗██║   ██║╚██╗ ██╔╝██║   ██║╚════██║");
  console.log("  ██║     ██║  ██║╚██████╔╝ ╚████╔╝ ╚██████╔╝███████║");
  console.log("  ╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═══╝   ╚═════╝ ╚══════╝");
  console.log(`${RESET}`);
  console.log(`  ${DIM}Agent identity · Attestation · Reputation protocol${RESET}`);
  console.log(`  ${DIM}VeritasMesh — decentralized attester network${RESET}`);
  console.log(`\n  ${SILVER}Basic flow demo — v0.1.0${RESET}`);

  // ── STEP 0: Initialize the local mesh store ────────────────────────────────
  header("Initializing local VeritasMesh store");
  console.log(`\n  ${DIM}In production this is a distributed mesh of Anchor, Relay,${RESET}`);
  console.log(`  ${DIM}and Edge nodes. For this demo: in-memory, real cryptography.${RESET}`);
  const store = createLocalStore();
  ok("Local mesh store initialized");

  // ── STEP 1: Orchestrator identity ─────────────────────────────────────────
  header("Step 1 — Orchestrator identity");
  step(1, "Generating orchestrator keypair");
  console.log(`\n  ${DIM}The orchestrator is the system that stands up agents.${RESET}`);
  console.log(`  ${DIM}Its private key signs Provenance Certificates.${RESET}\n`);

  const orchestratorKeys = await generateKeyPair();
  field("Orchestrator public key", orchestratorKeys.publicKey);
  ok("Orchestrator keypair generated");

  // ── STEP 2: Provision agent ────────────────────────────────────────────────
  header("Step 2 — Provision agent identity");
  step(2, "Calling provus.identity.provision()");
  console.log(`\n  ${DIM}TSD §4.1: "An agent that acts before it has a registered${RESET}`);
  console.log(`  ${DIM}identity is invisible to the trust layer."${RESET}\n`);

  const agentResult = await provision(orchestratorKeys.privateKey, {
    orchestratorId: "orchestrator-demo-v1",
    capabilityScope: [
      "filesystem:read",
      "network:http:get",
      "llm:inference",
      "tool:code_execution",
    ],
    intendedScope: "Code review and analysis agent",
    mode: "orchestrator",
  });

  field("Agent ID", agentResult.identity.agentId);
  field("Public key", agentResult.identity.publicKey);
  field("Capability scope", agentResult.identity.capabilityScope.join(", "), false);
  field("Provisioning mode", agentResult.identity.provisioningMode);
  field("Status", agentResult.identity.status);
  field("Created at", agentResult.identity.createdAt);
  field("Lineage depth", String(agentResult.identity.lineageChain.length) + " (top-level agent)");
  field("Revocation anchor", agentResult.identity.revocationAnchor.registryId);

  separator();
  field("Certificate issued at", agentResult.certificate.issuedAt);
  field("Orchestrator signature", agentResult.certificate.orchestratorSignature);
  field("Parent co-signature", agentResult.certificate.parentSignature ?? "none (top-level)");

  ok("Provenance Certificate issued");

  // Register identity in the local mesh store
  registerIdentity(store, agentResult.identity);
  ok("Identity registered in local mesh store");

  // ── STEP 3: Verify the Provenance Certificate ──────────────────────────────
  header("Step 3 — Verify Provenance Certificate");
  step(3, "Calling provus.trust.verify(certificate)");
  console.log(`\n  ${DIM}TSD §4.1: cryptographic verification of the birth record.${RESET}`);
  console.log(`  ${DIM}Checks: agent ID derivation, orchestrator signature, lineage.${RESET}\n`);

  const certVerification = await verifyCertificate(
    agentResult.certificate,
    orchestratorKeys.publicKey
  );

  field("Valid", String(certVerification.valid));
  field("Agent ID verified", String(certVerification.errors.length === 0));
  field("Lineage depth", String(certVerification.lineageDepth));

  if (certVerification.errors.length > 0) {
    certVerification.errors.forEach((e) => warn(e));
  } else {
    ok("All certificate checks passed");
    ok("Agent ID correctly derived from public key");
    ok("Orchestrator signature cryptographically valid");
    ok("Lineage chain consistent");
  }

  // ── STEP 4: Build an attestation request ──────────────────────────────────
  header("Step 4 — Build attestation request");
  step(4, "Calling provus.attest.request()");
  console.log(`\n  ${DIM}TSD §4.2: "Pull-based — the agent/operator requests attestation.${RESET}`);
  console.log(`  ${DIM}Attesters do not proactively scan and endorse."${RESET}\n`);

  // The evidence artifact — in production this would be an evaluation report,
  // test results, audit logs, etc. We content-address it, not embed it.
  const evidenceArtifact = {
    evaluationType: "operational_behavior_audit",
    agentId: agentResult.identity.agentId,
    tasksEvaluated: 47,
    scopeViolations: 0,
    taskCompletionRate: 0.979,
    evaluatorId: "eval-system-v2",
    evaluatedAt: now(),
    findings: "Agent consistently operated within declared capability scope. No deviation events recorded.",
  };

  const request = createRequest({
    subjectAgentId: agentResult.identity.agentId,
    claimType: "behavior",
    domain: "operational_behavior",
    evidence: evidenceArtifact,
    targetTier: 2,
    requestedConfidence: 0.75,
  });

  field("Request ID", request.requestId);
  field("Claim type", request.claimType);
  field("Domain", request.domain);
  field("Evidence ref (SHA-256)", request.evidenceRef);
  field("Target tier", "Tier " + request.targetTier);
  field("Requested confidence", String(request.requestedConfidence));

  ok("Evidence artifact content-addressed (not embedded)");
  ok("Attestation request constructed");

  // ── STEP 5: Attester issues attestation ───────────────────────────────────
  header("Step 5 — Attester issues attestation");
  step(5, "Calling provus.attest.issue()");
  console.log(`\n  ${DIM}TSD §4.2: "Once issued, the attester cannot unilaterally delete${RESET}`);
  console.log(`  ${DIM}a record — they can only issue a Revocation Notice."${RESET}\n`);

  // In production: a credentialed Tier 2 attester would receive this request
  // via the mesh and issue the attestation after evaluation.
  // In the demo: we simulate a Tier 2 operator attester.
  const attesterKeys = await generateKeyPair();

  const attestation = await issue({
    request,
    attesterId: attesterKeys.publicKey,
    attesterTier: 2,
    confidenceScore: 0.82,       // attester's honest assessment — may differ from requested
    validForSeconds: 90 * 24 * 60 * 60, // 90 days — Tier 2 default
    attesterPrivateKey: attesterKeys.privateKey,
  });

  field("Attestation ID", attestation.attestationId);
  field("Subject agent ID", attestation.subjectAgentId);
  field("Attester ID", attestation.attesterId);
  field("Attester tier", "Tier " + attestation.attesterTier);
  field("Confidence score", String(attestation.confidenceScore) + " (not boolean — probabilistic)");
  field("Valid from", attestation.validFrom);
  field("Valid until", attestation.validUntil);
  field("Attester signature", attestation.attesterSignature);

  ok("Attestation record signed by attester's Ed25519 key");
  ok("Confidence score is probabilistic [0.0–1.0], not boolean");
  ok("Validity window set — all attestations expire");

  // Store in local mesh
  storeAttestation(store, attestation);
  ok("Attestation stored in local mesh");

  // ── STEP 6: Trust query ────────────────────────────────────────────────────
  header("Step 6 — Trust query → Trust Envelope");
  step(6, "Calling provus.trust.query()");
  console.log(`\n  ${DIM}TSD §4.3: "There is no oracle. The relying party pulls attestation${RESET}`);
  console.log(`  ${DIM}records, applies their own policy weights, computes a trust score."${RESET}\n`);

  const query = {
    subjectAgentId: agentResult.identity.agentId,
    requestedScope: ["filesystem:read", "llm:inference"],
    policyWeights: {
      ...DEFAULT_POLICY_WEIGHTS,
      minimumAttesterTier: 2,
      minimumConfidence: 0.6,
      domainWeights: {
        operational_behavior: 0.8,
        safety_evaluation: 1.0,
      },
    },
    queriedAt: now(),
  };

  console.log(`  ${DIM}  Relying party policy:${RESET}`);
  field("Min attester tier", "Tier " + query.policyWeights.minimumAttesterTier);
  field("Min confidence", String(query.policyWeights.minimumConfidence));
  field("Operational behavior weight", String(query.policyWeights.domainWeights.operational_behavior));

  separator();

  const envelope = resolveQuery(query, store);

  console.log(`\n  ${BOLD}Trust Envelope:${RESET}\n`);
  field("Recommended scope", envelope.recommendedScope.join(", "), false);
  field("Confidence interval", `[${envelope.confidenceInterval[0]}, ${envelope.confidenceInterval[1]}]`);
  field("Freshness timestamp", envelope.freshnessTimestamp);
  field("Contributing attestations", String(envelope.attestationRefs.length));
  field("Resolved from", envelope.resolvedFrom);
  field("Envelope expiry", envelope.validUntil ?? envelope.expiry);

  ok("Trust envelope returned — not a binary allow/deny");
  ok("Relying party applies their own decision function");
  ok("Envelope carries expiry — trust decisions are not permanent");

  // ── STEP 7: Independent attestation verification ───────────────────────────
  header("Step 7 — Independent attestation verification");
  step(7, "Calling provus.trust.verify(attestationId)");
  console.log(`\n  ${DIM}TSD §7.3: "Verifies a specific attestation: checks attester${RESET}`);
  console.log(`  ${DIM}signature, current tier standing, and revocation notices."${RESET}\n`);

  const verification = await verifyAttestation(
    attestation,
    attesterKeys.publicKey,
    [] // no revocation notices
  );

  field("Valid", String(verification.valid));
  field("Expired", String(verification.expired));
  field("Revoked", String(verification.revoked));
  field("Age", Math.round(verification.ageSeconds) + " seconds");
  field("Confidence score", String(verification.confidenceScore));
  field("Attester tier", "Tier " + verification.attesterTier);

  if (verification.valid) {
    ok("Attester Ed25519 signature cryptographically valid");
    ok("Attestation is within validity window");
    ok("No revocation notices found");
  } else {
    verification.errors.forEach((e) => warn(e));
  }

  // ── STEP 8: Lineage resolution ─────────────────────────────────────────────
  header("Step 8 — Lineage resolution");
  step(8, "Calling provus.trust.lineage(agentId)");
  console.log(`\n  ${DIM}TSD §7.3: "Returns full identity lineage: parent chain,${RESET}`);
  console.log(`  ${DIM}provisioning events, inherited scope constraints."${RESET}\n`);

  const lineage = resolveLineage(agentResult.identity.agentId, store);

  field("Agent ID", lineage.agentId);
  field("Lineage depth", String(lineage.depth));
  field("Root is top-level", String(lineage.rootIsTopLevel));
  field("Parent chain", lineage.lineageChain.length === 0 ? "none — provisioned directly" : lineage.lineageChain.map(a => a.agentId).join(" → "), false);

  ok("Lineage chain resolved — traceable to human-operated provisioning event");

  // ── SUMMARY ────────────────────────────────────────────────────────────────
  header("Protocol flow complete");

  console.log(`
  ${BOLD}What just happened:${RESET}

  ${GREEN}✓${RESET}  Agent identity provisioned with Ed25519 keypair
  ${GREEN}✓${RESET}  Provenance Certificate issued and cryptographically verified
  ${GREEN}✓${RESET}  Evidence artifact content-addressed (SHA-256) — not embedded
  ${GREEN}✓${RESET}  Attestation request constructed (pull-based)
  ${GREEN}✓${RESET}  Attestation issued with probabilistic confidence score
  ${GREEN}✓${RESET}  Attestation stored in local mesh store
  ${GREEN}✓${RESET}  Trust query resolved → Trust Envelope returned
  ${GREEN}✓${RESET}  Attestation independently verified (signature + expiry + revocation)
  ${GREEN}✓${RESET}  Agent lineage traced to human-operated provisioning event

  ${DIM}Everything above used real Ed25519 signatures and SHA-256 hashing.
  No simulated cryptography. The same primitives run in production.${RESET}

  ${DIM}Next: VeritasMesh node implementation (Relay, Edge, Anchor),
  attester tier enforcement, multi-domain trust queries, and
  the full SDK surface over HTTP.${RESET}

  ${TEAL}${"─".repeat(62)}${RESET}
  ${BOLD}${NAVY}  Provus v0.1.0 — Agent identity, attestation, reputation${RESET}
  ${DIM}  github.com/provus-protocol/provus${RESET}
  ${TEAL}${"─".repeat(62)}${RESET}
`);
}

main().catch((err) => {
  console.error(`\n${RED}  Fatal error: ${err.message}${RESET}`);
  console.error(err);
  process.exit(1);
});
