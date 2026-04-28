/**
 * @provus/node — anchor/consensus.ts
 *
 * Consensus engine for the Anchor node.
 *
 * PoC model: threshold signature consensus.
 *   - N Anchor nodes in the cluster
 *   - A record is confirmed when M = floor(N/2)+1 nodes vote to confirm
 *   - This is simple majority — equivalent to BFT safety under honest majority
 *
 * Production path: MonadBFT integration.
 *   MonadBFT properties relevant to Provus (from Grok research):
 *   - n=3f+1 validators, tolerates f<n/3 Byzantine failures
 *   - ~800ms full finality (well within our <10s Anchor consensus target)
 *   - No-tail-forking (NTF) guarantee — prevents record censorship
 *   - Linear message complexity — scales to large validator sets
 *   - Safety holds as long as <2/3 stake is malicious (T8 residual risk)
 *
 * The consensus interface is designed so swapping PoC threshold
 * voting for MonadBFT requires only replacing this module.
 * Everything above (store, routes, propagation) stays the same.
 *
 * TSD §6.2 Anchor consensus target: < 10 seconds.
 */

import type { AnchorStore } from "./store.js";
import type { AnchorNodeConfig } from "./config.js";
import { generateId, now } from "@provus/core";

export type ConsensusResult = {
  recordId: string;
  confirmed: boolean;
  votes: number;
  required: number;
  elapsed: number;
};

export class ConsensusEngine {
  private config: AnchorNodeConfig;
  private store: AnchorStore;
  private syncTimer: NodeJS.Timeout | null = null;

  constructor(config: AnchorNodeConfig, store: AnchorStore) {
    this.config = config;
    this.store = store;
  }

  start(): void {
    // Periodic sync with peer Anchor nodes
    this.syncTimer = setInterval(
      () => this.syncWithPeers(),
      this.config.syncIntervalMs
    );
    console.log(
      `[provus:anchor:consensus] Started — sync interval: ${this.config.syncIntervalMs}ms`
    );
    console.log(
      `[provus:anchor:consensus] Cluster: ${this.config.clusterEndpoints.length} nodes, ` +
      `quorum: ${this.config.quorumThreshold}`
    );

    if (this.config.clusterEndpoints.length === 1) {
      console.log(
        "[provus:anchor:consensus] Single-node mode — all records auto-confirm (PoC)"
      );
    }
  }

  stop(): void {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
  }

  /**
   * Propose a record for consensus.
   *
   * In single-node mode (PoC): auto-confirms immediately.
   * In multi-node mode: broadcasts vote request to all peers,
   * waits for quorum within the consensus timeout.
   *
   * TSD §6.2 target: Anchor consensus < 10 seconds.
   */
  async propose(
    recordId: string,
    recordType: "identity" | "attestation" | "revocation" | "incident",
    domain: string,
    payload: unknown,
    submittedBy: string
  ): Promise<ConsensusResult> {
    const start = Date.now();

    // Submit to local store — starts as pending, self-vote recorded
    const alreadyConfirmed = this.store.submitRecord(
      recordId, recordType, domain, payload, submittedBy
    );

    if (alreadyConfirmed) {
      return {
        recordId,
        confirmed: true,
        votes: this.config.quorumThreshold,
        required: this.config.quorumThreshold,
        elapsed: Date.now() - start,
      };
    }

    // Single-node: self-vote is sufficient for quorum — auto-confirm
    if (this.config.clusterEndpoints.length === 1 ||
        this.config.quorumThreshold === 1) {
      const result = this.store.recordVote(
        recordId, this.config.nodeId, "confirm", "single-node-auto"
      );
      return {
        recordId,
        confirmed: result.confirmed,
        votes: result.votes,
        required: result.required,
        elapsed: Date.now() - start,
      };
    }

    // Multi-node: broadcast to peers and collect votes
    await this.broadcastVoteRequest(recordId, recordType, domain, payload);

    // Wait for quorum with timeout
    const result = await this.waitForQuorum(
      recordId,
      this.config.consensusTimeoutMs
    );

    const elapsed = Date.now() - start;

    if (elapsed > 10_000) {
      console.warn(
        `[provus:anchor:consensus] Consensus exceeded 10s target: ${elapsed}ms for ${recordId.slice(0, 16)}…`
      );
    } else {
      console.log(
        `[provus:anchor:consensus] Consensus in ${elapsed}ms for ${recordId.slice(0, 16)}… ` +
        `(confirmed: ${result.confirmed})`
      );
    }

    return { recordId, ...result, elapsed };
  }

  /**
   * Receive a vote from a peer Anchor node.
   * Called by the HTTP route when a peer votes.
   */
  receiveVote(
    recordId: string,
    voterId: string,
    vote: "confirm" | "reject",
    signature: string
  ): ConsensusResult {
    const start = Date.now();
    const result = this.store.recordVote(recordId, voterId, vote, signature);

    if (result.confirmed) {
      console.log(
        `[provus:anchor:consensus] Quorum reached via peer vote: ${recordId.slice(0, 16)}…`
      );
    }

    return {
      recordId,
      confirmed: result.confirmed,
      votes: result.votes,
      required: result.required,
      elapsed: Date.now() - start,
    };
  }

  /**
   * Broadcast a vote request to all peer Anchor nodes.
   * Peers will receive this, validate, and respond with their vote.
   */
  private async broadcastVoteRequest(
    recordId: string,
    recordType: string,
    domain: string,
    payload: unknown
  ): Promise<void> {
    const peers = this.config.clusterEndpoints.filter(
      (e) => !e.includes(`:${this.config.port}`)
    );

    if (!peers.length) return;

    await Promise.allSettled(
      peers.map(async (peer) => {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 3000);

          await fetch(`${peer}/anchor/consensus/vote`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              recordId,
              recordType,
              domain,
              payload,
              proposerId: this.config.nodeId,
            }),
            signal: controller.signal,
          });

          clearTimeout(timeout);
        } catch {
          // Peer unreachable — consensus continues with available nodes
        }
      })
    );
  }

  /**
   * Poll the store until quorum is reached or timeout expires.
   */
  private async waitForQuorum(
    recordId: string,
    timeoutMs: number
  ): Promise<{ confirmed: boolean; votes: number; required: number }> {
    const deadline = Date.now() + timeoutMs;
    const pollInterval = 200; // 200ms poll

    while (Date.now() < deadline) {
      const record = this.store.getRecord(recordId, "attestation") ??
                     this.store.getRecord(recordId, "identity") ??
                     this.store.getRecord(recordId, "revocation") ??
                     this.store.getRecord(recordId, "incident");

      if (record?.status === "confirmed") {
        return {
          confirmed: true,
          votes: record.quorumVotes,
          required: record.quorumRequired,
        };
      }

      await sleep(pollInterval);
    }

    // Timeout — return current state (provisional)
    const record = this.store.getPendingRecords()
      .find((r) => r.recordId === recordId);

    return {
      confirmed: false,
      votes: record?.quorumVotes ?? 0,
      required: this.config.quorumThreshold,
    };
  }

  /**
   * Sync confirmed records with peer Anchor nodes.
   * Ensures all Anchors have the same authoritative ledger.
   *
   * TSD §6.1: "Anchor nodes must maintain quorum."
   */
  private async syncWithPeers(): Promise<void> {
    const peers = this.config.clusterEndpoints.filter(
      (e) => !e.includes(`:${this.config.port}`)
    );

    if (!peers.length) return;

    for (const peer of peers) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4000);

        const response = await fetch(`${peer}/anchor/sync`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            nodeId: this.config.nodeId,
            confirmedCount: this.store.getStats().confirmedRecords,
          }),
          signal: controller.signal,
        });

        clearTimeout(timeout);

        if (response.ok) {
          const data = await response.json() as any;
          this.store.recordSync(
            generateId(),
            peer,
            data.recordsSynced ?? 0,
            "success"
          );
        }
      } catch {
        this.store.recordSync(generateId(), peer, 0, "failed");
      }
    }
  }

  getStatus(): {
    nodeId: string;
    clusterSize: number;
    quorumThreshold: number;
    consensusModel: string;
    productionPath: string;
  } {
    return {
      nodeId: this.config.nodeId,
      clusterSize: this.config.clusterEndpoints.length,
      quorumThreshold: this.config.quorumThreshold,
      consensusModel: this.config.clusterEndpoints.length === 1
        ? "single-node (PoC)"
        : `threshold-${this.config.quorumThreshold}-of-${this.config.clusterEndpoints.length} (PoC)`,
      productionPath: "MonadBFT — n=3f+1, <800ms finality, NTF guarantee",
    };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
