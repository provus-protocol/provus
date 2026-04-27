/**
 * @provus/node — relay/propagation.ts
 *
 * Propagation manager for the Relay node.
 *
 * Handles two propagation paths:
 *
 * 1. Relay → Anchor (upstream)
 *    TSD §6.2: Target < 5 seconds.
 *    All records go upstream. High-severity revocations use a
 *    dedicated fast path with a separate timeout budget.
 *
 * 2. Relay → Relay (lateral, same domain)
 *    TSD §6.2: Target < 2 seconds.
 *    Records propagate to all peer Relay nodes in the same domain
 *    so any Relay can serve queries for this domain.
 *
 * Propagation is fire-and-confirm: records are queued in the store
 * before propagation is attempted. If propagation fails, the queue
 * retries on the next flush cycle. Records are never lost.
 */

import type { RelayStore } from "./store.js";
import type { RelayNodeConfig } from "./config.js";
import { generateId } from "@provus/core";

export class PropagationManager {
  private config: RelayNodeConfig;
  private store: RelayStore;
  private flushTimer: NodeJS.Timeout | null = null;
  private flushing = false;

  constructor(config: RelayNodeConfig, store: RelayStore) {
    this.config = config;
    this.store = store;
  }

  start(): void {
    // Flush standard propagation queue every 2 seconds
    // High-severity revocations are pushed immediately, not on this timer
    this.flushTimer = setInterval(() => this.flush(), 2000);
    console.log("[provus:relay:propagation] Started — standard flush every 2s");
    console.log(
      `[provus:relay:propagation] Anchor endpoints: ${this.config.anchorEndpoints.join(", ") || "none"}`
    );
    console.log(
      `[provus:relay:propagation] Peer relays: ${this.config.peerRelayEndpoints.join(", ") || "none"}`
    );
  }

  stop(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  /**
   * Queue a record for propagation to all Anchors and peer Relays.
   * Called whenever a new record is accepted by the Relay.
   */
  queueRecord(
    recordId: string,
    recordType: "identity" | "attestation" | "revocation" | "incident",
    payload: unknown,
    priority: "standard" | "high" = "standard"
  ): void {
    // Queue for each Anchor
    for (const anchorEndpoint of this.config.anchorEndpoints) {
      this.store.queueForAnchor(
        generateId(),
        recordId,
        recordType,
        { payload, source: "relay", relayId: this.config.operatorId },
        priority
      );
    }

    // Queue for each peer Relay
    for (const peerEndpoint of this.config.peerRelayEndpoints) {
      this.store.queueForPeer(
        generateId(),
        recordId,
        recordType,
        peerEndpoint,
        { payload, source: "relay", relayId: this.config.operatorId }
      );
    }

    if (priority === "high") {
      // High-severity: push immediately, don't wait for flush cycle
      // TSD §6.2: "High-severity revocations use a dedicated push path,
      // targeting < 5 seconds full propagation."
      this.pushHighSeverityImmediate(recordId, recordType, payload)
        .catch((err) => console.error("[provus:relay:propagation] High-severity push error:", err.message));
    }
  }

  /**
   * Immediate push for high-severity revocations.
   * Bypasses the queue flush cycle — goes directly to all endpoints.
   * TSD §6.2 revocation fast path.
   */
  async pushHighSeverityImmediate(
    recordId: string,
    recordType: string,
    payload: unknown
  ): Promise<void> {
    const start = Date.now();
    console.log(
      `[provus:relay:propagation] HIGH SEVERITY push — ${recordType} ${recordId.slice(0, 12)}…`
    );

    const allTargets = [
      ...this.config.anchorEndpoints.map((e) => ({ endpoint: e, type: "anchor" })),
      ...this.config.peerRelayEndpoints.map((e) => ({ endpoint: e, type: "peer" })),
    ];

    await Promise.allSettled(
      allTargets.map(async ({ endpoint, type }) => {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(
            () => controller.abort(),
            this.config.revocationPushTimeoutMs
          );

          const response = await fetch(
            `${endpoint}/relay/revocation/push`,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                payload,
                severity: "high",
                source: this.config.operatorId,
              }),
              signal: controller.signal,
            }
          );

          clearTimeout(timeout);
          const elapsed = Date.now() - start;

          if (response.ok) {
            console.log(
              `[provus:relay:propagation] High-severity pushed to ${type} ${endpoint} in ${elapsed}ms`
            );
          } else {
            console.warn(
              `[provus:relay:propagation] High-severity push rejected by ${endpoint}: HTTP ${response.status}`
            );
          }
        } catch (err: any) {
          console.warn(
            `[provus:relay:propagation] High-severity push failed to ${endpoint}: ${err.message}`
          );
        }
      })
    );

    const totalElapsed = Date.now() - start;
    if (totalElapsed > this.config.revocationPushTimeoutMs) {
      console.warn(
        `[provus:relay:propagation] High-severity push exceeded target: ${totalElapsed}ms > ${this.config.revocationPushTimeoutMs}ms`
      );
    }
  }

  /**
   * Flush standard propagation queue.
   * Runs every 2 seconds. Processes pending Anchor and peer Relay submissions.
   */
  async flush(): Promise<void> {
    if (this.flushing) return;
    this.flushing = true;

    try {
      await Promise.all([
        this.flushAnchorQueue(),
        this.flushPeerQueue(),
      ]);
    } finally {
      this.flushing = false;
    }
  }

  private async flushAnchorQueue(): Promise<void> {
    const pending = this.store.getPendingAnchorQueue();
    if (!pending.length) return;

    for (const item of pending) {
      let submitted = false;

      for (const anchorEndpoint of this.config.anchorEndpoints) {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 5000);

          const response = await fetch(
            `${anchorEndpoint}/anchor/records`,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: item.payload,
              signal: controller.signal,
            }
          );

          clearTimeout(timeout);

          if (response.ok) {
            submitted = true;
            break; // One anchor confirmed — mark sent
          }
        } catch {
          // Try next anchor
        }
      }

      this.store.markAnchorQueueItem(item.id, submitted ? "sent" : "failed");

      if (submitted) {
        console.log(
          `[provus:relay:propagation] → Anchor: ${item.record_type} ${item.record_id?.slice(0, 12)}…`
        );
      }
    }
  }

  private async flushPeerQueue(): Promise<void> {
    const pending = this.store.getPendingPeerQueue();
    if (!pending.length) return;

    for (const item of pending) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3000);

        const response = await fetch(
          `${item.peer_endpoint}/relay/records`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: item.payload,
            signal: controller.signal,
          }
        );

        clearTimeout(timeout);
        this.store.markPeerQueueItem(item.id, response.ok ? "sent" : "failed");

        if (response.ok) {
          console.log(
            `[provus:relay:propagation] → Peer: ${item.record_type} ${item.record_id?.slice(0, 12)}… to ${item.peer_endpoint}`
          );
        }
      } catch {
        this.store.markPeerQueueItem(item.id, "failed");
      }
    }
  }

  getStatus(): {
    pendingAnchor: number;
    pendingPeer: number;
    isFlushing: boolean;
    anchorEndpoints: string[];
    peerEndpoints: string[];
  } {
    const stats = this.store.getStats();
    return {
      pendingAnchor: stats.pendingAnchorQueue,
      pendingPeer: stats.pendingPeerQueue,
      isFlushing: this.flushing,
      anchorEndpoints: this.config.anchorEndpoints,
      peerEndpoints: this.config.peerRelayEndpoints,
    };
  }
}
