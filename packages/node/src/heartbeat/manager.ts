/**
 * @provus/node — heartbeat/manager.ts
 *
 * Heartbeat protocol for Edge → Relay connection monitoring.
 *
 * TSD §6.5:
 *   "Edge nodes heartbeat to their Relay node every 30 seconds.
 *    3 consecutive missed heartbeats marks the node as degraded.
 *    5 consecutive marks it offline and routes traffic to the
 *    next available node in the same tier."
 *
 * When the Relay becomes unreachable:
 *   1. Cache is marked stale (reads still served with staleness flag)
 *   2. Submissions are queued locally
 *   3. Heartbeat continues — will detect recovery and flush queue
 */

import type { EdgeStore } from "../store/db.js";
import type { EdgeNodeConfig } from "../config.js";
import { SubmissionQueue } from "../queue/manager.js";

export type RelayStatus = "connected" | "degraded" | "offline";

export class HeartbeatManager {
  private config: EdgeNodeConfig;
  private store: EdgeStore;
  private queue: SubmissionQueue;
  private timer: NodeJS.Timeout | null = null;
  private missedBeats = 0;
  private status: RelayStatus = "offline";

  constructor(
    config: EdgeNodeConfig,
    store: EdgeStore,
    queue: SubmissionQueue
  ) {
    this.config = config;
    this.store = store;
    this.queue = queue;
  }

  start(): void {
    console.log(
      `[provus:heartbeat] Starting — interval: ${this.config.heartbeatIntervalMs}ms`
    );
    console.log(`[provus:heartbeat] Relay: ${this.config.relayEndpoint}`);

    // Immediate first beat
    this.beat();

    this.timer = setInterval(
      () => this.beat(),
      this.config.heartbeatIntervalMs
    );
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      console.log("[provus:heartbeat] Stopped");
    }
  }

  getStatus(): RelayStatus {
    return this.status;
  }

  getMissedBeats(): number {
    return this.missedBeats;
  }

  private async beat(): Promise<void> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000); // 5s timeout

      const response = await fetch(
        `${this.config.relayEndpoint}/health`,
        {
          method: "GET",
          signal: controller.signal,
        }
      );

      clearTimeout(timeout);

      if (response.ok) {
        this.onRelayReachable();
      } else {
        this.onRelayUnreachable(`HTTP ${response.status}`);
      }
    } catch (err: any) {
      this.onRelayUnreachable(err.message ?? "Network error");
    }
  }

  private onRelayReachable(): void {
    const wasDown = this.status !== "connected";
    this.missedBeats = 0;
    this.status = "connected";
    this.store.recordRelayContact();

    if (wasDown) {
      console.log("[provus:heartbeat] Relay connection restored");
      // Flush the queue now that we're back online
      this.queue.flush().catch((err) => {
        console.error("[provus:heartbeat] Queue flush error:", err.message);
      });
    }
  }

  private onRelayUnreachable(reason: string): void {
    this.missedBeats++;

    const previousStatus = this.status;

    if (this.missedBeats >= this.config.heartbeatOfflineThreshold) {
      this.status = "offline";
    } else if (this.missedBeats >= this.config.heartbeatDegradedThreshold) {
      this.status = "degraded";
    }

    this.store.updateRelayStatus(this.status, this.missedBeats);

    // On first miss — mark all cache stale
    // TSD §6.4: "Reads prefer availability over consistency — serve stale
    // cache with explicit staleness flag if Relay is down."
    if (this.missedBeats === 1) {
      this.store.markAllCacheStale();
    }

    if (this.status !== previousStatus) {
      console.warn(
        `[provus:heartbeat] Relay status: ${previousStatus} → ${this.status} ` +
        `(missed: ${this.missedBeats}, reason: ${reason})`
      );
    } else {
      console.warn(
        `[provus:heartbeat] Relay unreachable (missed: ${this.missedBeats}, reason: ${reason})`
      );
    }
  }
}
