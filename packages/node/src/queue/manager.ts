/**
 * @provus/node — queue/manager.ts
 *
 * Submission queue for upstream record delivery to the Relay node.
 *
 * TSD §6.4 — Consistency model for writes:
 *   "If an Edge node cannot reach its Relay node, attestation submission
 *    is queued locally and retried. Records are not submitted to an
 *    alternative Relay node — that would create duplicate submission
 *    paths and consistency headaches."
 *
 *   "Records that exceed the age limit without successful submission are
 *    flagged as submission-failed and must be resubmitted manually.
 *    This is a hard constraint, not graceful degradation — stale
 *    unsubmitted attestations are worse than no attestation."
 *
 * The queue flushes automatically when the heartbeat detects
 * the Relay is reachable again.
 */

import type { EdgeStore } from "../store/db.js";
import type { EdgeNodeConfig } from "../config.js";

export class SubmissionQueue {
  private config: EdgeNodeConfig;
  private store: EdgeStore;
  private flushing = false;

  constructor(config: EdgeNodeConfig, store: EdgeStore) {
    this.config = config;
    this.store = store;
  }

  /**
   * Enqueue a record for upstream submission.
   * Called when a write operation cannot be submitted immediately
   * because the Relay is unreachable.
   */
  enqueue(
    id: string,
    type: "attestation" | "identity" | "incident" | "revocation",
    payload: unknown
  ): void {
    this.store.enqueue(id, type, payload);
    console.log(`[provus:queue] Enqueued ${type} ${id.slice(0, 12)}…`);
  }

  /**
   * Submit a record directly to the Relay node.
   * Returns true if successful, false if the Relay is unreachable.
   */
  async submit(
    type: "attestation" | "identity" | "incident" | "revocation",
    payload: unknown
  ): Promise<boolean> {
    const endpoint = this.relayEndpointFor(type);

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);

      const response = await fetch(
        `${this.config.relayEndpoint}${endpoint}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: controller.signal,
        }
      );

      clearTimeout(timeout);

      if (response.ok) {
        return true;
      }

      console.warn(
        `[provus:queue] Relay rejected ${type}: HTTP ${response.status}`
      );
      return false;
    } catch (err: any) {
      return false;
    }
  }

  /**
   * Submit immediately or enqueue if Relay is unreachable.
   * This is the primary write path for all upstream submissions.
   */
  async submitOrQueue(
    id: string,
    type: "attestation" | "identity" | "incident" | "revocation",
    payload: unknown
  ): Promise<"submitted" | "queued"> {
    const success = await this.submit(type, payload);

    if (success) {
      console.log(`[provus:queue] Submitted ${type} ${id.slice(0, 12)}… to Relay`);
      return "submitted";
    }

    this.enqueue(id, type, payload);
    return "queued";
  }

  /**
   * Flush all pending queue items to the Relay.
   * Called automatically when heartbeat detects Relay recovery.
   *
   * TSD §6.4: Records queued during downtime are submitted
   * in order when connectivity is restored.
   */
  async flush(): Promise<void> {
    if (this.flushing) return;
    this.flushing = true;

    const pending = this.store.getPendingSubmissions();
    if (pending.length === 0) {
      this.flushing = false;
      return;
    }

    console.log(`[provus:queue] Flushing ${pending.length} queued submissions`);

    let submitted = 0;
    let failed = 0;

    for (const item of pending) {
      try {
        const payload = JSON.parse(item.payload);
        const success = await this.submit(item.type, payload);

        if (success) {
          this.store.markSubmitted(item.id);
          submitted++;
        } else {
          this.store.incrementAttempt(item.id);
          failed++;

          // Stop flushing if Relay is still down
          // Don't waste attempts on a broken connection
          if (failed >= 3) {
            console.warn(
              "[provus:queue] Relay still unreachable — stopping flush"
            );
            break;
          }
        }
      } catch (err: any) {
        this.store.markSubmissionFailed(item.id);
        failed++;
      }
    }

    console.log(
      `[provus:queue] Flush complete — submitted: ${submitted}, failed: ${failed}`
    );
    this.flushing = false;
  }

  /**
   * Queue depth and status summary.
   */
  getStatus(): {
    pending: number;
    isFlushing: boolean;
  } {
    const pending = this.store.getPendingSubmissions();
    return {
      pending: pending.length,
      isFlushing: this.flushing,
    };
  }

  private relayEndpointFor(
    type: "attestation" | "identity" | "incident" | "revocation"
  ): string {
    switch (type) {
      case "identity":     return "/relay/identity";
      case "attestation":  return "/relay/attestation";
      case "incident":     return "/relay/incident";
      case "revocation":   return "/relay/revocation";
    }
  }
}
