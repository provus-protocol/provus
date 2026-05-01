/**
 * @provus/sdk — billing.ts
 *
 * Sustainability model activation. TSD §11.
 *
 * Phase 1 (current): usage tracking only. No payment processing.
 * Records every billable operation per operator for when the fee
 * model activates in Phase 2.
 *
 * Phase 2 fee split (TSD §11.3):
 *   65% → issuing attester
 *   20% → serving relay node
 *   15% → protocol treasury
 *
 * Billable operations:
 *   - Attestation issuance (per request)
 *   - Authoritative trust queries (per query — premium)
 *   - Standard trust queries (per query — standard rate)
 *
 * Non-billable:
 *   - Identity provisioning (free — bootstrapping incentive)
 *   - Scope checks (free — must be on critical path, no friction)
 *   - Incident recording (free — safety signals must flow freely)
 *
 * TSD §11.3 Phase 1: "No fees. Free participation for all tiers.
 * Founding token allocation vested 3yr / 1yr cliff."
 */

import { now } from "@provus/core";

// ── TYPES ─────────────────────────────────────────────────────────────────────

export type BillableEventType =
  | "attestation_issued"
  | "attestation_declined"
  | "trust_query_standard"
  | "trust_query_authoritative"
  | "trust_query_batch";

export interface BillableEvent {
  eventId: string;
  operatorId: string;
  eventType: BillableEventType;
  domain?: string;
  attesterTier?: number;
  recordedAt: string;

  /**
   * Phase 2: fee in stablecoin (smallest unit).
   * Phase 1: always 0 — tracking only.
   */
  feeUnits: number;

  /** Phase 2 fee split */
  split?: {
    attester: number;   // 65%
    relay: number;      // 20%
    treasury: number;   // 15%
  };
}

export interface OperatorUsageSummary {
  operatorId: string;
  period: { from: string; to: string };
  events: {
    attestationsIssued: number;
    attestationsDeclined: number;
    trustQueriesStandard: number;
    trustQueriesAuthoritative: number;
    trustQueriesBatch: number;
    total: number;
  };
  fees: {
    totalUnits: number;
    currency: "USD_STABLECOIN";
    phase: "1 — tracking only, no charges";
  };
  tier2EligibilityProgress: {
    daysActive: number;
    requiredDays: number;
    onTrack: boolean;
  };
}

// ── FEE SCHEDULE ──────────────────────────────────────────────────────────────

/**
 * Phase 2 fee schedule (not yet active).
 * TSD §11.3: "Per-attestation fee (stablecoin). Low enough that cost
 * is never a reason not to attest, high enough that the treasury
 * accumulates meaningful reserves."
 *
 * Units: micro-USD (1 unit = $0.000001)
 */
export const FEE_SCHEDULE: Record<BillableEventType, number> = {
  attestation_issued:          1000,  // $0.001 per attestation
  attestation_declined:           0,  // declined attestations are free
  trust_query_standard:          10,  // $0.00001 per standard query
  trust_query_authoritative:    500,  // $0.0005 per authoritative query (premium)
  trust_query_batch:             50,  // $0.00005 per batch query
};

export const FEE_SPLIT = {
  attester:  0.65,
  relay:     0.20,
  treasury:  0.15,
};

// ── BILLING TRACKER ───────────────────────────────────────────────────────────

export class BillingTracker {
  private events: BillableEvent[] = [];
  private operatorFirstActivity: Map<string, string> = new Map();
  private phase: 1 | 2 = 1; // Phase 1: tracking only

  /**
   * Record a billable event.
   * Phase 1: records for tracking, charges 0.
   * Phase 2: records with fee calculation.
   */
  record(
    operatorId: string,
    eventType: BillableEventType,
    meta?: { domain?: string; attesterTier?: number }
  ): BillableEvent {
    // Track first activity for Tier 2 eligibility
    if (!this.operatorFirstActivity.has(operatorId)) {
      this.operatorFirstActivity.set(operatorId, now());
    }

    const feeUnits = this.phase === 2 ? FEE_SCHEDULE[eventType] : 0;
    const split = feeUnits > 0 ? {
      attester: Math.floor(feeUnits * FEE_SPLIT.attester),
      relay: Math.floor(feeUnits * FEE_SPLIT.relay),
      treasury: Math.floor(feeUnits * FEE_SPLIT.treasury),
    } : undefined;

    const event: BillableEvent = {
      eventId: Math.random().toString(36).slice(2),
      operatorId,
      eventType,
      domain: meta?.domain,
      attesterTier: meta?.attesterTier,
      recordedAt: now(),
      feeUnits,
      split,
    };

    this.events.push(event);
    return event;
  }

  /**
   * Get usage summary for an operator.
   * TSD §11.3: Operators need visibility into their usage
   * before Phase 2 fees activate.
   */
  getSummary(operatorId: string, from?: string, to?: string): OperatorUsageSummary {
    const fromTs = from ? new Date(from).getTime() : 0;
    const toTs = to ? new Date(to).getTime() : Date.now();

    const operatorEvents = this.events.filter(
      (e) =>
        e.operatorId === operatorId &&
        new Date(e.recordedAt).getTime() >= fromTs &&
        new Date(e.recordedAt).getTime() <= toTs
    );

    const counts = {
      attestationsIssued: operatorEvents.filter((e) => e.eventType === "attestation_issued").length,
      attestationsDeclined: operatorEvents.filter((e) => e.eventType === "attestation_declined").length,
      trustQueriesStandard: operatorEvents.filter((e) => e.eventType === "trust_query_standard").length,
      trustQueriesAuthoritative: operatorEvents.filter((e) => e.eventType === "trust_query_authoritative").length,
      trustQueriesBatch: operatorEvents.filter((e) => e.eventType === "trust_query_batch").length,
      total: operatorEvents.length,
    };

    const totalFeeUnits = operatorEvents.reduce((sum, e) => sum + e.feeUnits, 0);

    // Tier 2 eligibility progress
    const firstActivity = this.operatorFirstActivity.get(operatorId);
    const daysActive = firstActivity
      ? Math.floor((Date.now() - new Date(firstActivity).getTime()) / 86400000)
      : 0;

    return {
      operatorId,
      period: {
        from: from ?? (firstActivity ?? now()),
        to: to ?? now(),
      },
      events: counts,
      fees: {
        totalUnits: totalFeeUnits,
        currency: "USD_STABLECOIN",
        phase: "1 — tracking only, no charges",
      },
      tier2EligibilityProgress: {
        daysActive,
        requiredDays: 90,
        onTrack: daysActive > 0,
      },
    };
  }

  /**
   * Get treasury accumulation summary.
   * What the treasury would have collected if Phase 2 were active.
   */
  getTreasurySummary(): {
    phase: number;
    totalEventsTracked: number;
    projectedTreasuryUnits: number;
    projectedAttesterUnits: number;
    projectedRelayUnits: number;
    note: string;
  } {
    const projected = this.events.reduce(
      (acc, e) => {
        const fee = FEE_SCHEDULE[e.eventType];
        acc.treasury += Math.floor(fee * FEE_SPLIT.treasury);
        acc.attester += Math.floor(fee * FEE_SPLIT.attester);
        acc.relay += Math.floor(fee * FEE_SPLIT.relay);
        return acc;
      },
      { treasury: 0, attester: 0, relay: 0 }
    );

    return {
      phase: this.phase,
      totalEventsTracked: this.events.length,
      projectedTreasuryUnits: projected.treasury,
      projectedAttesterUnits: projected.attester,
      projectedRelayUnits: projected.relay,
      note:
        this.phase === 1
          ? "Phase 1: tracking only. No charges applied. " +
            "Projected figures show what Phase 2 fees would have collected."
          : "Phase 2 active. Fees are being collected.",
    };
  }

  activatePhase2(): void {
    this.phase = 2;
    console.log(
      "[provus:billing] Phase 2 fee model activated. " +
      "Attestation and query fees are now being collected."
    );
  }

  get currentPhase(): number {
    return this.phase;
  }

  get totalEvents(): number {
    return this.events.length;
  }
}

// ── SINGLETON ─────────────────────────────────────────────────────────────────

let _tracker: BillingTracker | null = null;

export function getBillingTracker(): BillingTracker {
  if (!_tracker) _tracker = new BillingTracker();
  return _tracker;
}
