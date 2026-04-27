/**
 * @provus/node
 * VeritasMesh node implementations.
 * Edge node:   v0.1.0 — packages/node/src/edge.ts
 * Relay node:  v0.1.0 — packages/node/src/relay/server.ts
 * Anchor node: coming v0.4.0
 */

// Edge node
export { EdgeStore } from "./store/db.js";
export { SubmissionQueue } from "./queue/manager.js";
export { HeartbeatManager } from "./heartbeat/manager.js";
export { loadConfig } from "./config.js";
export type { EdgeNodeConfig } from "./config.js";
export type { NodeState, QueuedSubmission } from "./store/db.js";
export type { RelayStatus } from "./heartbeat/manager.js";

// Relay node
export { RelayStore } from "./relay/store.js";
export { PropagationManager } from "./relay/propagation.js";
export { loadRelayConfig } from "./relay/config.js";
export type { RelayNodeConfig } from "./relay/config.js";
export type { EdgeNodeEntry, PropagationRecord } from "./relay/store.js";
