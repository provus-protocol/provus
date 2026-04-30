/**
 * @provus/sdk — version.ts
 *
 * SDK versioning. TSD §7.4 — SDK versioning and compliance certification.
 *
 * Every response carries X-Provus-Version and X-Provus-Protocol-Version headers.
 * Clients can check compatibility before making calls.
 * The /version endpoint exposes full version info.
 *
 * Semantic versioning:
 *   MAJOR — breaking protocol changes (new required fields, removed endpoints)
 *   MINOR — backwards-compatible additions (new endpoints, new optional fields)
 *   PATCH — bug fixes, performance improvements
 *
 * Compatibility rule: a client built against SDK vX.Y.Z can talk to any server
 * running vX.Y'.Z' where Y' >= Y. Major version must match.
 */

export const SDK_VERSION = "0.6.0";
export const PROTOCOL_VERSION = "0.1.0";
export const MIN_CLIENT_VERSION = "0.1.0"; // minimum client version we support

export interface VersionInfo {
  sdkVersion: string;
  protocolVersion: string;
  minClientVersion: string;
  nodeEnv: string;
  uptime: number;
  startedAt: string;
  features: FeatureFlags;
}

export interface FeatureFlags {
  /** Attester registry and tier enforcement active */
  tierEnforcement: boolean;
  /** Scope check uses local cache */
  scopeCheckCache: boolean;
  /** Attestation routing uses registry */
  registryRouting: boolean;
  /** VeritasMesh node connectivity */
  meshConnectivity: boolean;
}

const startedAt = new Date().toISOString();

export function getVersionInfo(features: Partial<FeatureFlags> = {}): VersionInfo {
  return {
    sdkVersion: SDK_VERSION,
    protocolVersion: PROTOCOL_VERSION,
    minClientVersion: MIN_CLIENT_VERSION,
    nodeEnv: process.env.NODE_ENV ?? "development",
    uptime: Math.floor(
      (Date.now() - new Date(startedAt).getTime()) / 1000
    ),
    startedAt,
    features: {
      tierEnforcement: true,
      scopeCheckCache: true,
      registryRouting: true,
      meshConnectivity: false, // true when connected to a live Relay node
      ...features,
    },
  };
}

/**
 * Check if a client version is compatible with this server.
 * Returns null if compatible, an error message if not.
 */
export function checkCompatibility(clientVersion: string | undefined): string | null {
  if (!clientVersion) return null; // no version header — assume compatible

  const [clientMajor] = clientVersion.split(".").map(Number);
  const [serverMajor] = SDK_VERSION.split(".").map(Number);

  if (clientMajor !== serverMajor) {
    return (
      `Client version ${clientVersion} is incompatible with server version ${SDK_VERSION}. ` +
      `Major versions must match. Please upgrade your client.`
    );
  }

  return null;
}

/**
 * Fastify plugin — adds version headers to every response
 * and registers the /version endpoint.
 */
export async function versionPlugin(app: any) {
  // Add version headers to every response
  app.addHook("onSend", async (req: any, reply: any) => {
    reply.header("X-Provus-Version", SDK_VERSION);
    reply.header("X-Provus-Protocol-Version", PROTOCOL_VERSION);
  });

  // Version compatibility check on every request
  app.addHook("onRequest", async (req: any, reply: any) => {
    const clientVersion = req.headers["x-provus-client-version"] as string | undefined;
    const error = checkCompatibility(clientVersion);
    if (error) {
      return reply.status(400).send({
        error: "Version incompatibility",
        message: error,
        serverVersion: SDK_VERSION,
        tsdRef: "TSD §7.4 — SDK versioning and compliance certification",
      });
    }
  });

  // /version endpoint
  app.get("/version", async () => getVersionInfo());
}
