import type { Detector, DiscoveredServer, Finding, ScanResult } from "./types.js";
import { discoverServers } from "./discovery.js";
import { secretsDetector } from "./detectors/secrets.js";
import { permissionsDetector } from "./detectors/permissions.js";
import { toolPoisoningDetector } from "./detectors/toolPoisoning.js";
import { computeDrift, loadSnapshot, saveSnapshot } from "./snapshot.js";

const STATIC_DETECTORS: Detector[] = [
  toolPoisoningDetector,
  secretsDetector,
  permissionsDetector,
];

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export interface ScanOptions {
  /** Extra config paths to include beyond the auto-discovered ones. */
  extraPaths?: string[];
  /** Enable drift detection against the saved snapshot. */
  drift?: boolean;
  /** Path to the drift snapshot store. */
  snapshotPath?: string;
}

export async function runScan(options: ScanOptions = {}): Promise<ScanResult> {
  const { clients, servers } = await discoverServers(options.extraPaths ?? []);
  const findings: Finding[] = [];

  for (const target of servers) {
    for (const detector of STATIC_DETECTORS) {
      const result = await detector.run(target);
      findings.push(...result);
    }
  }

  if (options.drift && options.snapshotPath) {
    const prev = await loadSnapshot(options.snapshotPath);
    const { findings: driftFindings, next } = computeDrift(servers, prev);
    findings.push(...driftFindings);
    await saveSnapshot(options.snapshotPath, next);
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  return {
    scannedAt: new Date().toISOString(),
    clients,
    serverCount: servers.length,
    findings,
  };
}

export function serverList(servers: DiscoveredServer[]): string[] {
  return servers.map((s) => `${s.client.name}/${s.server.name}`);
}
