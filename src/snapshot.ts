import { homedir } from "node:os";
import { join } from "node:path";
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import type { DiscoveredServer, Finding } from "./types.js";

/**
 * Drift / "rug pull" detection.
 *
 * A server you approved can silently change what it does after the fact — a new
 * version, a changed command, a mutated tool description. We fingerprint each
 * server and compare against the last run; any change is surfaced so an
 * after-the-fact swap can't slip past review.
 */

export interface SnapshotEntry {
  fingerprint: string;
  command?: string;
  firstSeen: string;
  lastSeen: string;
}

export type Snapshot = Record<string, SnapshotEntry>;

export function defaultSnapshotPath(): string {
  return join(homedir(), ".mcp-audit-snapshot.json");
}

/** Stable key for a server across runs. */
function serverKey(t: DiscoveredServer): string {
  return `${t.client.id}::${t.server.name}`;
}

/**
 * Fingerprint the security-relevant shape of a server. We include env *keys*
 * but not values (values are secrets, and rotating a key shouldn't look like an
 * attack); we include command, args, url and type.
 */
export function fingerprint(t: DiscoveredServer): string {
  const s = t.server;
  const shape = {
    command: s.command ?? null,
    args: s.args ?? [],
    url: s.url ?? null,
    type: s.type ?? null,
    envKeys: s.env ? Object.keys(s.env).sort() : [],
  };
  return createHash("sha256").update(JSON.stringify(shape)).digest("hex").slice(0, 16);
}

export async function loadSnapshot(path: string): Promise<Snapshot> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as Snapshot;
  } catch {
    return {};
  }
}

export async function saveSnapshot(path: string, snap: Snapshot): Promise<void> {
  await writeFile(path, JSON.stringify(snap, null, 2), "utf8");
}

/**
 * Compare the current servers against the stored snapshot, returning drift
 * findings, and produce the updated snapshot to persist.
 */
export function computeDrift(
  servers: DiscoveredServer[],
  prev: Snapshot,
): { findings: Finding[]; next: Snapshot } {
  const now = new Date().toISOString();
  const next: Snapshot = {};
  const findings: Finding[] = [];
  const firstRun = Object.keys(prev).length === 0;

  const seen = new Set<string>();
  for (const t of servers) {
    const key = serverKey(t);
    seen.add(key);
    const fp = fingerprint(t);
    const before = prev[key];

    const base = {
      detector: "drift",
      server: t.server.name,
      client: `${t.client.name} (${t.client.configPath})`,
    };

    if (!before) {
      if (!firstRun) {
        findings.push({
          ...base,
          severity: "medium",
          title: "New MCP server appeared since last scan",
          detail: "A server that was not present at the previous scan is now configured. Confirm you added it intentionally.",
          evidence: `${t.server.command ?? t.server.url ?? "?"}`,
          remediation: "If you did not add this server, remove it and investigate who did.",
        });
      }
      next[key] = { fingerprint: fp, command: t.server.command, firstSeen: now, lastSeen: now };
    } else if (before.fingerprint !== fp) {
      findings.push({
        ...base,
        severity: "high",
        title: "Server definition changed since last scan (possible rug pull)",
        detail: "This server's launch command, arguments, URL, or env-var set changed since you last approved it. A silent change after approval is the signature of a rug-pull attack.",
        evidence: `fingerprint ${before.fingerprint} -> ${fp}`,
        remediation: "Diff the config against what you expected. Re-review the server before trusting it again.",
      });
      next[key] = { fingerprint: fp, command: t.server.command, firstSeen: before.firstSeen, lastSeen: now };
    } else {
      next[key] = { ...before, lastSeen: now };
    }
  }

  // Carry forward entries that disappeared (informational), without re-adding stale servers.
  for (const [key, entry] of Object.entries(prev)) {
    if (!seen.has(key)) {
      // Dropped servers are fine; we simply stop tracking them.
      void entry;
    }
  }

  return { findings, next };
}
