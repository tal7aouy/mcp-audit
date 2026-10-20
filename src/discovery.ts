import { homedir, platform } from "node:os";
import { join } from "node:path";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import type { DiscoveredServer, McpClient, McpServerConfig } from "./types.js";

/**
 * Well-known locations where AI clients store their MCP server lists.
 * Paths differ per OS; we build the candidate list for the current platform.
 */
interface ClientSpec {
  id: string;
  name: string;
  paths: string[];
}

function clientSpecs(): ClientSpec[] {
  const home = homedir();
  const os = platform();
  const appData = process.env.APPDATA ?? join(home, "AppData", "Roaming");

  const claudeDesktop =
    os === "darwin"
      ? join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
      : os === "win32"
        ? join(appData, "Claude", "claude_desktop_config.json")
        : join(home, ".config", "Claude", "claude_desktop_config.json");

  return [
    { id: "claude-desktop", name: "Claude Desktop", paths: [claudeDesktop] },
    {
      id: "claude-code",
      name: "Claude Code",
      paths: [join(home, ".claude.json"), join(process.cwd(), ".mcp.json")],
    },
    {
      id: "cursor",
      name: "Cursor",
      paths: [join(home, ".cursor", "mcp.json"), join(process.cwd(), ".cursor", "mcp.json")],
    },
    {
      id: "windsurf",
      name: "Windsurf",
      paths: [join(home, ".codeium", "windsurf", "mcp_config.json")],
    },
    {
      id: "vscode",
      name: "VS Code",
      paths: [join(process.cwd(), ".vscode", "mcp.json")],
    },
  ];
}

/** Pull the server map out of the many config shapes clients use. */
function extractServerMap(parsed: unknown): Record<string, unknown> {
  if (!parsed || typeof parsed !== "object") return {};
  const obj = parsed as Record<string, unknown>;

  // Most clients: { "mcpServers": { ... } }
  if (obj.mcpServers && typeof obj.mcpServers === "object") {
    return obj.mcpServers as Record<string, unknown>;
  }
  // VS Code: { "servers": { ... } } or { "mcp": { "servers": { ... } } }
  if (obj.servers && typeof obj.servers === "object") {
    return obj.servers as Record<string, unknown>;
  }
  if (obj.mcp && typeof obj.mcp === "object") {
    const mcp = obj.mcp as Record<string, unknown>;
    if (mcp.servers && typeof mcp.servers === "object") {
      return mcp.servers as Record<string, unknown>;
    }
  }
  return {};
}

/** Normalize one raw server entry into our McpServerConfig shape. */
function normalizeServer(name: string, raw: unknown): McpServerConfig {
  const entry = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  return {
    name,
    command: typeof entry.command === "string" ? entry.command : undefined,
    args: Array.isArray(entry.args) ? entry.args.map(String) : undefined,
    env:
      entry.env && typeof entry.env === "object"
        ? (entry.env as Record<string, string>)
        : undefined,
    url: typeof entry.url === "string" ? entry.url : undefined,
    type: typeof entry.type === "string" ? entry.type : undefined,
    raw,
  };
}

/**
 * Scan the filesystem for client configs and return every MCP server found,
 * tagged with the client it belongs to.
 */
export async function discoverServers(
  extraPaths: string[] = [],
): Promise<{ clients: McpClient[]; servers: DiscoveredServer[] }> {
  const specs = clientSpecs();
  const clients: McpClient[] = [];
  const servers: DiscoveredServer[] = [];

  const jobs: Array<{ id: string; name: string; path: string }> = [];
  for (const spec of specs) {
    for (const p of spec.paths) jobs.push({ id: spec.id, name: spec.name, path: p });
  }
  for (const p of extraPaths) {
    jobs.push({ id: "custom", name: "Custom config", path: p });
  }

  for (const job of jobs) {
    if (!existsSync(job.path)) continue;

    let parsed: unknown;
    try {
      const text = await readFile(job.path, "utf8");
      parsed = JSON.parse(stripJsonComments(text));
    } catch {
      // Unreadable or invalid JSON — skip quietly; not every candidate exists cleanly.
      continue;
    }

    const serverMap = extractServerMap(parsed);
    const names = Object.keys(serverMap);
    if (names.length === 0) continue;

    const client: McpClient = { id: job.id, name: job.name, configPath: job.path };
    clients.push(client);

    for (const name of names) {
      servers.push({ client, server: normalizeServer(name, serverMap[name]) });
    }
  }

  return { clients, servers };
}

/**
 * Minimal JSON-with-comments stripper. VS Code configs are JSONC.
 * Not a full parser — removes // line and /* block comments outside strings.
 */
export function stripJsonComments(input: string): string {
  let out = "";
  let inString = false;
  let stringChar = "";
  let inLine = false;
  let inBlock = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;
    const next = input[i + 1];

    if (inLine) {
      if (ch === "\n") {
        inLine = false;
        out += ch;
      }
      continue;
    }
    if (inBlock) {
      if (ch === "*" && next === "/") {
        inBlock = false;
        i++;
      }
      continue;
    }
    if (inString) {
      out += ch;
      if (ch === "\\") {
        // Preserve escaped char verbatim.
        out += input[i + 1] ?? "";
        i++;
      } else if (ch === stringChar) {
        inString = false;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      inString = true;
      stringChar = ch;
      out += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      inLine = true;
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlock = true;
      i++;
      continue;
    }
    out += ch;
  }
  return out;
}
