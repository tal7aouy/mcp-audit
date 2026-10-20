/**
 * Shared types for mcp-audit.
 *
 * The data model follows the lifecycle of a scan:
 *   discover client configs -> parse into servers -> run detectors -> findings -> report
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** The AI client a config belongs to (Claude Desktop, Cursor, etc.). */
export interface McpClient {
  /** Stable id, e.g. "claude-desktop". */
  id: string;
  /** Human label, e.g. "Claude Desktop". */
  name: string;
  /** Absolute path to the config file that was found. */
  configPath: string;
}

/**
 * A single MCP server entry as declared in a client config.
 * We normalize the many config shapes into this.
 */
export interface McpServerConfig {
  /** Key the server is registered under in the config. */
  name: string;
  /** Launch command for stdio servers (e.g. "npx"). */
  command?: string;
  /** Arguments passed to the command. */
  args?: string[];
  /** Environment variables handed to the server process. */
  env?: Record<string, string>;
  /** URL for remote (SSE / streamable-http) servers. */
  url?: string;
  /** Transport type if the config declared one. */
  type?: string;
  /** Raw entry, kept for detectors that want the untouched object. */
  raw: unknown;
}

/** A server plus where it came from. */
export interface DiscoveredServer {
  client: McpClient;
  server: McpServerConfig;
}

/** One problem a detector found on a server. */
export interface Finding {
  /** Detector that produced this, e.g. "tool-poisoning". */
  detector: string;
  severity: Severity;
  /** Short one-line title. */
  title: string;
  /** Longer explanation of what and why it matters. */
  detail: string;
  /** Which server this is about. */
  server: string;
  /** Which client config it came from. */
  client: string;
  /** Optional concrete evidence (the matched string, redacted if needed). */
  evidence?: string;
  /** Optional remediation hint. */
  remediation?: string;
}

/** Contract every detector implements. */
export interface Detector {
  id: string;
  /** Run against one discovered server; may return zero or more findings. */
  run(target: DiscoveredServer): Promise<Finding[]> | Finding[];
}

/** Aggregate result of a full scan. */
export interface ScanResult {
  scannedAt: string;
  clients: McpClient[];
  serverCount: number;
  findings: Finding[];
}
