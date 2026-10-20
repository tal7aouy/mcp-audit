import pc from "picocolors";
import type { Finding, ScanResult, Severity } from "./types.js";

const SEV_META: Record<Severity, { label: string; color: (s: string) => string; icon: string }> = {
  critical: { label: "CRITICAL", color: (s) => pc.bgRed(pc.white(pc.bold(s))), icon: "✖" },
  high: { label: "HIGH", color: (s) => pc.red(pc.bold(s)), icon: "▲" },
  medium: { label: "MEDIUM", color: (s) => pc.yellow(pc.bold(s)), icon: "●" },
  low: { label: "LOW", color: (s) => pc.cyan(s), icon: "○" },
  info: { label: "INFO", color: (s) => pc.dim(s), icon: "·" },
};

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function sevTag(sev: Severity): string {
  const m = SEV_META[sev];
  return m.color(` ${m.label} `);
}

/** Pretty, screenshot-friendly terminal report. */
export function renderReport(result: ScanResult): string {
  const lines: string[] = [];
  const { findings, clients, serverCount } = result;

  lines.push("");
  lines.push(pc.bold(pc.magenta("  mcp-audit")) + pc.dim("  ·  MCP security scan"));
  lines.push(pc.dim("  " + "─".repeat(50)));

  if (clients.length === 0) {
    lines.push("");
    lines.push("  " + pc.yellow("No MCP client configs found on this machine."));
    lines.push(pc.dim("  Looked for Claude Desktop, Claude Code, Cursor, Windsurf, VS Code."));
    lines.push(pc.dim("  Point at a config with:  mcp-audit --config <path>"));
    lines.push("");
    return lines.join("\n");
  }

  lines.push("");
  lines.push(`  Clients scanned: ${pc.bold(String(clients.length))}   Servers: ${pc.bold(String(serverCount))}`);
  for (const c of clients) {
    lines.push(pc.dim(`    • ${c.name}  ${c.configPath}`));
  }

  // Severity tally.
  const counts = tally(findings);
  lines.push("");
  const summary = ORDER.filter((s) => counts[s] > 0)
    .map((s) => `${sevTag(s)} ${counts[s]}`)
    .join("   ");
  lines.push("  " + (summary || pc.green(pc.bold("✓ no issues found"))));
  lines.push(pc.dim("  " + "─".repeat(50)));

  if (findings.length === 0) {
    lines.push("");
    lines.push("  " + pc.green("Nothing suspicious in the scanned configs. "));
    lines.push(pc.dim("  Re-run with --live to inspect tool descriptions at runtime."));
    lines.push("");
    return lines.join("\n");
  }

  let n = 0;
  for (const f of findings) {
    n++;
    const m = SEV_META[f.severity];
    lines.push("");
    lines.push(`  ${sevTag(f.severity)} ${pc.bold(f.title)}`);
    lines.push(`     ${pc.dim("server")}  ${f.server}   ${pc.dim("via")} ${pc.dim(f.detector)}`);
    lines.push(`     ${wrap(f.detail, 72, "     ")}`);
    if (f.evidence) {
      lines.push(`     ${pc.dim("evidence")}  ${pc.yellow(f.evidence)}`);
    }
    if (f.remediation) {
      lines.push(`     ${pc.dim("fix")}  ${pc.green(f.remediation)}`);
    }
  }

  lines.push("");
  lines.push(pc.dim("  " + "─".repeat(50)));
  lines.push(
    `  ${pc.bold(String(findings.length))} finding${findings.length === 1 ? "" : "s"} across ${serverCount} server${serverCount === 1 ? "" : "s"}.`,
  );
  if (counts.critical > 0 || counts.high > 0) {
    lines.push("  " + pc.red("Review the critical/high findings before trusting these servers."));
  }
  lines.push("");
  return lines.join("\n");
}

function tally(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** Soft-wrap long text to width, indenting continuation lines. */
function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const out: string[] = [];
  let line = "";
  for (const w of words) {
    if ((line + " " + w).trim().length > width) {
      out.push(line.trim());
      line = w;
    } else {
      line += " " + w;
    }
  }
  if (line.trim()) out.push(line.trim());
  return out.join("\n" + indent);
}

/** Highest severity present, for process exit codes. */
export function worstSeverity(findings: Finding[]): Severity | null {
  for (const s of ORDER) {
    if (findings.some((f) => f.severity === s)) return s;
  }
  return null;
}
