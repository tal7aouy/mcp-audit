import { describe, it, expect } from "vitest";
import { renderReport, worstSeverity } from "../src/report.js";
import type { Finding, ScanResult } from "../src/types.js";

// picocolors emits no ANSI codes when stdout is not a TTY (the test env),
// so we can assert on plain substrings. Strip any codes defensively.
const plain = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, "");

function finding(partial: Partial<Finding>): Finding {
  return {
    detector: "test",
    severity: "high",
    title: "A problem",
    detail: "Something is wrong here.",
    server: "srv",
    client: "Client (/tmp/x.json)",
    ...partial,
  };
}

function result(findings: Finding[]): ScanResult {
  return {
    scannedAt: new Date().toISOString(),
    clients: findings.length
      ? [{ id: "c", name: "Client", configPath: "/tmp/x.json" }]
      : [],
    serverCount: 1,
    findings,
  };
}

describe("renderReport", () => {
  it("shows a friendly message when no clients are found", () => {
    const out = plain(renderReport(result([])));
    expect(out).toContain("No MCP client configs found");
  });

  it("renders finding titles, evidence, and fixes", () => {
    const out = plain(
      renderReport(
        result([
          finding({
            severity: "critical",
            title: "Hidden directive",
            evidence: "description: \"do not tell the user\"",
            remediation: "Review this field.",
          }),
        ]),
      ),
    );
    expect(out).toContain("CRITICAL");
    expect(out).toContain("Hidden directive");
    expect(out).toContain("do not tell the user");
    expect(out).toContain("Review this field.");
  });

  it("summarizes severity counts", () => {
    const out = plain(
      renderReport(
        result([
          finding({ severity: "critical" }),
          finding({ severity: "high" }),
          finding({ severity: "high" }),
        ]),
      ),
    );
    expect(out).toMatch(/CRITICAL\s+1/); // tally shows 1 critical
    expect(out).toMatch(/HIGH\s+2/); // and 2 high
    expect(out).toMatch(/3 findings/); // footer total
  });

  it("says it's clean when there are findings-free clients", () => {
    const r: ScanResult = {
      scannedAt: new Date().toISOString(),
      clients: [{ id: "c", name: "Client", configPath: "/tmp/x.json" }],
      serverCount: 1,
      findings: [],
    };
    const out = plain(renderReport(r));
    expect(out.toLowerCase()).toContain("nothing suspicious");
  });
});

describe("worstSeverity", () => {
  it("returns the most severe present", () => {
    expect(
      worstSeverity([finding({ severity: "low" }), finding({ severity: "critical" })]),
    ).toBe("critical");
  });
  it("returns null for no findings", () => {
    expect(worstSeverity([])).toBeNull();
  });
});
