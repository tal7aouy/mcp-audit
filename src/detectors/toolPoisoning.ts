import type { Detector, DiscoveredServer, Finding } from "../types.js";
import { scanText } from "./patterns.js";

/**
 * Static tool-poisoning scan over the config itself.
 *
 * Some servers ship instructions in fields that end up in front of the model
 * (descriptions, "instructions", custom notes). This walks every string in the
 * raw config entry and runs the injection scanner on it. The deeper, live scan
 * of tool descriptions returned at runtime lives in ../live.ts (--live).
 */

/** Collect every string value in an arbitrary JSON value, with its path. */
function walkStrings(value: unknown, path: string, out: Array<{ path: string; text: string }>) {
  if (typeof value === "string") {
    out.push({ path, text: value });
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => walkStrings(v, `${path}[${i}]`, out));
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      walkStrings(v, path ? `${path}.${k}` : k, out);
    }
  }
}

export const toolPoisoningDetector = {
  id: "tool-poisoning",
  run(target: DiscoveredServer): Finding[] {
    const findings: Finding[] = [];
    const { server, client } = target;
    const base = {
      detector: "tool-poisoning",
      server: server.name,
      client: `${client.name} (${client.configPath})`,
    };

    const strings: Array<{ path: string; text: string }> = [];
    walkStrings(server.raw, "", strings);

    for (const { path, text } of strings) {
      for (const hit of scanText(text)) {
        findings.push({
          ...base,
          severity: hit.severity,
          title: `Suspicious instruction in config (${hit.label})`,
          detail: `The config field "${path}" contains text that reads like an instruction to the AI model rather than data. Tool poisoning hides directives in model-visible text to redirect its behaviour.`,
          evidence: `${path}: "${hit.match}"`,
          remediation:
            "Review this field. Legitimate configs rarely contain imperative instructions aimed at the model.",
        });
      }
    }

    return findings;
  },
} satisfies Detector;
