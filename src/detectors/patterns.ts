import type { Severity } from "../types.js";

/**
 * Text-level heuristics for prompt-injection / tool-poisoning.
 *
 * These run against any untrusted string: a tool description returned by a
 * server, an argument, or a field in the config. Tool poisoning hides
 * instructions to the *model* inside text the model will read, so we look for
 * the shapes those instructions take.
 */

export interface PatternHit {
  severity: Severity;
  label: string;
  /** The matched slice, for evidence. */
  match: string;
  index: number;
}

interface Rule {
  severity: Severity;
  label: string;
  re: RegExp;
}

const RULES: Rule[] = [
  {
    severity: "critical",
    label: "Instruction override ('ignore previous instructions')",
    re: /\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(instruction|prompt|rule|context)/i,
  },
  {
    severity: "critical",
    label: "Hidden directive to the assistant/model",
    re: /\b(you must|you should|always|do not tell|don'?t tell|without (telling|informing)|secretly|silently)\b[^.\n]{0,60}\b(user|assistant|model|ai)\b/i,
  },
  {
    severity: "critical",
    label: "Data exfiltration instruction",
    re: /\b(send|upload|post|exfiltrate|leak|forward|transmit)\b[^.\n]{0,40}\b(ssh|\.env|secret|token|api[_ -]?key|password|credential|private key|~\/)/i,
  },
  {
    severity: "high",
    label: "Reads sensitive local paths",
    re: /(~\/\.ssh|id_rsa|\.aws\/credentials|\.env\b|\/etc\/passwd|\.config\/|keychain)/i,
  },
  {
    severity: "high",
    label: "Embedded <IMPORTANT>/system-style directive block",
    re: /<\/?(important|system|instructions?|secret|hidden|admin)>/i,
  },
  {
    severity: "high",
    label: "Tells model to conceal behaviour from the user",
    re: /\b(do not mention|never mention|hide this|keep this (secret|hidden)|without the user('?s)? knowledge)\b/i,
  },
  {
    severity: "medium",
    label: "Overrides tool-selection / routing",
    re: /\b(before (using|calling) (any|this|other)|always (use|call|route)|instead of)\b[^.\n]{0,40}\btool/i,
  },
  {
    severity: "medium",
    label: "References another tool's arguments (cross-tool shadowing)",
    re: /\b(when|whenever)\b[^.\n]{0,40}\b(other|another|different)\b[^.\n]{0,20}\btool/i,
  },
];

/**
 * Characters that can hide text from a human but not from the model:
 * zero-width spaces/joiners, bidi overrides, word joiner, BOM, soft hyphen,
 * and the Unicode "tag" block (U+E0000–U+E007F) used for invisible payloads.
 * Astral ranges need the \u{...} form under the /u flag.
 */
const INVISIBLE =
  /[​-‏‪-‮⁠-⁤﻿­\u{E0000}-\u{E007F}]/u;

/** Scan a string for injection/poisoning signals. */
export function scanText(text: string): PatternHit[] {
  if (!text) return [];
  const hits: PatternHit[] = [];

  for (const rule of RULES) {
    const m = rule.re.exec(text);
    if (m) {
      hits.push({
        severity: rule.severity,
        label: rule.label,
        match: truncate(m[0]),
        index: m.index,
      });
    }
  }

  const inv = INVISIBLE.exec(text);
  if (inv) {
    hits.push({
      severity: "critical",
      label: "Invisible/zero-width characters (text hidden from humans)",
      match: `U+${text.codePointAt(inv.index)!.toString(16).toUpperCase().padStart(4, "0")} at offset ${inv.index}`,
      index: inv.index,
    });
  }

  return hits;
}

function truncate(s: string, max = 120): string {
  const clean = s.replace(/\s+/g, " ").trim();
  return clean.length > max ? clean.slice(0, max) + "…" : clean;
}
