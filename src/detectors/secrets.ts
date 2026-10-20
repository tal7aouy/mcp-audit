import type { Detector, DiscoveredServer, Finding } from "../types.js";
// Narrow, synchronous detector shape; `satisfies Detector` keeps conformance.

/**
 * Finds credentials hardcoded into MCP server configs — the env block and args
 * are the usual offenders, since servers are configured with API keys inline.
 */

interface SecretRule {
  name: string;
  re: RegExp;
}

const SECRET_RULES: SecretRule[] = [
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: "OpenAI API key", re: /\bsk-(proj-)?[A-Za-z0-9]{20,}\b/ },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { name: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "Stripe secret key", re: /\bsk_live_[0-9A-Za-z]{24,}\b/ },
  { name: "JWT", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { name: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "Generic bearer token", re: /\bbearer\s+[A-Za-z0-9._-]{20,}\b/i },
];

/** Shannon entropy per character — high values suggest a random secret. */
function entropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Env var names whose value is expected to be a secret. */
const SECRET_NAME_HINT = /(token|secret|password|passwd|api[_-]?key|apikey|auth|credential|private[_-]?key)/i;

function redact(value: string): string {
  if (value.length <= 8) return "****";
  return value.slice(0, 4) + "…" + value.slice(-2);
}

export const secretsDetector = {
  id: "secrets",
  run(target: DiscoveredServer): Finding[] {
    const findings: Finding[] = [];
    const { server, client } = target;

    const base = {
      detector: "secrets",
      server: server.name,
      client: `${client.name} (${client.configPath})`,
    };

    const checkValue = (value: string, where: string, nameHint = false) => {
      for (const rule of SECRET_RULES) {
        if (rule.re.test(value)) {
          findings.push({
            ...base,
            severity: "high",
            title: `Hardcoded ${rule.name} in ${where}`,
            detail: `A ${rule.name} is stored in plaintext in the server config. Anyone with read access to this file — or any tool that can read it — gets the live credential.`,
            evidence: `${where} = ${redact(value)}`,
            remediation:
              "Move the secret to an environment variable reference or a secrets manager, and rotate it since it has been on disk in cleartext.",
          });
          return;
        }
      }
      // Entropy fallback: long high-entropy value under a secret-ish name.
      if (nameHint && value.length >= 20 && entropy(value) >= 3.5 && !value.includes(" ")) {
        findings.push({
          ...base,
          severity: "medium",
          title: `Likely secret in ${where}`,
          detail: `${where} holds a long, high-entropy value under a credential-like name. This looks like a hardcoded secret.`,
          evidence: `${where} = ${redact(value)}`,
          remediation: "Confirm whether this is a credential; if so, externalize and rotate it.",
        });
      }
    };

    if (server.env) {
      for (const [k, v] of Object.entries(server.env)) {
        if (typeof v === "string") checkValue(v, `env.${k}`, SECRET_NAME_HINT.test(k));
      }
    }
    if (server.args) {
      server.args.forEach((a, i) => checkValue(a, `args[${i}]`));
    }
    if (server.url) checkValue(server.url, "url");

    return findings;
  },
} satisfies Detector;
