import type { Detector, DiscoveredServer, Finding } from "../types.js";

/**
 * Flags how a server is launched and reached: shell execution, unpinned
 * remote code via npx/uvx, curl|bash patterns, and remote HTTP endpoints.
 * These are the capabilities an attacker inherits if the server is malicious.
 */

const SHELL_BINARIES = new Set(["sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"]);
const REMOTE_RUNNERS = new Set(["npx", "npx.cmd", "uvx", "uv", "pnpm", "bunx", "dlx"]);

function joinInvocation(target: DiscoveredServer): string {
  const { command, args } = target.server;
  return [command ?? "", ...(args ?? [])].join(" ").trim();
}

export const permissionsDetector = {
  id: "permissions",
  run(target: DiscoveredServer): Finding[] {
    const findings: Finding[] = [];
    const { server, client } = target;
    const base = {
      detector: "permissions",
      server: server.name,
      client: `${client.name} (${client.configPath})`,
    };

    const command = server.command ?? "";
    const bin = command.split(/[\\/]/).pop()?.toLowerCase() ?? "";
    const invocation = joinInvocation(target);

    // Direct shell execution.
    if (SHELL_BINARIES.has(bin)) {
      findings.push({
        ...base,
        severity: "high",
        title: `Server launched through a shell (${bin})`,
        detail: `This server is started via a shell interpreter, so its full command line is shell-evaluated. That widens what a crafted argument or env value can do.`,
        evidence: invocation,
        remediation: "Prefer launching the server binary directly instead of through a shell.",
      });
    }

    // curl|bash / iex download-and-run.
    if (/\b(curl|wget|iwr|invoke-webrequest)\b/i.test(invocation) && /\|\s*(sh|bash|pwsh|iex)/i.test(invocation)) {
      findings.push({
        ...base,
        severity: "critical",
        title: "Downloads and executes remote code at launch (curl|bash)",
        detail: "The launch command fetches a script from the network and pipes it straight into a shell. Whoever controls that URL controls your machine on every start.",
        evidence: invocation,
        remediation: "Never pipe remote downloads into a shell. Vendor the script, review it, and run a pinned copy.",
      });
    }

    // Unpinned remote package runners (npx some-pkg with no @version).
    if (REMOTE_RUNNERS.has(bin)) {
      const pkgArg = (server.args ?? []).find(
        (a) => !a.startsWith("-") && !a.startsWith("@types/"),
      );
      const pinned = pkgArg ? /@\d|@[0-9a-f]{7,}/.test(pkgArg) : false;
      findings.push({
        ...base,
        severity: pinned ? "low" : "medium",
        title: pinned
          ? `Runs a remote package via ${bin}`
          : `Runs an UNPINNED remote package via ${bin}`,
        detail: pinned
          ? `This server pulls and runs a package from a registry each launch. Even pinned, a compromised registry account can affect you.`
          : `This server pulls the latest version of a package from a registry on every launch. A single malicious release (or an account takeover) runs as you, instantly — the classic supply-chain / rug-pull vector.`,
        evidence: invocation,
        remediation: pinned
          ? "Consider vendoring critical servers locally."
          : "Pin an exact version (pkg@1.2.3) or a commit, and review updates before adopting them.",
      });
    }

    // Remote transport endpoints.
    if (server.url) {
      const isHttp = /^http:\/\//i.test(server.url);
      findings.push({
        ...base,
        severity: isHttp ? "high" : "info",
        title: isHttp ? "Remote server over plaintext HTTP" : "Remote (hosted) server endpoint",
        detail: isHttp
          ? "This server is reached over unencrypted HTTP. Traffic — including any tokens — can be read or tampered with on the network path."
          : "This server runs remotely. Its operator sees everything the model sends to it and fully controls the tools and responses you receive.",
        evidence: server.url,
        remediation: isHttp
          ? "Require HTTPS for remote MCP endpoints."
          : "Confirm you trust the operator of this endpoint.",
      });
    }

    return findings;
  },
} satisfies Detector;
