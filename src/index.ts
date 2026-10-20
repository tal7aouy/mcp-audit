import pc from "picocolors";
import { runScan } from "./scanner.js";
import { renderReport, worstSeverity } from "./report.js";
import { defaultSnapshotPath } from "./snapshot.js";
import type { Severity } from "./types.js";

const VERSION = "0.1.0";

interface Args {
  json: boolean;
  drift: boolean;
  help: boolean;
  version: boolean;
  configs: string[];
  snapshot: string;
  failOn: Severity;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function parseArgs(argv: string[]): Args {
  const args: Args = {
    json: false,
    drift: true,
    help: false,
    version: false,
    configs: [],
    snapshot: defaultSnapshotPath(),
    failOn: "high",
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    switch (a) {
      case "--json":
        args.json = true;
        break;
      case "--no-drift":
        args.drift = false;
        break;
      case "-h":
      case "--help":
        args.help = true;
        break;
      case "-v":
      case "--version":
        args.version = true;
        break;
      case "--config":
        args.configs.push(expect(argv, ++i, "--config"));
        break;
      case "--snapshot":
        args.snapshot = expect(argv, ++i, "--snapshot");
        break;
      case "--fail-on": {
        const v = expect(argv, ++i, "--fail-on") as Severity;
        if (!SEVERITIES.includes(v)) fail(`--fail-on must be one of: ${SEVERITIES.join(", ")}`);
        args.failOn = v;
        break;
      }
      default:
        fail(`Unknown option: ${a}`);
    }
  }
  return args;
}

function expect(argv: string[], i: number, flag: string): string {
  const v = argv[i];
  if (v === undefined) fail(`${flag} requires a value`);
  return v!;
}

function fail(msg: string): never {
  process.stderr.write(pc.red(`error: ${msg}\n`));
  process.exit(2);
}

const HELP = `
${pc.bold(pc.magenta("mcp-audit"))} — scan your installed MCP servers for security problems

${pc.bold("USAGE")}
  mcp-audit [options]

${pc.bold("WHAT IT CHECKS")}
  • tool poisoning / prompt-injection text hidden in configs
  • hardcoded secrets (API keys, tokens, private keys)
  • risky launch paths (shell exec, curl|bash, unpinned npx/uvx)
  • remote / plaintext-HTTP endpoints
  • drift: servers that changed since your last scan (rug pulls)

${pc.bold("OPTIONS")}
  --config <path>    Also scan this config file (repeatable)
  --json             Emit findings as JSON
  --no-drift         Skip drift detection
  --snapshot <path>  Drift snapshot location (default: ~/.mcp-audit-snapshot.json)
  --fail-on <sev>    Exit non-zero at/above this severity (default: high)
                     one of: critical, high, medium, low, info
  -h, --help         Show this help
  -v, --version      Show version

${pc.bold("EXIT CODES")}
  0  clean (nothing at/above --fail-on)   1  findings at/above --fail-on   2  usage error
`;

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    process.stdout.write(HELP + "\n");
    return;
  }
  if (args.version) {
    process.stdout.write(VERSION + "\n");
    return;
  }

  const result = await runScan({
    extraPaths: args.configs,
    drift: args.drift,
    snapshotPath: args.snapshot,
  });

  if (args.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  } else {
    process.stdout.write(renderReport(result) + "\n");
  }

  // Exit code reflects the worst finding vs the fail-on threshold.
  const worst = worstSeverity(result.findings);
  if (worst) {
    const rank = SEVERITIES.indexOf(worst);
    const threshold = SEVERITIES.indexOf(args.failOn);
    if (rank <= threshold) process.exit(1);
  }
}

main().catch((err) => {
  process.stderr.write(pc.red(`\nmcp-audit crashed: ${(err as Error).message}\n`));
  process.exit(2);
});
