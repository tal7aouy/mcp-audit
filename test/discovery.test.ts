import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverServers, stripJsonComments } from "../src/discovery.js";

let dir: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "mcp-audit-disc-"));
});
afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function fixture(name: string, body: unknown): Promise<string> {
  const p = join(dir, name);
  await writeFile(p, typeof body === "string" ? body : JSON.stringify(body), "utf8");
  return p;
}

describe("discoverServers (via extra config paths)", () => {
  it("parses the mcpServers shape", async () => {
    const p = await fixture("a.json", {
      mcpServers: { weather: { command: "node", args: ["w.js"] } },
    });
    const { servers } = await discoverServers([p]);
    expect(servers).toHaveLength(1);
    expect(servers[0]!.server.name).toBe("weather");
    expect(servers[0]!.server.command).toBe("node");
  });

  it("parses the VS Code servers shape", async () => {
    const p = await fixture("b.json", {
      servers: { db: { command: "uvx", args: ["db-mcp"] } },
    });
    const { servers } = await discoverServers([p]);
    expect(servers.map((s) => s.server.name)).toContain("db");
  });

  it("parses the nested mcp.servers shape", async () => {
    const p = await fixture("c.json", {
      mcp: { servers: { x: { url: "https://x/mcp" } } },
    });
    const { servers } = await discoverServers([p]);
    expect(servers[0]!.server.url).toBe("https://x/mcp");
  });

  it("reads JSONC (comments + trailing content)", async () => {
    const p = await fixture(
      "d.jsonc",
      `{
        // my config
        "mcpServers": {
          "t": { "command": "node" } /* inline */
        }
      }`,
    );
    const { servers } = await discoverServers([p]);
    expect(servers).toHaveLength(1);
  });

  it("skips files that are missing or invalid JSON", async () => {
    const bad = await fixture("bad.json", "{ not json ");
    const { servers } = await discoverServers([bad, join(dir, "does-not-exist.json")]);
    expect(servers).toHaveLength(0);
  });

  it("tags each server with its client config path", async () => {
    const p = await fixture("e.json", { mcpServers: { s: { command: "node" } } });
    const { clients } = await discoverServers([p]);
    expect(clients[0]!.configPath).toBe(p);
  });
});

describe("stripJsonComments edge cases", () => {
  it("keeps // and /* inside string values", () => {
    const parsed = JSON.parse(
      stripJsonComments('{"a":"http://x","b":"/* literal */","c":"a//b"}'),
    );
    expect(parsed.a).toBe("http://x");
    expect(parsed.b).toBe("/* literal */");
    expect(parsed.c).toBe("a//b");
  });

  it("handles escaped quotes in strings", () => {
    const parsed = JSON.parse(stripJsonComments('{"a":"she said \\"hi\\" // ok"}'));
    expect(parsed.a).toBe('she said "hi" // ok');
  });
});
