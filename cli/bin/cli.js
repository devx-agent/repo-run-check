#!/usr/bin/env node
import { scanText, verdict, parseRepo } from "../src/core.js";
const args = process.argv.slice(2), json = args.includes("--json"), rest = args.filter((x) => x !== "--json");
if (rest[0] === "mcp") {
  const { createServer } = await import("../src/mcp.js");
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  await createServer({ baseUrl: process.env.REPO_CHECK_URL || undefined }).connect(new StdioServerTransport());
} else if (!rest.length || rest[0] === "-h" || rest[0] === "--help") {
  process.stdout.write(`Usage:
  devx-repo-check [dir]                 scan a cloned repo offline (default: .)
  devx-repo-check owner/repo            fetch + scan a GitHub repo's README
  devx-repo-check --cmd "<command>"     scan one shell command before running it
  devx-repo-check mcp                   run as an MCP server (stdio)
  --json for machine output. Exit code: 0 no red flags, 2 review/dangerous, 1 error. Never executes anything.
`);
} else {
  const { scanDir, summarize } = await import("../src/local.js");
  let r, name;
  if (rest[0] === "--cmd") { const f = scanText(rest.slice(1).join(" "), "command"); r = { verdict: verdict(f), findings: f }; name = "command"; }
  else { const { existsSync } = await import("node:fs");
    if (existsSync(rest[0])) r = scanDir(rest[0]);
    else if (!parseRepo(rest[0]).error) { const { basic } = await import("../src/net.js"); r = await basic(rest[0]); }
    else r = { error: `${rest[0]}: not a directory or github.com/owner/repo` }; }
  if (r.error) { process.stderr.write(r.error + "\n"); process.exitCode = 1; }
  else { process.stdout.write((json ? JSON.stringify(r, null, 2) : summarize(r, name)) + "\n"); process.exitCode = r.verdict === "no_red_flags" ? 0 : 2; }
}
