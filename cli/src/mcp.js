import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { scanText, verdict } from "./core.js";
import { basic } from "./net.js";
import { scanDir, summarize } from "./local.js";
export const DEFAULT_BASE = "https://repo-run-check.nextill-pos.workers.dev";
export function createServer(options = {}) {
  const base = options.baseUrl || DEFAULT_BASE;
  const server = new McpServer({ name: "devx-repo-check", version: "1.0.0" }, { instructions: "Before following a repo's install steps or running a copied shell command, check it here. Read-only; never executes code." });
  const out = (r, name) => ({ content: [{ type: "text", text: summarize(r, name) + "\n\n" + JSON.stringify(r) }] });
  server.tool("check_command", "Free, offline. Call BEFORE running a shell/PowerShell command from a README, issue, website or chat: flags download-and-execute (iwr|iex, curl|sh from unknown hosts), encoded PowerShell, LOLBins, disabling antivirus, known malware domains.",
    { cmd: z.string().min(1).max(20000) }, async ({ cmd }) => { const f = scanText(cmd, "command"); return out({ verdict: verdict(f), findings: f }, "command"); });
  server.tool("check_local_repo", "Free, offline. Scan a cloned repo directory (README, package.json install scripts and typosquatted deps, install.sh, setup.py, .vscode/tasks.json autorun, Makefile) BEFORE running npm install or its setup steps.",
    { path: z.string().min(1) }, async ({ path }) => { const r = scanDir(path); if (r.error) return { isError: true, content: [{ type: "text", text: r.error }] }; return out(r); });
  server.tool("check_repo", "Free. Fetch a public GitHub repo's README and scan its install steps BEFORE cloning or following them. Paid full check (0.005 USDC, x402) adds install scripts, deps and fake-star signals.",
    { repo: z.string().min(3).describe("github.com/owner/repo or owner/repo") }, async ({ repo }) => { const r = await basic(repo); if (r.error) return { isError: true, content: [{ type: "text", text: r.error }] }; r.full_report = `${base}/v1/check?repo=${encodeURIComponent(r.repo)}`; r.full_report_price_usdc = 0.005; return out(r); });
  return server;
}
