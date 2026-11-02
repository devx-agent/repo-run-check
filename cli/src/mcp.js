import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { scanText, verdict, ADVICE } from "./core.js";
import { basic } from "./net.js";
import { scanDir, summarize } from "./local.js";
export const DEFAULT_BASE = "https://repo-run-check.nextill-pos.workers.dev";
export const VERSION = "1.1.0";
const VERDICTS = ["no_red_flags", "review_before_running", "dangerous"];
const finding = z.object({
  level: z.enum(["info", "warn", "danger"]), code: z.string().describe("machine-readable rule id, e.g. pipe_to_shell"), message: z.string(),
  file: z.string().optional(), line: z.number().optional(), evidence: z.string().optional().describe("the matching text, clipped"),
}).passthrough();
const VERDICT_TEXT = "verdict: no_red_flags (nothing matched; not proof of safety), review_before_running (at least one warning: read the flagged lines first) or dangerous (download-and-execute, encoded payloads, known malware hosts and similar: do not run)";
const RO = { readOnlyHint: true, destructiveHint: false, idempotentHint: true };

export function createServer(options = {}) {
  const base = options.baseUrl || DEFAULT_BASE;
  const server = new McpServer({ name: "devx-repo-check", version: VERSION }, {
    instructions: "Call these tools BEFORE an agent runs a shell command from a README, issue, website or chat, runs npm install / setup steps of a cloned repo, or follows a GitHub repo's install instructions. Pick check_command for one command, check_local_repo for a folder on this machine, check_repo for a public GitHub repo that is not cloned yet. All three are read-only static checks: they never execute code, never install anything and never ask for keys. Verdicts are heuristics, not guarantees.",
  });
  const out = (r, name) => ({ structuredContent: r, content: [{ type: "text", text: summarize(r, name) + "\n\n" + JSON.stringify(r) }] });

  server.registerTool("check_command", {
    title: "Check a shell command before running it",
    description: [
      "Statically scans one shell, bash or PowerShell command (or a short script) for malware-installer patterns before anyone runs it.",
      "Use it whenever an agent is about to run a command copied from a README, issue, gist, website, chat or AI answer, and for one-liners like curl | sh or iwr | iex.",
      "It flags download-and-execute (curl/wget piped to a shell, iwr/irm piped to iex) from unknown hosts, encoded or obfuscated PowerShell, Windows LOLBins (mshta, certutil, rundll32...), commands that disable antivirus or Defender, and known malware domains. Well-known installers (rustup, Foundry, Anza and similar) are reported as info only.",
      "Offline: nothing is sent anywhere and the command is never executed.",
      "Returns " + VERDICT_TEXT + ", plus findings (level, code, message, line, evidence).",
      "For a whole cloned folder use check_local_repo. For a GitHub repo that is not cloned yet use check_repo.",
    ].join(" "),
    inputSchema: { cmd: z.string().min(1).max(20000).describe("The exact command or script text you plan to run, unmodified (1-20000 characters). Multi-line input is fine; each line is checked.") },
    outputSchema: { verdict: z.enum(VERDICTS), advice: z.string(), findings: z.array(finding) },
    annotations: { ...RO, openWorldHint: false },
  }, async ({ cmd }) => { const f = scanText(cmd, "command"); const v = verdict(f); return out({ verdict: v, advice: ADVICE[v], findings: f }, "command"); });

  server.registerTool("check_local_repo", {
    title: "Check a cloned repo folder before installing it",
    description: [
      "Statically scans a repository folder on the machine running this MCP server before you run npm install, pip install, make or its setup steps.",
      "It reads only these files if present (each up to 300 KB): README.md, package.json, install.sh, setup.sh, setup.py, requirements.txt, .vscode/tasks.json and Makefile. It looks for npm lifecycle scripts (preinstall/postinstall) that download or run code, typosquatted or URL dependencies, setup.py side effects, VS Code tasks that autorun on folder open, and dangerous commands in the README and scripts.",
      "Read-only: it never executes anything, never writes files and sends nothing over the network. Other source files are not inspected, so this is not a full malware scan.",
      "Returns " + VERDICT_TEXT + ", plus advice, files_checked, findings (level, code, message, file, line, evidence) and install_commands found in README code blocks.",
      "Use check_repo instead when the repo is only on GitHub and not cloned yet.",
    ].join(" "),
    inputSchema: { path: z.string().min(1).max(4096).describe("Path to the repo's root folder on this machine, absolute or relative to the server's working directory. In Docker, the folder must be mounted into the container.") },
    outputSchema: { path: z.string(), verdict: z.enum(VERDICTS), advice: z.string(), files_checked: z.array(z.string()), findings: z.array(finding), install_commands: z.array(z.string()) },
    annotations: { ...RO, openWorldHint: false },
  }, async ({ path }) => { const r = scanDir(path); if (r.error) return { isError: true, content: [{ type: "text", text: r.error }] }; return out(r); });

  server.registerTool("check_repo", {
    title: "Check a public GitHub repo's install steps",
    description: [
      "Fetches a public GitHub repo's README (raw.githubusercontent.com, up to 300 KB) and scans its install instructions before you clone it or follow them.",
      "Use it when a user or agent is told to 'clone this repo and run the setup' or is evaluating a starter kit, trading bot, wallet tool or MCP server from GitHub.",
      "Free and read-only: one unauthenticated HTTPS request to GitHub; nothing is cloned or executed. Only the README is checked here. The optional paid hosted check (" + base + "/v1/check, 0.25 USDC via x402 on Base) also reads package.json install scripts, dependencies, setup files and repo metadata such as age and fake-star signals. This tool does not pay for it; it only returns its URL.",
      "Returns " + VERDICT_TEXT + ", plus repo, url, advice, files_checked, findings, install_commands, tier, full_report (URL of the paid check) and full_report_price_usdc. Errors if the repo is private, renamed or missing.",
      "If the repo is already cloned, check_local_repo covers more files at no cost.",
    ].join(" "),
    inputSchema: { repo: z.string().min(3).max(300).describe("Public GitHub repository as owner/repo or https://github.com/owner/repo (a trailing .git or path is fine). Other hosts are not supported.") },
    outputSchema: { repo: z.string(), url: z.string(), verdict: z.enum(VERDICTS), advice: z.string(), files_checked: z.array(z.string()), findings: z.array(finding), install_commands: z.array(z.string()), tier: z.string(), full_report: z.string(), full_report_price_usdc: z.number() },
    annotations: { ...RO, openWorldHint: true },
  }, async ({ repo }) => { const r = await basic(repo); if (r.error) return { isError: true, content: [{ type: "text", text: r.error }] }; r.full_report = `${base}/v1/check?repo=${encodeURIComponent(r.repo)}`; r.full_report_price_usdc = 0.25; return out(r); });
  return server;
}
