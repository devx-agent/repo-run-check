// Minimal stateless MCP (Streamable HTTP, JSON responses) for the free checks.
import { basic } from "./net.js";
import { scanText, verdict, ADVICE } from "./core.js";
const TOOLS = [
  { name: "check_repo", description: "Free, read-only. Call BEFORE following a GitHub repo's install/setup instructions or running its commands: scans the README for download-and-execute one-liners (iwr|iex, curl|sh from unknown hosts), obfuscated or base64 payloads, known malware domains, agent-targeted prompt injection, password-protected archives. Returns verdict dangerous | review_before_running | no_red_flags with line evidence. Paid full check (0.005 USDC via x402) adds package.json install scripts, typosquatted deps, install.sh/setup.py, .vscode autorun tasks and fake-star signals.",
    inputSchema: { type: "object", properties: { repo: { type: "string", description: "github.com/owner/repo or owner/repo" } }, required: ["repo"] }, annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: "check_command", description: "Free, offline. Call BEFORE running a shell/PowerShell command copied from a README, issue, website or chat: flags download-and-execute, encoded PowerShell, LOLBins, disabling antivirus, known malware domains and pipe-to-shell from unknown hosts.",
    inputSchema: { type: "object", properties: { cmd: { type: "string", description: "command or text block" } }, required: ["cmd"] }, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: "full_report_info", description: "How to buy the full repo check via x402. Does not pay.", inputSchema: { type: "object", properties: {} }, annotations: { readOnlyHint: true } },
];
const ok = (id, result) => ({ jsonrpc: "2.0", id, result });
const err = (id, code, message) => ({ jsonrpc: "2.0", id, error: { code, message } });
const summary = (r) => { const lines = r.findings.filter((f) => f.level !== "info").map((f) => `- [${f.level}] ${f.message}${f.evidence ? " | " + f.file + ":" + f.line + " " + f.evidence : ""}`); return `Verdict: ${r.verdict}. ${r.advice}\n${lines.join("\n") || "No red flags in the text checked."}`; };
async function handle(m, origin) {
  const { id, method, params } = m || {};
  if (id === undefined || id === null) return null;
  if (method === "initialize") return ok(id, { protocolVersion: (params && params.protocolVersion) || "2025-06-18", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "devx-repo-run-check", version: "1.0.0" }, instructions: "Check GitHub repos and shell commands for malware-delivery tricks before running them. Read-only; never executes code." });
  if (method === "ping") return ok(id, {});
  if (method === "tools/list") return ok(id, { tools: TOOLS });
  if (method === "tools/call") {
    const name = params && params.name, a = (params && params.arguments) || {};
    if (name === "full_report_info") return ok(id, { content: [{ type: "text", text: `GET ${origin}/v1/check?repo=...[&repo=...] (1-3 repos) answers HTTP 402 with an x402 v2 PAYMENT-REQUIRED header: exact, eip155:8453, USDC, 5000 units = 0.005 USDC. Settled only after the report is produced. Docs ${origin}/openapi.json. Humans can pay in the browser at ${origin}/` }] });
    if (name === "check_repo") {
      const r = await basic(a.repo || ""); if (r.error) return ok(id, { isError: true, content: [{ type: "text", text: r.error }] });
      r.full_report = `${origin}/v1/check?repo=${encodeURIComponent(r.repo)}`; r.full_report_price_usdc = 0.005;
      return ok(id, { content: [{ type: "text", text: `${r.repo}: ${summary(r)}\nFull check (install scripts, deps, VS Code tasks, fake-star signals): ${r.full_report} (0.005 USDC, x402).\n\n${JSON.stringify(r)}` }], structuredContent: r });
    }
    if (name === "check_command") {
      const c = String(a.cmd || ""); if (!c.trim() || c.length > 20000) return ok(id, { isError: true, content: [{ type: "text", text: "cmd required (max 20000 chars)" }] });
      const findings = scanText(c, "command"), v = verdict(findings), r = { verdict: v, advice: v === "dangerous" ? "Do NOT run this command." : v === "review_before_running" ? "Read what it downloads before running it, or use a sandbox." : "No known red flags. Not proof it is safe.", findings };
      return ok(id, { content: [{ type: "text", text: summary(r) + "\n\n" + JSON.stringify(r) }], structuredContent: r });
    }
    return err(id, -32602, "unknown tool");
  }
  return err(id, -32601, "method not found");
}
export async function mcp(req, origin) {
  const H = { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-expose-headers": "mcp-session-id" };
  if (req.method === "GET") return new Response(JSON.stringify({ name: "devx-repo-run-check", transport: "streamable-http (POST JSON-RPC)", tools: TOOLS.map((t) => t.name) }), { status: 200, headers: H });
  if (req.method !== "POST") return new Response(null, { status: 405, headers: H });
  let body; try { body = await req.json(); } catch { return new Response(JSON.stringify(err(null, -32700, "parse error")), { status: 400, headers: H }); }
  if (Array.isArray(body)) { const out = (await Promise.all(body.map((m) => handle(m, origin)))).filter(Boolean); return out.length ? new Response(JSON.stringify(out), { headers: H }) : new Response(null, { status: 202, headers: H }); }
  const r = await handle(body, origin);
  return r ? new Response(JSON.stringify(r), { headers: H }) : new Response(null, { status: 202, headers: H });
}
