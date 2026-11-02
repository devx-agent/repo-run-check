// Stateless MCP (Streamable HTTP, JSON responses): free checks + one paid tool (full_report) using the x402 MCP transport
// (https://github.com/coinbase/x402/blob/main/specs/transports-v2/mcp.md): unpaid call -> isError result with PaymentRequired
// in structuredContent + content[0].text; paid retry carries PaymentPayload in params._meta["x402/payment"]; the receipt is
// returned in result._meta["x402/payment-response"]. Verify -> build report -> settle only if the report succeeded.
import { basic } from "./net.js";
import { scanText, verdict, parseRepo } from "./core.js";
import { deepReport, reportText } from "./deep.js";
import { PAY_TO, USDC_BASE, PRICE, PRICE_USD, NETWORK, requirements, facil, matches } from "./pay.js";
const PAID_DESC = "PAID (0.25 USDC via x402 on Base, per call). Full pre-run security report for a GitHub repo (1-3 repos per call), for AI coding agents about to clone it and run its install steps. Everything check_repo does, plus: package.json install/lifecycle scripts and the local scripts they run, typosquatted crypto/AI dependencies, install.sh/setup.sh/setup.py/requirements.txt/Makefile, VS Code autorun tasks and settings, dev-container hooks, agent-instruction files (AGENTS.md, CLAUDE.md, .cursorrules, copilot-instructions, .claude hooks/permissions) and MCP server configs shipped in the repo, committed executables and archives from the full file tree, GitHub fake-star / new-owner signals, a 0-100 risk score and concrete next steps. Optional: also checks a command you plan to run. Unpaid calls return an x402 PaymentRequired (isError) result; retry with the signed payment in params._meta[\"x402/payment\"]. You are charged only if the report is delivered.";
const TOOLS = [
  { name: "check_repo", description: "Free, read-only. Call BEFORE following a GitHub repo's install/setup instructions or running its commands: scans the README for download-and-execute one-liners (iwr|iex, curl|sh from unknown hosts), obfuscated or base64 payloads, known malware domains, agent-targeted prompt injection, password-protected archives. Returns verdict dangerous | review_before_running | no_red_flags with line evidence. For the complete check use the paid tool full_report (0.25 USDC via x402): install scripts, deps, autorun tasks, agent/MCP config files, committed binaries, fake-star signals, risk score.",
    inputSchema: { type: "object", properties: { repo: { type: "string", description: "github.com/owner/repo or owner/repo" } }, required: ["repo"] }, annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: "check_command", description: "Free, offline. Call BEFORE running a shell/PowerShell command copied from a README, issue, website or chat: flags download-and-execute, encoded PowerShell, LOLBins, disabling antivirus, known malware domains and pipe-to-shell from unknown hosts.",
    inputSchema: { type: "object", properties: { cmd: { type: "string", description: "command or text block" } }, required: ["cmd"] }, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: "full_report", description: PAID_DESC,
    inputSchema: { type: "object", properties: { repo: { type: "string", description: "github.com/owner/repo or owner/repo (or up to 3, comma-separated)" }, repos: { type: "array", items: { type: "string" }, maxItems: 3, description: "optional instead of repo: 1-3 repos in one paid call" }, command: { type: "string", description: "optional: an install/run command you plan to execute for this repo" } } },
    annotations: { title: "Full repo security report (paid, 0.25 USDC x402)", readOnlyHint: true, openWorldHint: true },
    _meta: { "x402/paid": true, "x402/price": { amount: PRICE, asset: USDC_BASE, network: NETWORK, payTo: PAY_TO, usd: PRICE_USD } } },
  { name: "full_report_info", description: "Free. How to buy the full report (paid MCP tool full_report or HTTP GET /v1/check, 0.25 USDC via x402 on Base). Does not pay.", inputSchema: { type: "object", properties: {} }, annotations: { readOnlyHint: true } },
];
const ok = (id, result) => ({ jsonrpc: "2.0", id, result });
const err = (id, code, message) => ({ jsonrpc: "2.0", id, error: { code, message } });
const summary = (r) => { const lines = r.findings.filter((f) => f.level !== "info").map((f) => `- [${f.level}] ${f.message}${f.evidence ? " | " + f.file + ":" + f.line + " " + f.evidence : ""}`); return `Verdict: ${r.verdict}. ${r.advice}\n${lines.join("\n") || "No red flags in the text checked."}`; };
const toolError = (text) => ({ isError: true, content: [{ type: "text", text }] });
function paymentRequired(origin, error) {
  return { x402Version: 2, error: error || "Payment required to access this resource",
    resource: { url: "mcp://tool/full_report", description: "DevX Repo Run Check full report for 1-3 GitHub repos (" + origin + "/mcp)", mimeType: "application/json" },
    accepts: [requirements()] };
}
const prResult = (pr, extraMeta) => ({ isError: true, structuredContent: pr, content: [{ type: "text", text: JSON.stringify(pr) }], ...(extraMeta ? { _meta: extraMeta } : {}) });
const NO_CHARGE = " You were not charged.";

function repoList(a) {
  const raw = a.repos ?? a.repo; const list = (Array.isArray(raw) ? raw : raw == null ? [] : String(raw).split(/[\s,]+/)).map((x) => String(x).trim()).filter(Boolean);
  return [...new Set(list)];
}
async function fullReport(id, a, meta, origin, env) {
  let payment = meta && meta["x402/payment"];
  if (typeof payment === "string") { try { payment = JSON.parse(payment); } catch { try { payment = JSON.parse(atob(payment)); } catch { payment = null; } } }
  const list = repoList(a);
  if (list.length > 3) return ok(id, toolError("max 3 repos per call." + NO_CHARGE));
  for (const r of list) { const p = parseRepo(r); if (p.error) return ok(id, toolError(`Invalid repo "${r}": ${p.error}.` + NO_CHARGE)); }
  if (a.command !== undefined && String(a.command).length > 20000) return ok(id, toolError("command too long (max 20000 characters)." + NO_CHARGE));
  if (!payment) { console.log(JSON.stringify({ ev: "mcp_payment_required" })); return ok(id, prResult(paymentRequired(origin))); }
  if (!list.length) return ok(id, toolError("repo is required (github.com/owner/repo)." + NO_CHARGE));
  if (!matches(payment)) return ok(id, prResult(paymentRequired(origin, `payment does not match requirements (x402Version 2, exact, ${NETWORK}, USDC ${PRICE} atomic units to ${PAY_TO}).` + NO_CHARGE)));
  const reqs = requirements();
  const v = await facil(env, "verify", { x402Version: 2, paymentPayload: payment, paymentRequirements: reqs });
  if (!v.isValid) { console.log(JSON.stringify({ ev: "mcp_pay_invalid", r: v.invalidReason || "unknown" })); return ok(id, prResult(paymentRequired(origin, "payment verification failed: " + (v.invalidReason || v.errorReason || v.errorMessage || v.message || v.error || "unknown") + "." + NO_CHARGE))); }
  const budget = [24, 6, 0][list.length - 1];
  let reports;
  try { reports = await Promise.all(list.map((r) => deepReport(r, { budget, command: a.command }))); } catch (e) { reports = [{ error: "internal error while building the report" }]; }
  const failed = reports.filter((r) => !r || r.error);
  if (failed.length) return ok(id, toolError("Could not produce the report: " + failed.map((r) => (r && (r.repo || r.input) ? (r.repo || r.input) + ": " : "") + ((r && r.error) || "unknown error")).join("; ") + "." + NO_CHARGE + " (payment authorization was not settled)"));
  const s = await facil(env, "settle", { x402Version: 2, paymentPayload: payment, paymentRequirements: reqs });
  console.log(JSON.stringify({ ev: s.success ? "mcp_paid" : "mcp_settle_fail" }));
  if (!s.success) return ok(id, prResult(paymentRequired(origin, "Settlement failed: " + (s.errorReason || "unknown") + "." + NO_CHARGE), { "x402/payment-response": { success: false, errorReason: s.errorReason || "unknown", transaction: s.transaction || "", network: s.network || NETWORK, payer: s.payer || "" } }));
  const receipt = { success: true, transaction: s.transaction || "", network: s.network || NETWORK, payer: s.payer || payment.payload?.authorization?.from || "" };
  const payInfo = { tx: receipt.transaction, network: receipt.network, amount_usdc: PRICE_USD };
  const out = reports.length === 1 ? { ...reports[0], payment: payInfo } : { count: reports.length, reports, payment: payInfo };
  return ok(id, { content: [{ type: "text", text: reports.map(reportText).join("\n\n----\n\n") + `\n\nPaid ${PRICE_USD} USDC, tx ${receipt.transaction || "n/a"}.\n\n` + JSON.stringify(out) }], structuredContent: out, _meta: { "x402/payment-response": receipt } });
}

async function handle(m, origin, env) {
  const { id, method, params } = m || {};
  if (id === undefined || id === null) return null;
  if (method === "initialize") return ok(id, { protocolVersion: (params && params.protocolVersion) || "2025-06-18", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "devx-repo-run-check", version: "1.2.0" }, instructions: "Check GitHub repos and shell commands for malware-delivery tricks before running them. Read-only; never executes code. check_repo and check_command are free; full_report is paid per call over x402 (0.25 USDC on Base)." });
  if (method === "ping") return ok(id, {});
  if (method === "tools/list") return ok(id, { tools: TOOLS });
  if (method === "tools/call") {
    const name = params && params.name, a = (params && params.arguments) || {};
    if (name === "full_report") return fullReport(id, a, params && params._meta, origin, env);
    if (name === "full_report_info") return ok(id, { content: [{ type: "text", text: `Full report = 0.25 USDC per call (x402 v2, exact, ${NETWORK}, USDC ${USDC_BASE}, ${PRICE} atomic units, payTo ${PAY_TO}). Two ways to buy:\n1) MCP: call tool full_report {repo, command?}. Unpaid it returns an isError result whose structuredContent is an x402 PaymentRequired; sign it and retry with the PaymentPayload in params._meta["x402/payment"]. The receipt comes back in result._meta["x402/payment-response"].\n2) HTTP: GET ${origin}/v1/check?repo=...[&repo=...] (1-3 repos) answers 402 with a PAYMENT-REQUIRED header; retry with PAYMENT-SIGNATURE.\nIncludes install/lifecycle scripts, typosquatted deps, VS Code/dev-container autorun, agent-instruction and MCP config files, committed binaries/archives, GitHub fake-star signals, risk score and next steps. Payment is settled only after the report is produced; on any error you are not charged. Docs ${origin}/openapi.json. Humans can pay in the browser at ${origin}/` }] });
    if (name === "check_repo") {
      const r = await basic(a.repo || ""); if (r.error) return ok(id, toolError(r.error));
      r.full_report = `MCP tool full_report or ${origin}/v1/check?repo=${encodeURIComponent(r.repo)}`; r.full_report_price_usdc = PRICE_USD;
      return ok(id, { content: [{ type: "text", text: `${r.repo}: ${summary(r)}\nFull report (install scripts, deps, autorun tasks, agent/MCP configs, committed binaries, fake-star signals, risk score): paid tool full_report, 0.25 USDC via x402.\n\n${JSON.stringify(r)}` }], structuredContent: r });
    }
    if (name === "check_command") {
      const c = String(a.cmd || ""); if (!c.trim() || c.length > 20000) return ok(id, toolError("cmd required (max 20000 chars)"));
      const findings = scanText(c, "command"), v = verdict(findings), r = { verdict: v, advice: v === "dangerous" ? "Do NOT run this command." : v === "review_before_running" ? "Read what it downloads before running it, or use a sandbox." : "No known red flags. Not proof it is safe.", findings };
      return ok(id, { content: [{ type: "text", text: summary(r) + "\n\n" + JSON.stringify(r) }], structuredContent: r });
    }
    return err(id, -32602, "unknown tool");
  }
  return err(id, -32601, "method not found");
}
export const MCP_TOOLS = TOOLS.map((t) => t.name);
export async function mcp(req, origin, env) {
  const H = { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-expose-headers": "mcp-session-id" };
  if (req.method === "GET") return new Response(JSON.stringify({ name: "devx-repo-run-check", transport: "streamable-http (POST JSON-RPC)", tools: MCP_TOOLS, paid_tools: { full_report: { price_usdc: PRICE_USD, protocol: "x402 v2 MCP transport", network: NETWORK, payTo: PAY_TO } } }), { status: 200, headers: H });
  if (req.method !== "POST") return new Response(null, { status: 405, headers: H });
  let body; try { body = await req.json(); } catch { return new Response(JSON.stringify(err(null, -32700, "parse error")), { status: 400, headers: H }); }
  if (Array.isArray(body)) { const out = (await Promise.all(body.map((m) => handle(m, origin, env)))).filter(Boolean); return out.length ? new Response(JSON.stringify(out), { headers: H }) : new Response(null, { status: 202, headers: H }); }
  const r = await handle(body, origin, env);
  return r ? new Response(JSON.stringify(r), { headers: H }) : new Response(null, { status: 202, headers: H });
}
