import { facilitatorConfig } from "../../shared/facilitator.js";
import { enhanceDocs, schemaFrom } from "../../shared/openapi_enhance.js";
import { parseRepo, scanText, verdict, ADVICE } from "./core.js";
import { basic } from "./net.js";
import PAGE from "./page.html";
import EXPLAINER from "./explainer.html";
import { mcp, MCP_TOOLS } from "./mcp.js";
import { deepReport } from "./deep.js";
import { PAY_TO, USDC_BASE, PRICE, PRICE_USD, requirements, facil as facilEnv } from "./pay.js";

const VERSION = "1.2.1";
const SERVICE = "DevX Repo Run Check";
const FACILITATOR = "Coinbase CDP facilitator (api.cdp.coinbase.com/platform/v2/x402)";
const ROUTE = "/v1/check";
const MAX = 3;
const GUIDE = "/is-this-github-repo-safe-to-run";
const DESC = "Full pre-run security report (0.25 USDC) on 1-3 GitHub repos before an AI coding agent runs their install steps: README, install/lifecycle scripts, typosquatted deps, VS Code and dev-container autorun, agent-instruction and MCP config files, committed binaries, fake-star/new-owner signals, risk score and next steps. Also the paid MCP tool full_report.";
const enc = new TextEncoder();
const b64 = (o) => btoa(String.fromCharCode(...enc.encode(JSON.stringify(o))));
const unb64 = (s) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0))));
const EX_REPO = "github.com/SolanaUpdateTools/solana-starter-kit";
const EXAMPLE = { repo: "SolanaUpdateTools/solana-starter-kit", verdict: "dangerous", findings: [{ level: "danger", code: "download_and_execute_powershell" }, { level: "danger", code: "obfuscated_url" }, { level: "warn", code: "never_updated" }], repo_meta: { stars: 287, age_days: 357 } };

function advertised(resUrl) { return { ...requirements(), maxAmountRequired: PRICE, resource: resUrl, description: DESC, mimeType: "application/json" }; }
function paymentRequired(origin, error) {
  const resUrl = origin + ROUTE;
  return { x402Version: 2, error: error || "PAYMENT-SIGNATURE header is required",
    resource: { url: resUrl, description: DESC, mimeType: "application/json", serviceName: SERVICE, tags: ["security", "ai-agents", "supply-chain", "malware", "github", "x402"] },
    accepts: [advertised(resUrl)],
    extensions: { bazaar: { info: { input: { type: "http", method: "GET", discoverable: true, queryParams: { repo: EX_REPO } }, output: { type: "json", example: EXAMPLE } },
      schema: { $schema: "https://json-schema.org/draft/2020-12/schema", type: "object", properties: { input: { type: "object", properties: { type: { type: "string", const: "http" }, method: { type: "string", enum: ["GET"] }, discoverable: { type: "boolean" }, queryParams: { type: "object", properties: { repo: { type: "string", description: "github.com/owner/repo; repeat for up to 3" } }, required: ["repo"] } }, required: ["type", "method"] }, output: { type: "object", properties: { type: { type: "string", const: "json" }, example: schemaFrom(EXAMPLE) } } }, required: ["input"] } } } };
}

// X402_COMPAT_V1: serve x402 v1 body (network "base") + v2 PAYMENT-REQUIRED header; accept v1 X-PAYMENT and v2 PAYMENT-SIGNATURE; accept POST JSON.
const POST_KEY = "repo", POST_MODE = "multi";
function v1Requirements(resUrl) { return { scheme: "exact", network: "base", maxAmountRequired: PRICE, resource: resUrl, description: DESC, mimeType: "application/json", payTo: PAY_TO, maxTimeoutSeconds: 120, asset: USDC_BASE, outputSchema: { input: { type: "http", method: "GET", discoverable: true, queryParams: { [POST_KEY]: { type: "string", required: true } } }, output: schemaFrom(EXAMPLE) }, extra: { name: "USD Coin", version: "2" } }; }
function v1Body(pr) { const resUrl = pr.resource.url; return { x402Version: 1, error: (pr.error && pr.error !== "PAYMENT-SIGNATURE header is required") ? pr.error : "X-PAYMENT header is required (x402 v1) or PAYMENT-SIGNATURE (x402 v2, see PAYMENT-REQUIRED header)", accepts: [v1Requirements(resUrl)], resource: pr.resource, extensions: pr.extensions }; }
function uaFamily(ua) { ua = (ua || "").toLowerCase(); for (const [k, re] of [["x402_sdk", /x402|coinbase|cdp|agentcash|payai/], ["monitor", /monitor|uptime|bot|crawl|spider|scan|probe|check/], ["axios", /axios/], ["python", /python|httpx|aiohttp/], ["curl", /curl|wget/], ["go", /go-http/], ["node", /node|undici/], ["browser", /mozilla/]]) if (re.test(ua)) return k; return ua ? "other" : "none"; }
async function postToParams(req, url) {
  if (req.method !== "POST") return null;
  let b; try { b = await req.json(); } catch { return { error: "POST body must be JSON, e.g. {\"" + POST_KEY + "\": ...}" }; }
  const vals = []; for (const k of [POST_KEY, POST_KEY + "s", POST_KEY + "es"]) { const v = b && b[k]; if (v == null) continue; (Array.isArray(v) ? v : [v]).forEach((x) => vals.push(String(x))); }
  url.searchParams.delete(POST_KEY);
  if (POST_MODE === "join") { if (vals.length) url.searchParams.set(POST_KEY, vals.join(",")); } else vals.forEach((v) => url.searchParams.append(POST_KEY, v));
  return null;
}
const H = { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-expose-headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-RESPONSE" };
const J = (o, status = 200, h = {}) => new Response(JSON.stringify(o, null, 2), { status, headers: { ...H, ...h } });
const T = (s, ct = "text/plain; charset=utf-8") => new Response(s, { headers: { "content-type": ct, "access-control-allow-origin": "*" } });
// CDP_SWITCH: Coinbase CDP facilitator when CDP_API_KEY_ID/SECRET secrets are set (lists in CDP x402 Bazaar), else PayAI.
let ENV = {};
async function facil(op, body) { return facilEnv(ENV, op, body); }
function parseRepos(sp) {
  const list = [...new Set(sp.getAll("repo").map((s) => s.trim()).filter(Boolean))];
  if (!list.length) return { error: "repo query parameter required (repeat ?repo=...&repo=... for up to 3)" };
  if (list.length > MAX) return { error: `max ${MAX} repos per call` };
  for (const r of list) { const x = parseRepo(r); if (x.error) return { error: `${r}: ${x.error}` }; }
  return { list };
}
function commandCheck(cmd) {
  cmd = String(cmd || ""); if (!cmd.trim()) return { error: "cmd required" }; if (cmd.length > 20000) return { error: "max 20000 characters" };
  const findings = scanText(cmd, "command"), v = verdict(findings);
  return { verdict: v, advice: CMD_ADVICE[v], findings, tier: "free (text you supplied, nothing fetched)" };
}
const CMD_ADVICE = { dangerous: "Do NOT run this command. If it already ran: disconnect the machine, check startup entries and unknown processes, and rotate keys, tokens and wallets that were on it.", review_before_running: "Read what this command downloads before running it, or run it in a sandbox.", no_red_flags: "No known red flags. Not proof it is safe." };
const TERMS = `${SERVICE} - Terms of Service (v${VERSION}, effective 2026-11-02)
Operator: DevX / Made by DevX (madebydevx.com), contact madebydevx@gmail.com.
1. Service. Heuristic static checks of public GitHub repositories and shell commands for signs of malware delivery. GET /api/basic?repo=... (free) scans the README. GET/POST /api/command (free) scans text you send. GET ${ROUTE}?repo=...[&repo=...] (paid, 1-${MAX} repos) and the paid MCP tool full_report (POST /mcp, x402 MCP transport) also scan package.json and its lifecycle scripts, install.sh, setup.sh, setup.py, requirements.txt, .vscode tasks/settings, Makefile, dev-container hooks, agent-instruction and MCP config files and the repo file tree, and read public GitHub repo/owner metadata. We never clone, build or execute code.
2. Price. 0.25 USDC (250000 atomic units) per paid call (HTTP /v1/check with 1-${MAX} repos, or one MCP full_report tool call), x402 v2 "exact" on Base (eip155:8453), paid to ${PAY_TO}, settled through ${FACILITATOR}. In the browser you sign an EIP-3009 USDC authorization for exactly that amount; gas is paid by the facilitator.
3. Not charged on error. Payment is settled only after the report is produced. Invalid input or an internal error returns an error and the authorization is not settled.
4. Refunds. If you were charged but got no report, email madebydevx@gmail.com with the Base tx hash within 30 days; verified cases are refunded in USDC on Base to the paying address.
5. Not a guarantee. Verdicts are heuristics over a few files. "no_red_flags" does not prove code is safe and "dangerous" does not prove intent. Run untrusted code in a sandbox without wallet keys or credentials.
6. Data. We do not store checked repos or commands beyond Cloudflare's standard request logs.
7. Changes. Material changes bump the version; the price in the live 402 response is authoritative.`;
function docs(origin) {
  const pay = { protocol: "x402", x402Version: 2, scheme: "exact", network: "eip155:8453", asset: USDC_BASE, amount: PRICE, price_usd: PRICE_USD, payTo: PAY_TO, facilitator: FACILITATOR };
  return { openapi: "3.1.0", info: { title: SERVICE, version: VERSION, description: DESC, termsOfService: origin + "/terms", contact: { name: "DevX", email: "madebydevx@gmail.com", url: "https://madebydevx.com" } }, servers: [{ url: origin }],
    paths: {
      "/api/basic": { get: { summary: "Free: scan a GitHub repo's README for malware-delivery install steps", parameters: [{ name: "repo", in: "query", required: true, schema: { type: "string" } }], responses: { 200: { description: "verdict + findings" } } } },
      "/api/command": { get: { summary: "Free: scan a shell command or text before running it", parameters: [{ name: "cmd", in: "query", required: true, schema: { type: "string" } }], responses: { 200: { description: "verdict + findings" } } }, post: { summary: "Free: same, JSON body {cmd}", requestBody: { content: { "application/json": { schema: { type: "object", properties: { cmd: { type: "string" } }, required: ["cmd"] } } } }, responses: { 200: { description: "verdict + findings" } } } },
      [ROUTE]: { get: { summary: "Paid (0.25 USDC, x402): full report on 1-3 repos (README, install/lifecycle scripts, package.json, VS Code/dev-container autorun, agent + MCP config files, committed binaries, GitHub metadata, risk score)", parameters: [{ name: "repo", in: "query", required: true, schema: { type: "string" }, description: "github.com/owner/repo; repeat for up to 3" }], "x-payment-info": pay, responses: { 200: { description: "reports" }, 402: { description: "Payment required (PAYMENT-REQUIRED header, x402 v2)" } } } } } };
}
const LLMS = (o) => `# ${SERVICE}
> Is this GitHub repo safe for my AI coding agent to run? Free README and command scan; paid full report 0.25 USDC via x402 on Base (HTTP route or paid MCP tool full_report).
- Guide: ${o}${GUIDE}
- Free API: GET /api/basic?repo=github.com/owner/repo
- Free command check: GET /api/command?cmd=... or POST {"cmd": "..."}
- Paid API (x402): GET /v1/check?repo=...&repo=... (1-3)
- MCP: ${o}/mcp (free tools check_repo, check_command, full_report_info; paid tool full_report, 0.25 USDC per call via the x402 MCP transport: unpaid call returns PaymentRequired)
- OpenAPI: /openapi.json
- Source: https://github.com/devx-agent/repo-run-check
- Related: https://crypto-link-check.nextill-pos.workers.dev/ and https://sweeper-check.nextill-pos.workers.dev/
`;
export default {
  async fetch(req, env) {
    ENV = env || {};
    const url = new URL(req.url), origin = url.origin, p = url.pathname;
    if (req.method === "OPTIONS") return new Response(null, { headers: { ...H, "access-control-allow-headers": "*", "access-control-allow-methods": "GET, HEAD, POST, OPTIONS" } });
    if (p === "/") return new Response(PAGE.replaceAll("__PAYTO__", PAY_TO), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300" } });
    if (p === GUIDE || p === GUIDE + "/") return new Response(EXPLAINER, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=3600" } });
    if (p === "/robots.txt") return T(`User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`);
    if (p === "/sitemap.xml") return T(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${origin}/</loc><lastmod>2026-10-30</lastmod></url><url><loc>${origin}${GUIDE}</loc><lastmod>2026-10-30</lastmod></url></urlset>`, "application/xml");
    if (p === "/llms.txt") return T(LLMS(origin));
    if (p === "/index.json") return J({ service: SERVICE, version: VERSION, by: "Made by DevX (madebydevx.com)", free: [origin + "/api/basic?repo=...", origin + "/api/command?cmd=..."], paid: origin + ROUTE + "?repo=...", price_usdc: PRICE_USD, mcp_paid_tool: "full_report", protocol: "x402 v2 exact, USDC on Base", payTo: PAY_TO, mcp: origin + "/mcp", docs: origin + "/openapi.json", terms: origin + "/terms", guide: origin + GUIDE });
    if (p === "/terms") return T(TERMS);
    if (p === "/openapi.json") return J(enhanceDocs(docs(origin), { ...{"priceUsd": "0.25", "guidance": "Call GET /v1/check?repo=github.com/<owner>/<repo> (repeat repo= for up to 3 repos) before an AI coding agent clones a repo and runs its install steps. Scans README, package.json lifecycle scripts and the files they run, install scripts, .vscode tasks/settings, Makefile, dev-container hooks, agent-instruction (AGENTS.md, CLAUDE.md, .cursorrules) and MCP config files, and committed binaries for download-and-execute one-liners, obfuscated payloads, malware domains, typosquatted dependencies and agent-targeted prompt injection, plus GitHub fake-star/new-owner signals. Returns verdict, risk score, findings with line evidence and next steps. Same report as the paid MCP tool full_report at POST /mcp. Free: GET /api/basic?repo=... (README only) and /api/command for a single shell command.", "tags": ["security", "supply-chain", "malware", "github", "ai-agents", "coding-agents", "prompt-injection"]}, example: EXAMPLE }));
    if (p === "/.well-known/x402") return J({ version: 1, resources: [origin + ROUTE], description: SERVICE });
    if (p === "/.well-known/x402.json") return J({ x402Version: 2, name: SERVICE, provider: "Made by DevX (madebydevx.com)", resources: [{ url: origin + ROUTE, method: "GET", description: DESC, accepts: [requirements()] }] });
    if (p === "/mcp") return mcp(req, origin, ENV);
    if (p === "/.well-known/mcp.json" || p === "/.well-known/mcp/server-card.json") return J({ name: "devx-repo-run-check", description: "Check a GitHub repo or shell command for malware-delivery tricks before an AI agent runs it", url: origin + "/mcp", transport: "streamable-http", tools: MCP_TOOLS, paid_tools: { full_report: { price_usdc: PRICE_USD, protocol: "x402 v2 (MCP transport)", x402: requirements() } }, provider: "Made by DevX", repository: "https://github.com/devx-agent/repo-run-check" });
    if (p === "/7541a0b5b97746152a11eba4520fb3fb.txt") return T("7541a0b5b97746152a11eba4520fb3fb");
    if (p === "/.well-known/402index-verify.txt") return T("02de5dbaf2c08ed6fa1908bb92cbbc3a6dc7cc9096aef355438ede7d68016e49");
    if (p === "/health") return J({ ok: true, version: VERSION, facilitator: facilitatorConfig(ENV).name });
    if (p === "/api/basic") {
      const r = await basic(url.searchParams.get("repo") || ""); if (r.error) return J(r, 400);
      r.full_report = origin + ROUTE + "?repo=" + encodeURIComponent(r.repo); r.full_report_price_usdc = PRICE_USD; return J(r);
    }
    if (p === "/api/command") {
      let cmd = url.searchParams.get("cmd");
      if (req.method === "POST") { try { cmd = (await req.json()).cmd; } catch { return J({ error: "JSON body {cmd} required" }, 400); } }
      const r = commandCheck(cmd); return J(r, r.error ? 400 : 200);
    }
    if (p !== ROUTE) return J({ error: "not found", see: origin + "/index.json" }, 404);
    if (!["GET", "HEAD", "POST"].includes(req.method)) return J({ error: "use GET (or POST JSON)" }, 405);
    { const pe = await postToParams(req, url); if (pe && pe.error) return J({ error: pe.error }, 400); }
    const pr = paymentRequired(origin);
    const parsed = parseRepos(url.searchParams);
    const sig = req.headers.get("PAYMENT-SIGNATURE") || req.headers.get("X-PAYMENT");
    console.log(JSON.stringify({ ev: "paid_route", m: req.method, pay: sig ? (req.headers.get("X-PAYMENT") ? "x-payment" : "payment-signature") : null, ua: uaFamily(req.headers.get("user-agent")) }));
    if (!sig) return J(v1Body(pr), 402, { "PAYMENT-REQUIRED": b64(pr) });
    if (parsed.error) return J({ error: parsed.error + " (you were not charged)" }, 400);
    let payload; try { payload = unb64(sig); } catch { return J({ ...pr, error: "malformed PAYMENT-SIGNATURE" }, 400, { "PAYMENT-REQUIRED": b64(pr) }); }
    const reqs = requirements(), isV1 = payload.x402Version === 1 || (!payload.accepted && !!payload.network);
    const acc = isV1 ? { network: (payload.network === "base" || payload.network === "eip155:8453") ? reqs.network : payload.network, payTo: payload.payload?.authorization?.to, amount: String(payload.payload?.authorization?.value ?? ""), asset: USDC_BASE } : (payload.accepted || {});
    const fReq = isV1 ? v1Requirements(pr.resource.url) : reqs, fPay = isV1 ? { ...payload, x402Version: 1, scheme: "exact", network: "base" } : payload, fv = isV1 ? 1 : 2;
    console.log(JSON.stringify({ ev: "pay_attempt", v: fv, ua: uaFamily(req.headers.get("user-agent")) }));
    if ((!isV1 && payload.x402Version !== 2) || acc.network !== reqs.network || acc.payTo?.toLowerCase() !== PAY_TO.toLowerCase() || acc.amount !== reqs.amount || acc.asset?.toLowerCase() !== USDC_BASE.toLowerCase())
      return J({ ...(isV1 ? v1Body(pr) : pr), error: "payment does not match requirements (exact, Base USDC " + PRICE + " atomic to " + PAY_TO + ")" }, 402, { "PAYMENT-REQUIRED": b64(pr) });
    const v = await facil("verify", { x402Version: fv, paymentPayload: fPay, paymentRequirements: fReq });
    if (!v.isValid) { console.log(JSON.stringify({ ev: "pay_invalid", v: fv, r: v.invalidReason || "unknown" })); return J({ ...(isV1 ? v1Body(pr) : pr), error: "payment invalid: " + (v.invalidReason || v.errorReason || v.errorMessage || v.message || v.error || "unknown") + " (not charged)" }, 402, { "PAYMENT-REQUIRED": b64(pr) }); }
    const budget = [24, 6, 0][parsed.list.length - 1] ?? 0;
    let reports; try { reports = await Promise.all(parsed.list.map((r) => deepReport(r, { budget }))); } catch (e) { return J({ error: "internal error, you were not charged" }, 500); }
    const failed = reports.filter((r) => r.error);
    if (failed.length) return J({ error: "could not check " + failed.map((r) => (r.repo || r.input) + ": " + r.error).join("; ") + " (payment not settled, you were not charged; retry without it)" }, 502);
    const s = await facil("settle", { x402Version: fv, paymentPayload: fPay, paymentRequirements: fReq });
    const PRH = b64(isV1 ? { success: !!s.success, transaction: s.transaction || "", network: "base", payer: s.payer || payload.payload?.authorization?.from || "" } : s);
    console.log(JSON.stringify({ ev: s.success ? "paid" : "settle_fail", v: fv }));
    if (!s.success) return J({ ...pr, error: "settlement failed: " + (s.errorReason || "unknown") + " (report withheld, not charged)" }, 402, { "PAYMENT-REQUIRED": b64(pr), "PAYMENT-RESPONSE": PRH, "X-PAYMENT-RESPONSE": PRH });
    return J({ service: SERVICE, version: VERSION, count: reports.length, reports, payment: { tx: s.transaction || null, network: s.network || "eip155:8453", x402Version: fv } }, 200, { "PAYMENT-RESPONSE": PRH, "X-PAYMENT-RESPONSE": PRH });
  },
};
