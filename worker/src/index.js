import { parseRepo, scanText, verdict, ADVICE } from "./core.js";
import { basic, full } from "./net.js";
import PAGE from "./page.html";
import EXPLAINER from "./explainer.html";
import { mcp } from "./mcp.js";

const VERSION = "1.0.0";
const SERVICE = "DevX Repo Run Check";
const PAY_TO = "0xB3cDDccEe6B150c8efFD55B961afc0Ecefe7f247";
const FACILITATOR = "https://facilitator.payai.network";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PRICE = "5000"; // 0.005 USDC per report (1-3 repos)
const ROUTE = "/v1/check";
const MAX = 3;
const GUIDE = "/is-this-github-repo-safe-to-run";
const DESC = "Before an AI coding agent (or you) runs a GitHub repo's install steps: scans README, package.json install scripts, install.sh/setup.py, .vscode/tasks.json and Makefile for download-and-execute one-liners (iwr|iex, curl|sh), obfuscated or base64 payloads, known malware domains, typosquatted crypto dependencies, agent-targeted prompt injection and password-protected archives, plus GitHub signals of fake stars and new owner accounts. 1-3 repos per call.";
const enc = new TextEncoder();
const b64 = (o) => btoa(String.fromCharCode(...enc.encode(JSON.stringify(o))));
const unb64 = (s) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0))));
const EX_REPO = "github.com/SolanaUpdateTools/solana-starter-kit";
const EXAMPLE = { repo: "SolanaUpdateTools/solana-starter-kit", verdict: "dangerous", findings: [{ level: "danger", code: "download_and_execute_powershell" }, { level: "danger", code: "obfuscated_url" }, { level: "warn", code: "never_updated" }], repo_meta: { stars: 287, age_days: 357 } };

function requirements() { return { scheme: "exact", network: "eip155:8453", amount: PRICE, asset: USDC_BASE, payTo: PAY_TO, maxTimeoutSeconds: 120, extra: { name: "USD Coin", version: "2" } }; }
function advertised(resUrl) { return { ...requirements(), maxAmountRequired: PRICE, resource: resUrl, description: DESC, mimeType: "application/json" }; }
function paymentRequired(origin, error) {
  const resUrl = origin + ROUTE;
  return { x402Version: 2, error: error || "PAYMENT-SIGNATURE header is required",
    resource: { url: resUrl, description: DESC, mimeType: "application/json", serviceName: SERVICE, tags: ["security", "ai-agents", "supply-chain", "malware", "github", "x402"] },
    accepts: [advertised(resUrl)],
    extensions: { bazaar: { info: { input: { type: "http", method: "GET", queryParams: { repo: EX_REPO } }, output: { type: "json", example: EXAMPLE } },
      schema: { $schema: "https://json-schema.org/draft/2020-12/schema", type: "object", properties: { input: { type: "object", properties: { type: { type: "string", const: "http" }, method: { type: "string", enum: ["GET"] }, queryParams: { type: "object", properties: { repo: { type: "string", description: "github.com/owner/repo; repeat for up to 3" } }, required: ["repo"] } }, required: ["type", "method"] }, output: { type: "object" } }, required: ["input"] } } } };
}
const H = { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-expose-headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE" };
const J = (o, status = 200, h = {}) => new Response(JSON.stringify(o, null, 2), { status, headers: { ...H, ...h } });
const T = (s, ct = "text/plain; charset=utf-8") => new Response(s, { headers: { "content-type": ct, "access-control-allow-origin": "*" } });
async function facil(op, body) { const r = await fetch(`${FACILITATOR}/${op}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }); try { return await r.json(); } catch { return {}; } }
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
const TERMS = `${SERVICE} - Terms of Service (v${VERSION}, effective 2026-10-30)
Operator: DevX / Made by DevX (madebydevx.com), contact madebydevx@gmail.com.
1. Service. Heuristic static checks of public GitHub repositories and shell commands for signs of malware delivery. GET /api/basic?repo=... (free) scans the README. GET/POST /api/command (free) scans text you send. GET ${ROUTE}?repo=...[&repo=...] (paid, 1-${MAX} repos) also scans package.json, install.sh, setup.sh, setup.py, requirements.txt, .vscode/tasks.json and Makefile, and reads public GitHub repo/owner metadata. We never clone, build or execute code.
2. Price. 0.005 USDC per paid call, x402 v2 "exact" on Base (eip155:8453), paid to ${PAY_TO}, settled through ${FACILITATOR}. In the browser you sign an EIP-3009 USDC authorization for exactly that amount; gas is paid by the facilitator.
3. Not charged on error. Payment is settled only after the report is produced. Invalid input or an internal error returns an error and the authorization is not settled.
4. Refunds. If you were charged but got no report, email madebydevx@gmail.com with the Base tx hash within 30 days; verified cases are refunded in USDC on Base to the paying address.
5. Not a guarantee. Verdicts are heuristics over a few files. "no_red_flags" does not prove code is safe and "dangerous" does not prove intent. Run untrusted code in a sandbox without wallet keys or credentials.
6. Data. We do not store checked repos or commands beyond Cloudflare's standard request logs.
7. Changes. Material changes bump the version; the price in the live 402 response is authoritative.`;
function docs(origin) {
  const pay = { protocol: "x402", x402Version: 2, scheme: "exact", network: "eip155:8453", asset: USDC_BASE, amount: PRICE, price_usd: 0.005, payTo: PAY_TO, facilitator: FACILITATOR };
  return { openapi: "3.1.0", info: { title: SERVICE, version: VERSION, description: DESC, termsOfService: origin + "/terms", contact: { name: "DevX", email: "madebydevx@gmail.com", url: "https://madebydevx.com" } }, servers: [{ url: origin }],
    paths: {
      "/api/basic": { get: { summary: "Free: scan a GitHub repo's README for malware-delivery install steps", parameters: [{ name: "repo", in: "query", required: true, schema: { type: "string" } }], responses: { 200: { description: "verdict + findings" } } } },
      "/api/command": { get: { summary: "Free: scan a shell command or text before running it", parameters: [{ name: "cmd", in: "query", required: true, schema: { type: "string" } }], responses: { 200: { description: "verdict + findings" } } }, post: { summary: "Free: same, JSON body {cmd}", requestBody: { content: { "application/json": { schema: { type: "object", properties: { cmd: { type: "string" } }, required: ["cmd"] } } } }, responses: { 200: { description: "verdict + findings" } } } },
      [ROUTE]: { get: { summary: "Paid (0.005 USDC, x402): full check of 1-3 repos (README, install scripts, package.json, VS Code tasks, GitHub metadata)", parameters: [{ name: "repo", in: "query", required: true, schema: { type: "string" }, description: "github.com/owner/repo; repeat for up to 3" }], "x-payment-info": pay, responses: { 200: { description: "reports" }, 402: { description: "Payment required (PAYMENT-REQUIRED header, x402 v2)" } } } } } };
}
const LLMS = (o) => `# ${SERVICE}
> Is this GitHub repo safe for my AI coding agent to run? Free README and command scan; paid full check 0.005 USDC via x402 on Base.
- Guide: ${o}${GUIDE}
- Free API: GET /api/basic?repo=github.com/owner/repo
- Free command check: GET /api/command?cmd=... or POST {"cmd": "..."}
- Paid API (x402): GET /v1/check?repo=...&repo=... (1-3)
- MCP: ${o}/mcp (tools check_repo, check_command, full_report_info)
- OpenAPI: /openapi.json
- Source: https://github.com/devx-agent/repo-run-check
- Related: https://crypto-link-check.nextill-pos.workers.dev/ and https://sweeper-check.nextill-pos.workers.dev/
`;
export default {
  async fetch(req) {
    const url = new URL(req.url), origin = url.origin, p = url.pathname;
    if (req.method === "OPTIONS") return new Response(null, { headers: { ...H, "access-control-allow-headers": "*", "access-control-allow-methods": "GET, HEAD, POST, OPTIONS" } });
    if (p === "/") return new Response(PAGE.replaceAll("__PAYTO__", PAY_TO), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300" } });
    if (p === GUIDE || p === GUIDE + "/") return new Response(EXPLAINER, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=3600" } });
    if (p === "/robots.txt") return T(`User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`);
    if (p === "/sitemap.xml") return T(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${origin}/</loc><lastmod>2026-10-30</lastmod></url><url><loc>${origin}${GUIDE}</loc><lastmod>2026-10-30</lastmod></url></urlset>`, "application/xml");
    if (p === "/llms.txt") return T(LLMS(origin));
    if (p === "/index.json") return J({ service: SERVICE, version: VERSION, by: "Made by DevX (madebydevx.com)", free: [origin + "/api/basic?repo=...", origin + "/api/command?cmd=..."], paid: origin + ROUTE + "?repo=...", price_usdc: 0.005, protocol: "x402 v2 exact, USDC on Base", payTo: PAY_TO, mcp: origin + "/mcp", docs: origin + "/openapi.json", terms: origin + "/terms", guide: origin + GUIDE });
    if (p === "/terms") return T(TERMS);
    if (p === "/openapi.json") return J(docs(origin));
    if (p === "/.well-known/x402") return J({ version: 1, resources: [origin + ROUTE], description: SERVICE });
    if (p === "/.well-known/x402.json") return J({ x402Version: 2, name: SERVICE, provider: "Made by DevX (madebydevx.com)", resources: [{ url: origin + ROUTE, method: "GET", description: DESC, accepts: [requirements()] }] });
    if (p === "/mcp") return mcp(req, origin);
    if (p === "/.well-known/mcp.json" || p === "/.well-known/mcp/server-card.json") return J({ name: "devx-repo-run-check", description: "Check a GitHub repo or shell command for malware-delivery tricks before an AI agent runs it", url: origin + "/mcp", transport: "streamable-http", tools: ["check_repo", "check_command", "full_report_info"], provider: "Made by DevX", repository: "https://github.com/devx-agent/repo-run-check" });
    if (p === "/7541a0b5b97746152a11eba4520fb3fb.txt") return T("7541a0b5b97746152a11eba4520fb3fb");
    if (p === "/health") return J({ ok: true, version: VERSION });
    if (p === "/api/basic") {
      const r = await basic(url.searchParams.get("repo") || ""); if (r.error) return J(r, 400);
      r.full_report = origin + ROUTE + "?repo=" + encodeURIComponent(r.repo); r.full_report_price_usdc = 0.005; return J(r);
    }
    if (p === "/api/command") {
      let cmd = url.searchParams.get("cmd");
      if (req.method === "POST") { try { cmd = (await req.json()).cmd; } catch { return J({ error: "JSON body {cmd} required" }, 400); } }
      const r = commandCheck(cmd); return J(r, r.error ? 400 : 200);
    }
    if (p !== ROUTE) return J({ error: "not found", see: origin + "/index.json" }, 404);
    if (req.method !== "GET" && req.method !== "HEAD") return J({ error: "use GET" }, 405);
    const pr = paymentRequired(origin);
    const parsed = parseRepos(url.searchParams);
    const sig = req.headers.get("PAYMENT-SIGNATURE") || req.headers.get("X-PAYMENT");
    if (!sig) return J(pr, 402, { "PAYMENT-REQUIRED": b64(pr) });
    if (parsed.error) return J({ error: parsed.error + " (you were not charged)" }, 400);
    let payload; try { payload = unb64(sig); } catch { return J({ ...pr, error: "malformed PAYMENT-SIGNATURE" }, 400, { "PAYMENT-REQUIRED": b64(pr) }); }
    const reqs = requirements(), acc = payload.accepted || {};
    if (payload.x402Version !== 2 || acc.network !== reqs.network || acc.payTo?.toLowerCase() !== PAY_TO.toLowerCase() || acc.amount !== reqs.amount || acc.asset?.toLowerCase() !== USDC_BASE.toLowerCase())
      return J({ ...pr, error: "payment does not match requirements (x402 v2, exact, eip155:8453 USDC 5000)" }, 402, { "PAYMENT-REQUIRED": b64(pr) });
    const v = await facil("verify", { x402Version: 2, paymentPayload: payload, paymentRequirements: reqs });
    if (!v.isValid) return J({ ...pr, error: "payment invalid: " + (v.invalidReason || "unknown") }, 402, { "PAYMENT-REQUIRED": b64(pr) });
    let reports; try { reports = await Promise.all(parsed.list.map(full)); } catch (e) { return J({ error: "internal error, you were not charged" }, 500); }
    if (reports.every((r) => r.error)) return J({ error: "no repo could be checked (you were not charged)", reports }, 502);
    const s = await facil("settle", { x402Version: 2, paymentPayload: payload, paymentRequirements: reqs });
    if (!s.success) return J({ ...pr, error: "settlement failed: " + (s.errorReason || "unknown") + " (report withheld, not charged)" }, 402, { "PAYMENT-REQUIRED": b64(pr), "PAYMENT-RESPONSE": b64(s) });
    return J({ service: SERVICE, version: VERSION, count: reports.length, reports, payment: { tx: s.transaction || null, network: s.network || "eip155:8453" } }, 200, { "PAYMENT-RESPONSE": b64(s) });
  },
};
