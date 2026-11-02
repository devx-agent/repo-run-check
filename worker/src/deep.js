// Paid "full report": the free README scan + install scripts + GitHub signals (net.js full)
// plus a deep pass over the repo tree: agent-instruction files, MCP configs, autorun/devcontainer hooks,
// scripts referenced by npm lifecycle hooks, committed executables/archives, and an optional command check.
import { scanText, verdict, ADVICE, parseRepo } from "./core.js";
import { full } from "./net.js";
const UA = { "user-agent": "devx-repo-run-check/1.2 (+https://repo-run-check.nextill-pos.workers.dev)" };

async function raw(slug, path) {
  try {
    const r = await fetch(`https://raw.githubusercontent.com/${slug}/HEAD/${path.split("/").map(encodeURIComponent).join("/")}`, { headers: UA, cf: { cacheTtl: 300 } });
    if (r.status !== 200) { await r.body?.cancel(); return null; }
    const t = await r.text(); return t.slice(0, 50000); // keep CPU low (Workers free plan)
  } catch { return null; }
}
const MAX_TREE = 1200000;
async function treeJson(slug, recursive) {
  const r = await fetch(`https://api.github.com/repos/${slug}/git/trees/HEAD${recursive ? "?recursive=1" : ""}`, { headers: { ...UA, accept: "application/vnd.github+json" } });
  if (r.status !== 200) { await r.body?.cancel(); return { status: r.status }; }
  const cl = +(r.headers.get("content-length") || 0); if (cl > MAX_TREE) { await r.body?.cancel(); return { status: 413 }; }
  const rd = r.body.getReader(), parts = []; let n = 0;
  while (true) { const { done, value } = await rd.read(); if (done) break; n += value.length; if (n > MAX_TREE) { await rd.cancel(); return { status: 413 }; } parts.push(value); } // huge monorepo: parsing would blow the CPU budget
  const buf = new Uint8Array(n); let o = 0; for (const c of parts) { buf.set(c, o); o += c.length; } const t = new TextDecoder().decode(buf);
  const j = JSON.parse(t); return { status: 200, files: (j.tree || []).filter((x) => x.type === "blob").map((x) => ({ path: x.path, size: x.size || 0 })), truncated: !!j.truncated };
}
async function tree(slug) {
  try { const x = await treeJson(slug, true); if (x.status !== 413) return x; const root = await treeJson(slug, false); return root.status === 200 ? { ...root, truncated: true, rootOnly: true } : root; }
  catch { return { status: 0 }; }
}

const AGENT_FILES = /^((?:[^/]+\/){0,2}(?:AGENTS|CLAUDE|GEMINI)\.md|\.cursorrules|\.windsurfrules|\.clinerules|\.github\/copilot-instructions\.md|\.cursor\/rules\/.+|\.clinerules\/.+|\.claude\/(settings(\.local)?\.json|commands\/.+|agents\/.+)|\.github\/(prompts|instructions)\/.+)$/i;
const MCP_FILES = /^(\.mcp\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json|mcp\.json|\.gemini\/settings\.json)$/i;
const AUTORUN_FILES = /^(\.vscode\/settings\.json|\.vscode\/launch\.json|\.devcontainer\/devcontainer\.json|\.devcontainer\.json|pyproject\.toml|setup\.cfg|build\.rs|\.husky\/[^/]+|lefthook\.yml|\.pre-commit-config\.yaml|Dockerfile|docker-compose\.ya?ml|compose\.ya?ml|Gemfile|Rakefile|justfile|Taskfile\.ya?ml|\.npmrc|\.yarnrc\.yml)$/i;
const ROOT_SCRIPTS = /^[^/]+\.(sh|bash|ps1|bat|cmd|command|vbs)$/i;
const WORKFLOWS = /^\.github\/workflows\/[^/]+\.ya?ml$/i;
const EXEC_EXT = /\.(exe|dll|scr|msi|com|pif|lnk|vbs|vbe|hta|jar|apk|dmg|pkg|deb|rpm|appimage|so|dylib|node|bin)$/i;
const ARCHIVE_EXT = /\.(zip|rar|7z|tar|tgz|gz|xz|iso|cab)$/i;
const PRI = (p) => AGENT_FILES.test(p) ? 0 : MCP_FILES.test(p) ? 1 : AUTORUN_FILES.test(p) ? 2 : ROOT_SCRIPTS.test(p) ? 3 : WORKFLOWS.test(p) ? 4 : 9;
const FALLBACK = [".vscode/settings.json", "AGENTS.md", "CLAUDE.md", ".cursorrules", ".github/copilot-instructions.md", ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".devcontainer/devcontainer.json", ".vscode/launch.json", "pyproject.toml", "build.rs", ".claude/settings.json", "setup.cfg"];

// local files run by npm lifecycle scripts, e.g. "postinstall": "node scripts/setup.js"
function lifecycleTargets(pkgText) {
  let pj; try { pj = JSON.parse(pkgText); } catch { return []; }
  const s = pj.scripts || {}, out = [];
  for (const k of ["preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare"]) {
    const v = String(s[k] || ""); let m; const re = /(?:node|sh|bash|python3?|bun|deno run|tsx|ts-node|pwsh|powershell(?:\.exe)?\s+-file)\s+["']?(\.?\.?\/?[\w./-]+\.(?:c?js|mjs|ts|sh|py|ps1))/gi;
    while ((m = re.exec(v))) out.push(m[1].replace(/^\.\//, ""));
  }
  return [...new Set(out)].filter((p) => !p.startsWith("../") && !p.includes("node_modules"));
}

function specific(path, text) {
  const out = [], add = (level, code, message, evidence) => out.push({ level, code, message, file: path, evidence: evidence ? String(evidence).slice(0, 220) : undefined });
  let j = null; if (/\.json$/i.test(path)) { try { j = JSON.parse(text.replace(/^\s*\/\/.*$/gm, "")); } catch {} }
  if (MCP_FILES.test(path) && j) {
    const servers = j.mcpServers || j.servers || {};
    for (const [n, c] of Object.entries(servers)) { const cmd = [c.command, ...(c.args || [])].filter(Boolean).join(" ") || c.url || "";
      add("warn", "repo_ships_mcp_server", `Repo ships an MCP server config "${n}" that an AI agent/IDE may start automatically when the folder is opened. Check what it runs before approving it.`, cmd);
      out.push(...scanText(cmd, path)); }
  }
  if (/^\.claude\/settings/i.test(path) && j) {
    if (j.hooks) add("warn", "claude_hooks", "Repo defines Claude Code hooks: shell commands that run automatically during agent sessions.", JSON.stringify(j.hooks));
    const allow = (j.permissions && j.permissions.allow) || []; if (allow.some((a) => /^Bash\((\*|curl|wget|sh|bash)/i.test(a) || a === "Bash")) add("warn", "broad_agent_permissions", "Repo pre-approves broad shell permissions for the coding agent.", allow.join(", "));
  }
  if (/\.vscode\/settings\.json$/i.test(path) && /"task\.allowAutomaticTasks"\s*:\s*"on"/i.test(text)) add("danger", "vscode_auto_tasks_enabled", "Repo turns on automatic VS Code tasks (task.allowAutomaticTasks = on) so tasks run on folder open without asking.", "task.allowAutomaticTasks: on");
  if (/devcontainer\.json$/i.test(path)) { const m = text.match(/"(initializeCommand|onCreateCommand|postCreateCommand|postStartCommand|postAttachCommand|updateContentCommand)"\s*:\s*("[^"]*"|\[[^\]]*\])/g) || [];
    if (m.length) add(/initializeCommand/.test(m.join(" ")) ? "warn" : "info", "devcontainer_hooks", "Dev container runs commands automatically (initializeCommand runs on YOUR host, not in the container).", m.join("; ")); }
  if (/^build\.rs$/i.test(path) && /(Command::new|reqwest|ureq|std::net|TcpStream|download)/.test(text)) add("warn", "build_rs_side_effects", "build.rs spawns processes or touches the network during `cargo build`.");
  if (/pyproject\.toml$/i.test(path) && /\[tool\.(hatch\.build\.hooks|setuptools\.cmdclass)|build-backend\s*=\s*"(?!setuptools|hatchling|poetry|flit|pdm|maturin|scikit)/i.test(text)) add("info", "custom_python_build", "Custom Python build backend or build hook: code runs during pip install.");
  if (WORKFLOWS.test(path) && /pull_request_target/.test(text) && /actions\/checkout[\s\S]{0,300}github\.event\.pull_request\.head/.test(text)) add("warn", "pwn_request_workflow", "Workflow checks out untrusted PR code under pull_request_target (secrets exposure risk).");
  return out;
}

const scoreOf = (f) => Math.min(100, f.filter((x) => x.level === "danger").length * 40 + f.filter((x) => x.level === "warn").length * 12);
function nextSteps(v, f) {
  const s = [];
  if (v === "dangerous") s.push("Do not install or run anything from this repo. Do not open it in VS Code/Cursor with workspace trust enabled.", "If any step already ran: disconnect the machine, check startup items/scheduled tasks/launch agents, and rotate every API key, SSH key, token and wallet that was on it.");
  if (f.some((x) => /agent_targeted|repo_ships_mcp|claude_hooks|broad_agent/.test(x.code))) s.push("Open this repo with your AI agent in a restricted mode: do not auto-approve shell commands or MCP servers it suggests.");
  if (f.some((x) => /install_script|lifecycle|setup_py|custom_python_build|build_rs/.test(x.code))) s.push("Install with scripts disabled first (npm ci --ignore-scripts / pip download + inspect) and read the flagged scripts.");
  if (f.some((x) => /vscode|devcontainer/.test(x.code))) s.push("Open the folder in Restricted Mode (workspace trust off) so autorun tasks and dev-container hooks cannot fire.");
  if (f.some((x) => /committed_executable|committed_archive/.test(x.code))) s.push("Do not run committed binaries or extract committed archives; build from source or use signed releases.");
  if (f.some((x) => /stars|owner|never_updated|readme_only|brand_like/.test(x.code))) s.push("Popularity signals look manufactured; prefer the official project (check the vendor's website for the real GitHub org).");
  if (v !== "dangerous") s.push(v === "no_red_flags" ? "No red flags found in the files checked; still run untrusted code in a sandbox/VM without wallet keys or cloud credentials." : "Review the flagged lines above before letting an agent run the install steps; run them in a sandbox/VM without secrets.");
  return s;
}

/** opts: { budget: max extra file fetches, command?: string } */
export async function deepReport(input, opts = {}) {
  const budget = Math.max(0, Math.min(24, opts.budget ?? 16));
  const [base, tr] = await Promise.all([full(input), (async () => { const pr = parseRepo(input); return budget && !pr.error ? tree(pr.slug) : { status: -1 }; })()]);
  if (base.error) return base;
  const slug = base.repo, findings = [...base.findings], extra = [];
  const deep = { tree: tr.status === 200 ? "ok" : tr.status === -1 ? "skipped (multi-repo call budget)" : (tr.status === 403 || tr.status === 429 ? "GitHub API rate limit; probed common agent/autorun files instead" : "unavailable; probed common agent/autorun files instead") };
  let candidates = [];
  if (tr.status === 200) {
    const files = tr.files; deep.total_files = tr.rootOnly ? undefined : files.length; deep.tree_truncated = tr.truncated; if (tr.rootOnly) deep.tree = "large repo: root listing + common agent/autorun paths";
    const execs = files.filter((x) => EXEC_EXT.test(x.path) && !/(^|\/)(node_modules|vendor|test|tests|fixtures?|examples?)\//i.test(x.path)).slice(0, 15);
    const archives = files.filter((x) => ARCHIVE_EXT.test(x.path) && !/(^|\/)(test|tests|fixtures?|testdata)\//i.test(x.path)).slice(0, 15);
    for (const x of execs) findings.push({ level: "warn", code: "committed_executable", message: `Repo contains a compiled executable/binary (${x.path}, ${Math.round(x.size / 1024)} KB). Malware repos often ship the payload this way.`, file: x.path });
    for (const x of archives) findings.push({ level: /\.(zip|rar|7z)$/i.test(x.path) ? "warn" : "info", code: "committed_archive", message: `Repo contains an archive (${x.path}, ${Math.round(x.size / 1024)} KB) that antivirus may not inspect.`, file: x.path });
    deep.suspicious_files = [...execs, ...archives].map((x) => x.path);
    deep.agent_instruction_files = files.filter((x) => AGENT_FILES.test(x.path)).map((x) => x.path).slice(0, 30);
    deep.mcp_configs = files.filter((x) => MCP_FILES.test(x.path)).map((x) => x.path);
    let wf = 0; candidates = files.filter((x) => PRI(x.path) < 9 && x.size < 200000 && !base.files_checked.includes(x.path)).sort((a, b) => PRI(a.path) - PRI(b.path)).map((x) => x.path).filter((p) => !WORKFLOWS.test(p) || wf++ < 3);
  } else candidates = FALLBACK.filter((p) => !base.files_checked.includes(p));
  if (budget && base.files_checked.includes("package.json")) {
    const pkg = await raw(slug, "package.json"); if (pkg) for (const t of lifecycleTargets(pkg)) if (!candidates.includes(t)) candidates.unshift(t);
  }
  if (tr.rootOnly) for (const p of FALLBACK) if (!candidates.includes(p) && !base.files_checked.includes(p)) candidates.push(p);
  const pick = candidates.slice(0, budget);
  const texts = await Promise.all(pick.map((p) => raw(slug, p)));
  let scanned = 0; // cap total extra bytes scanned (~0.1 ms CPU per KB)
  pick.forEach((p, i) => { const t = texts[i]; if (t == null || scanned > 160000) return; scanned += t.length; extra.push(p); findings.push(...scanText(t, p), ...specific(p, t)); });
  deep.extra_files_checked = extra; deep.extra_files_skipped = Math.max(0, candidates.length - pick.length);
  let command_check;
  if (opts.command && String(opts.command).trim()) { const c = String(opts.command).slice(0, 20000), cf = scanText(c, "command"); command_check = { command: c.slice(0, 500), verdict: verdict(cf), findings: cf }; findings.push(...cf); }
  const v = verdict(findings);
  const counts = { danger: findings.filter((x) => x.level === "danger").length, warn: findings.filter((x) => x.level === "warn").length, info: findings.filter((x) => x.level === "info").length };
  const byFile = {}; for (const f of findings) if (f.level !== "info") byFile[f.file] = (byFile[f.file] || 0) + 1;
  return { input: base.input, repo: slug, url: base.url, tier: "paid full report", verdict: v, risk_score: scoreOf(findings), advice: ADVICE[v], counts, flagged_files: byFile, next_steps: nextSteps(v, findings),
    files_checked: [...base.files_checked, ...extra], findings, install_commands: base.install_commands, repo_meta: base.repo_meta, deep, ...(command_check ? { command_check } : {}), checked_at: base.checked_at };
}

export function reportText(r) {
  const lines = r.findings.filter((f) => f.level !== "info").slice(0, 40).map((f) => `- [${f.level}] ${f.message}${f.file ? " (" + f.file + (f.line ? ":" + f.line : "") + ")" : ""}${f.evidence ? "\n    " + f.evidence : ""}`);
  const m = r.repo_meta || {};
  return [`Full report: ${r.repo}  verdict=${r.verdict}  risk_score=${r.risk_score}/100  (${r.counts.danger} danger, ${r.counts.warn} warn, ${r.counts.info} info)`, r.advice, "",
    `Files checked (${r.files_checked.length}): ${r.files_checked.join(", ")}`,
    m.stars !== undefined ? `GitHub: ${m.stars} stars, ${m.forks} forks, ${m.watchers} watchers, repo ${m.age_days} days old, owner account ${m.owner_age_days ?? "?"} days old${m.license ? ", license " + m.license : ""}` : `GitHub metadata: ${m.unavailable || "n/a"}`,
    r.deep.suspicious_files && r.deep.suspicious_files.length ? `Committed binaries/archives: ${r.deep.suspicious_files.join(", ")}` : "", r.command_check ? `Your command: ${r.command_check.verdict}` : "",
    "", "Findings:", lines.join("\n") || "- none above info level", "", "Next steps:", ...r.next_steps.map((s) => "- " + s)].filter((x, i, a) => x !== "" || a[i - 1] !== "").join("\n");
}
