import { parseRepo, scanText, scanPackageJson, scanSetupPy, verdict, ADVICE, commands } from "./core.js";
const UA = { "user-agent": "devx-repo-run-check/1.0 (+https://repo-run-check.nextill-pos.workers.dev)" };
async function raw(o, r, path) {
  try {
    const res = await fetch(`https://raw.githubusercontent.com/${o}/${r}/HEAD/${path}`, { headers: UA, redirect: "follow", cf: { cacheTtl: 300 } });
    if (res.status !== 200) { await res.body?.cancel(); return { status: res.status }; }
    const reader = res.body.getReader(); let size = 0, chunks = [];
    while (true) { const { done, value } = await reader.read(); if (done) break; size += value.length; chunks.push(value); if (size > 300000) { await reader.cancel(); break; } }
    const buf = new Uint8Array(Math.min(size, 300000)); let off = 0; for (const c of chunks) { const n = Math.min(c.length, buf.length - off); buf.set(c.subarray(0, n), off); off += n; if (off >= buf.length) break; }
    return { status: 200, text: new TextDecoder().decode(buf), truncated: size > 300000 };
  } catch (e) { return { status: 0, error: String(e).slice(0, 80) }; }
}
async function readme(o, r) {
  for (const n of ["README.md", "readme.md"]) { const x = await raw(o, r, n); if (x.status === 200) return { name: n, ...x }; if (x.status === 404) continue; return { name: n, ...x }; }
  return { status: 404 };
}
async function gh(path) {
  try { const r = await fetch("https://api.github.com" + path, { headers: { ...UA, accept: "application/vnd.github+json" } }); if (r.status !== 200) return { status: r.status }; return { status: 200, json: await r.json() }; }
  catch { return { status: 0 }; }
}
const days = (iso) => iso ? Math.floor((Date.now() - Date.parse(iso)) / 864e5) : null;

export async function basic(input) {
  const p = parseRepo(input); if (p.error) return p;
  const rd = await readme(p.owner, p.repo);
  if (rd.status !== 200) return { error: rd.status === 404 ? "repo or README not found (private, renamed or deleted?)" : "could not fetch README from GitHub, try again", repo: p.slug };
  const findings = scanText(rd.text, rd.name);
  const v = verdict(findings);
  return { repo: p.slug, url: p.url, verdict: v, advice: ADVICE[v], files_checked: [rd.name], findings, install_commands: commands(rd.text), tier: "free (README only)" };
}

export async function full(input) {
  const p = parseRepo(input); if (p.error) return { input, error: p.error };
  const files = ["package.json", "install.sh", "setup.sh", "setup.py", "requirements.txt", ".vscode/tasks.json", "Makefile"];
  const [rd, meta, ...rest] = await Promise.all([readme(p.owner, p.repo), gh(`/repos/${p.owner}/${p.repo}`), ...files.map((f) => raw(p.owner, p.repo, f))]);
  if (rd.status !== 200 && meta.status === 404) return { input, repo: p.slug, error: "repo not found (private, renamed or deleted?)" };
  let findings = [], checked = [];
  if (rd.status === 200) { findings.push(...scanText(rd.text, rd.name)); checked.push(rd.name); }
  rest.forEach((x, i) => { if (x.status !== 200) return; const f = files[i]; checked.push(f);
    if (f === "package.json") findings.push(...scanPackageJson(x.text)); else if (f === "setup.py") findings.push(...scanSetupPy(x.text), ...scanText(x.text, f)); else findings.push(...scanText(x.text, f)); });
  let repo_meta = null;
  if (meta.status === 200) {
    const m = meta.json; repo_meta = { created: m.created_at, age_days: days(m.created_at), pushed: m.pushed_at, stars: m.stargazers_count, forks: m.forks_count, watchers: m.subscribers_count, size_kb: m.size, open_issues: m.open_issues_count, fork: m.fork, archived: m.archived, license: m.license && m.license.spdx_id, owner_type: m.owner && m.owner.type, default_branch: m.default_branch };
    const own = await gh(`/users/${p.owner}`);
    if (own.status === 200) { repo_meta.owner_created = own.json.created_at; repo_meta.owner_age_days = days(own.json.created_at); repo_meta.owner_public_repos = own.json.public_repos; repo_meta.owner_followers = own.json.followers; }
    if (repo_meta.age_days !== null && repo_meta.age_days < 120 && repo_meta.stars >= 100) findings.push({ level: "warn", code: "young_repo_many_stars", message: `${repo_meta.stars} stars on a repo only ${repo_meta.age_days} days old: stars may be bought to look trustworthy.`, file: "github" });
    if (repo_meta.stars >= 50 && repo_meta.watchers !== undefined && repo_meta.watchers <= 1 && repo_meta.forks <= repo_meta.stars / 40) findings.push({ level: "warn", code: "stars_without_engagement", message: `${repo_meta.stars} stars but ${repo_meta.forks} forks and ${repo_meta.watchers} watchers: an unusual ratio often seen with fake stars.`, file: "github" });
    if (repo_meta.owner_age_days !== undefined && repo_meta.owner_age_days !== null && repo_meta.owner_age_days < 90) findings.push({ level: "warn", code: "new_owner_account", message: `The owner account is only ${repo_meta.owner_age_days} days old.`, file: "github" });
    if (/(update|official|tools?|team|labs?)$/i.test(p.owner) && /(solana|phantom|metamask|ethereum|binance|coinbase|uniswap|jupiter|trading ?view|ledger|trezor)/i.test(p.owner)) findings.push({ level: "warn", code: "brand_like_owner", message: `Owner name "${p.owner}" imitates a crypto brand. Official orgs are e.g. solana-labs, solana-developers, anza-xyz, MetaMask, coinbase.`, file: "github" });
    const lifeDays = m.pushed_at && m.created_at ? (Date.parse(m.pushed_at) - Date.parse(m.created_at)) / 864e5 : null;
    if (lifeDays !== null && lifeDays < 2 && repo_meta.stars >= 50) findings.push({ level: "warn", code: "never_updated", message: `Last push was within ${Math.max(1, Math.ceil(lifeDays * 24))} h of creation, yet it has ${repo_meta.stars} stars: real projects keep getting commits.`, file: "github" });
    if (repo_meta.owner_public_repos <= 1 && repo_meta.owner_followers === 0 && repo_meta.stars >= 100) findings.push({ level: "warn", code: "single_repo_owner", message: "Owner has a single public repo and no followers, but the repo has many stars.", file: "github" });
    if (typeof m.size === "number" && m.size < 20 && checked.length <= 1 && rd.status === 200 && /(template|starter|boilerplate|dapp|kit|bot|sdk|app)/i.test((m.description || "") + rd.text.slice(0, 2000))) findings.push({ level: "warn", code: "readme_only_repo", message: "The repo is almost empty (README only) but presents itself as a template/app/kit. SolanaCry looked exactly like this.", file: "github" });
    if (m.archived) findings.push({ level: "info", code: "archived", message: "Repo is archived (no longer maintained).", file: "github" });
  } else repo_meta = { unavailable: meta.status === 403 || meta.status === 429 ? "GitHub API rate limit, metadata skipped" : "metadata unavailable" };
  const v = verdict(findings);
  return { input, repo: p.slug, url: p.url, verdict: v, advice: ADVICE[v], files_checked: checked, findings, install_commands: rd.status === 200 ? commands(rd.text) : [], repo_meta, checked_at: new Date().toISOString() };
}
