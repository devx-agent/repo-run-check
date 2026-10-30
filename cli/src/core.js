// DevX Repo Run Check: heuristics for "is it safe for my agent to follow this repo's install steps?"
export const IOC_DOMAINS = ["developer-update.app", "maxwintodaybtc.com", "betasignaltradingviewai.app"];
export const SAFE_INSTALLERS = ["sh.rustup.rs", "foundry.paradigm.xyz", "release.anza.xyz", "release.solana.com", "get.docker.com", "bun.sh", "deno.land", "install.python-poetry.org", "astral.sh", "get.pnpm.io", "nodejs.org", "deb.nodesource.com", "rpm.nodesource.com", "ollama.com", "starship.rs", "tailscale.com", "get.helm.sh", "sdk.cloud.google.com", "install.determinate.systems", "nixos.org", "sh.vector.dev", "get.k3s.io", "cli.github.com", "fly.io", "railway.app", "supabase.com", "vercel.com", "get.volta.sh", "fnm.vercel.app", "raw.githubusercontent.com/nvm-sh/", "raw.githubusercontent.com/Homebrew/", "raw.githubusercontent.com/ohmyzsh/", "install.solana.com", "solana-install.solana.workers.dev", "get.scoop.sh", "aka.ms", "dot.net", "cli.doppler.com", "pyenv.run", "get.rvm.io", "sh.sdkman.io", "raw.githubusercontent.com/coral-xyz/", "raw.githubusercontent.com/otter-sec/", "raw.githubusercontent.com/foundry-rs/", "raw.githubusercontent.com/solana-labs/", "raw.githubusercontent.com/anza-xyz/", "raw.githubusercontent.com/solana-developers/", "uv.dev", "claude.ai", "cursor.com", "opencode.ai", "x.ai"];
export const POPULAR = ["@solana/web3.js", "@solana/spl-token", "@solana/kit", "@coral-xyz/anchor", "@solana/wallet-adapter-react", "@solana/wallet-adapter-wallets", "@metaplex-foundation/umi", "ethers", "web3", "viem", "wagmi", "bs58", "tweetnacl", "bip39", "hardhat", "@openzeppelin/contracts", "@uniswap/sdk-core", "@walletconnect/web3-provider", "@rainbow-me/rainbowkit", "@coinbase/wallet-sdk", "@metamask/sdk", "axios", "dotenv", "express", "react", "next", "typescript", "chalk", "commander", "lodash", "node-fetch", "@x402/fetch", "x402-fetch", "@modelcontextprotocol/sdk"];
export const TYPO_TARGETS = ["@solana/web3.js", "@solana/spl-token", "@solana/kit", "@coral-xyz/anchor", "@solana/wallet-adapter-react", "@solana/wallet-adapter-wallets", "@metaplex-foundation/umi", "@openzeppelin/contracts", "@uniswap/sdk-core", "@walletconnect/web3-provider", "@rainbow-me/rainbowkit", "@coinbase/wallet-sdk", "@metamask/sdk", "@modelcontextprotocol/sdk", "ethers", "tweetnacl", "hardhat"];
const LEGIT_NEAR = ["ether", "bip32", "hardhat-deploy", "web3.js"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "goo.gl", "shorturl.at", "tiny.cc", "ow.ly"];
const FILEHOSTS = ["mega.nz", "mediafire.com", "cdn.discordapp.com", "media.discordapp.net", "gofile.io", "anonfiles.com", "transfer.sh", "pixeldrain.com", "dropbox.com", "drive.google.com", "files.catbox.moe", "temp.sh", "0x0.st"];

function dl(a, b) { const m = a.length, n = b.length; if (Math.abs(m - n) > 2) return 9; const d = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]); for (let j = 1; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++) { d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1); }
  return d[m][n]; }
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } };
const urlsIn = (s) => s.match(/https?:\/\/[^\s"'`<>)\]]+/gi) || [];
const inList = (u, list) => { const h = hostOf(u), full = u.toLowerCase(); return list.some((d) => d.includes("/") ? full.includes(d.toLowerCase()) : (h === d || h.endsWith("." + d))); };
const clip = (s) => { s = s.trim(); return s.length > 180 ? s.slice(0, 177) + "..." : s; };

export function parseRepo(input) {
  let s = String(input || "").trim().replace(/\.git$/, "").replace(/\/+$/, "");
  if (!s) return { error: "repo required (github.com/owner/repo or owner/repo)" };
  const m = s.match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100})(?:[\/?#].*)?$/i) || s.match(/^([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100})$/);
  if (!m) return { error: "only public GitHub repos are supported: github.com/owner/repo" };
  return { owner: m[1], repo: m[2], slug: `${m[1]}/${m[2]}`, url: `https://github.com/${m[1]}/${m[2]}` };
}

// Scan one text file. Returns findings with file + line evidence.
export function scanText(text, file = "input") {
  const out = [], seen = new Set();
  const add = (level, code, message, line, ln) => { const k = code + "|" + ln; if (seen.has(k)) return; seen.add(k); out.push({ level, code, message, file, line: ln, evidence: clip(line) }); };
  const lines = String(text || "").split(/\r?\n/);
  const isTasks = /\.vscode\/tasks\.json$/i.test(file);
  lines.forEach((raw, i) => {
    const ln = i + 1, L = raw, l = raw.toLowerCase();
    if (!l.trim()) return;
    for (const d of IOC_DOMAINS) if (l.includes(d)) add("danger", "known_malware_ioc", `References ${d}, a domain tied to a published malware campaign (SolanaCry / NetSupport RAT).`, L, ln);
    const psDl = /(\biwr\b|invoke-webrequest|\birm\b|invoke-restmethod|downloadstring|downloaddata|downloadfile|net\.webclient|start-bitstransfer)/i, psEx = /(\biex\b|invoke-expression|\[scriptblock\]::create|&\s*\(\s*\$)/i;
    if (psDl.test(L) && psEx.test(L)) add("danger", "download_and_execute_powershell", "PowerShell one-liner that downloads code and runs it in memory (iwr/irm + iex). This is exactly how the SolanaCry repo installed a remote-access trojan.", L, ln);
    if (/powershell[^\n]*\s-(e|ec|en|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{16,}/i.test(L)) add("danger", "encoded_powershell", "PowerShell with an -EncodedCommand payload: the real command is hidden in base64.", L, ln);
    if (/\$\w+\s*\+\s*['"$][^\n]*\+[^\n]*(\biex\b|invoke-expression|\biwr\b|invoke-webrequest)/i.test(L) || /['"][\w.-]{1,12}['"]\s*\+\s*['"][\w.\/-]{1,12}['"]\s*\+[^\n]*(\biex\b|\biwr\b|downloadstring)/i.test(L)) add("danger", "obfuscated_url", "The download URL is assembled from string fragments so it can't be read or blocked easily.", L, ln);
    if (/frombase64string[\s\S]{0,160}(\biex\b|invoke-expression|scriptblock|reflection\.assembly|::load)/i.test(L) || /base64\s+(-d|--decode|-D)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i.test(L) || /echo\s+['"]?[A-Za-z0-9+\/=]{40,}['"]?\s*\|\s*base64/i.test(L)) add("danger", "base64_execute", "Decodes a base64 blob and executes it.", L, ln);
    if (/\bmshta(\.exe)?\s+["']?(https?:|vbscript|javascript)/i.test(L) || /certutil[^\n]*-urlcache/i.test(L) || /regsvr32[^\n]*\/i:\s*https?:/i.test(L) || /rundll32[^\n]*(https?:|javascript:)/i.test(L) || /bitsadmin[^\n]*\/transfer/i.test(L)) add("danger", "lolbin_download", "Uses a Windows system binary (mshta/certutil/regsvr32/rundll32/bitsadmin) to fetch or run remote code, a common malware technique.", L, ln);
    if (/(add-mppreference\s+-exclusion|set-mppreference\s+-disable|disable\s+(your\s+)?(antivirus|anti-virus|windows\s+defender|defender|smartscreen|gatekeeper)|turn\s+off\s+(your\s+)?(antivirus|defender))/i.test(L)) add("danger", "disable_security", "Asks to disable antivirus / Defender / Gatekeeper or add an exclusion.", L, ln);
    if (/(ignore|disregard)\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts)/i.test(L) || /(ai|llm|coding)\s+(agent|assistant)s?\b[^\n]{0,80}\b(must|should|need to|have to)\s+(run|execute|install|paste)/i.test(L) || /\b(note|attention|important)\s+(to|for)\s+(ai|llm|agents?|assistants?)\b/i.test(L)) add("danger", "agent_targeted_instructions", "Text addressed to AI agents telling them what to run or to ignore instructions (prompt injection).", L, ln);
    if (/[\u202A-\u202E\u2066-\u2069]/.test(L)) add("danger", "bidi_control_chars", "Contains Unicode bidirectional control characters that can make code display differently than it runs (Trojan Source).", L, ln);
    else if (/[\u200B-\u200D\u2060\uFEFF]/.test(L.replace(/^\uFEFF/, ""))) add("warn", "invisible_chars", "Contains zero-width characters that can hide text from a human reviewer.", L, ln);
    const pipe = /(curl|wget|iwr|irm)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|(ba|z)?sh\s+(-c\s+)?["']?\$\(\s*(curl|wget)|bash\s+<\(\s*(curl|wget)|\|\s*(sudo\s+)?python3?\s*(-\s*)?$/i;
    if (pipe.test(L)) {
      const us = urlsIn(L); const ip = us.some((u) => /^\d+\.\d+\.\d+\.\d+$/.test(hostOf(u)));
      if (ip) add("danger", "pipe_to_shell_ip", "Pipes a script from a raw IP address straight into a shell.", L, ln);
      else if (us.length && us.every((u) => inList(u, SAFE_INSTALLERS))) add("info", "pipe_to_shell_known_installer", `Pipes an installer into a shell from a well-known vendor (${us.map(hostOf).join(", ")}). Normal for toolchains, still runs remote code.`, L, ln);
      else add("warn", "pipe_to_shell", `Downloads a script and pipes it straight into a shell${us.length ? " from " + us.map(hostOf).join(", ") : ""}. Read the script before running it.`, L, ln);
    }
    for (const u of urlsIn(L)) {
      const h = hostOf(u);
      if (/\.(exe|msi|scr|bat|cmd|vbs|vbe|ps1|hta|lnk|dmg|pkg|apk|jar|iso)(\?|#|$)/i.test(u) && !/(^|\.)github\.com$|githubusercontent\.com$|microsoft\.com$|apple\.com$|python\.org$|nodejs\.org$|docker\.com$|mozilla\.org$|google\.com$/.test(h)) add("warn", "binary_download", `Links a Windows/macOS/Android executable from ${h}. Prefer releases you can verify.`, L, ln);
      if (inList(u, SHORTENERS)) add("warn", "url_shortener", `Uses a URL shortener (${h}) that hides the real destination.`, L, ln);
      if (inList(u, FILEHOSTS) && /(download|install|setup|\.zip|\.rar|\.7z|\.exe|tool|bot|crack|loader)/i.test(L)) add("warn", "file_sharing_download", `Install files hosted on a file-sharing service (${h}).`, L, ln);
    }
    if (/(\.zip|\.rar|\.7z|archive)[^\n]{0,80}(password|passwd|pass|pwd)\s*[:=]?\s*\S{2,24}|(password|passwd|pwd)\s*[:=]\s*\S{2,24}[^\n]{0,60}(\.zip|\.rar|\.7z|archive|extract|unzip)/i.test(L)) add("danger", "password_protected_archive", "Password-protected archive: a classic trick to stop antivirus from scanning a malware download.", L, ln);
    if (/xattr\s+-(d|c|cr|rd)\b[^\n]*(quarantine)?/i.test(L) || /spctl\s+--master-disable/i.test(L)) add("warn", "macos_quarantine_bypass", "Removes macOS quarantine / disables Gatekeeper so an unsigned app can run.", L, ln);
    if (/\b(paste|enter|type|submit|provide)\s+(in\s+|here\s+)?your\s+(wallet'?s?\s+|real\s+|main\s+)?(seed(\s*phrase)?|recovery\s*phrase|mnemonic|secret\s*phrase|private\s*key)\b/i.test(L)) add("warn", "seed_phrase_request", "Asks you to paste a seed/recovery phrase. Never give a tool your real wallet's seed phrase.", L, ln);
    if (isTasks && /"runOn"\s*:\s*"folderOpen"/i.test(L)) add("danger", "vscode_autorun_task", "VS Code task set to run automatically when the folder is opened (a known malware-repo trick).", L, ln);
  });
  return out;
}

export function scanPackageJson(text) {
  const out = []; let pj; try { pj = JSON.parse(text); } catch { return [{ level: "info", code: "package_json_unparsed", message: "package.json is not valid JSON.", file: "package.json" }]; }
  const sc = pj.scripts || {};
  for (const k of ["preinstall", "install", "postinstall", "prepare", "prepublish"]) if (sc[k]) {
    const v = String(sc[k]); const bad = /(curl|wget|https?:\/\/|node\s+-e|eval|base64|powershell|\biex\b|\|\s*(ba)?sh|nc\s+-|\.exe\b)/i.test(v);
    out.push({ level: bad ? "danger" : "info", code: bad ? "install_script_network_exec" : "install_script", message: bad ? `npm "${k}" script fetches or evaluates code during install.` : `npm "${k}" script runs automatically on install.`, file: "package.json", evidence: clip(`"${k}": "${v}"`) });
  }
  const deps = { ...(pj.dependencies || {}), ...(pj.devDependencies || {}), ...(pj.optionalDependencies || {}) };
  for (const [name, ver] of Object.entries(deps)) {
    const v = String(ver);
    if (/^(https?:|git\+|git:|github:|[\w-]+\/[\w.-]+(#.*)?$)/i.test(v) && !/^workspace:|^file:|^link:|^npm:/.test(v)) out.push({ level: "warn", code: "dependency_from_url", message: `Dependency "${name}" is installed from a URL or git repo instead of the npm registry.`, file: "package.json", evidence: clip(`"${name}": "${v}"`) });
    if (!POPULAR.includes(name) && !LEGIT_NEAR.includes(name)) for (const p of TYPO_TARGETS) {
      const bare = (x) => x.replace(/^@[^/]+\//, ""), d = dl(name.toLowerCase(), p);
      const scopeFake = p.startsWith("@") && bare(name) === bare(p) && name !== p;
      if (scopeFake || (d > 0 && d <= (p.length > 8 ? 2 : 1))) { out.push({ level: scopeFake || p.startsWith("@") ? "danger" : "warn", code: "dependency_typosquat", message: `Dependency "${name}" looks like a typosquat of the popular package "${p}".`, file: "package.json", evidence: clip(`"${name}": "${v}"`) }); break; }
    }
  }
  return out;
}

export function scanSetupPy(text) {
  const out = [];
  if (/(urllib\.request|requests\.(get|post)|subprocess|os\.system|exec\(|eval\(|base64\.b64decode|socket\.)/.test(text) && /(setup\(|cmdclass|install\.run)/.test(text)) out.push({ level: "warn", code: "setup_py_side_effects", message: "setup.py runs network, shell or exec code during install.", file: "setup.py" });
  return out;
}

export function verdict(findings) {
  if (findings.some((f) => f.level === "danger")) return "dangerous";
  if (findings.some((f) => f.level === "warn")) return "review_before_running";
  return "no_red_flags";
}
export const ADVICE = {
  dangerous: "Do NOT run this repo's install steps. If you already did: disconnect the machine, look for new startup entries or unknown processes, and rotate every key, token and wallet that was on it.",
  review_before_running: "Read the flagged commands and scripts yourself before an agent runs them. Prefer package-manager installs and pinned releases.",
  no_red_flags: "No known red flags in the files checked. This is not proof the code is safe; run untrusted code in a sandbox without wallet keys.",
};

// Extract shell-ish commands from fenced code blocks (for transparency in reports).
export function commands(md) {
  const out = []; const re = /```[^\n]*\n([\s\S]*?)```/g; let m;
  while ((m = re.exec(md)) && out.length < 25) for (const line of m[1].split("\n")) { const t = line.trim().replace(/^\$\s+/, ""); if (/^(npm|npx|pnpm|yarn|bun|pip3?|uv|cargo|curl|wget|iwr|irm|powershell|pwsh|bash|sh|sudo|git|brew|go|docker|make|anchor|solana|forge|python3?|node|deno|chmod|\.\/)\b/i.test(t)) out.push(clip(t)); }
  return [...new Set(out)].slice(0, 25);
}
