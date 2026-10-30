import { readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { scanText, scanPackageJson, scanSetupPy, verdict, ADVICE, commands } from "./core.js";
export const FILES = ["README.md", "readme.md", "README", "package.json", "install.sh", "setup.sh", "setup.py", "requirements.txt", ".vscode/tasks.json", "Makefile"];
export function scanDir(dir) {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) return { error: `${dir}: not a directory` };
  const findings = [], checked = []; let readme = "";
  for (const f of FILES) {
    const p = join(dir, f); if (!existsSync(p) || !statSync(p).isFile()) continue;
    if (/^readme/i.test(f) && readme) continue;
    const t = readFileSync(p, "utf8").slice(0, 300000); checked.push(f);
    if (/^readme/i.test(f)) readme = t;
    if (f === "package.json") findings.push(...scanPackageJson(t)); else if (f === "setup.py") findings.push(...scanSetupPy(t), ...scanText(t, f)); else findings.push(...scanText(t, f));
  }
  const v = verdict(findings);
  return { path: dir, verdict: v, advice: ADVICE[v], files_checked: checked, findings, install_commands: commands(readme) };
}
export function summarize(r, name) {
  const lines = r.findings.filter((f) => f.level !== "info").map((f) => `  [${f.level}] ${f.message}${f.evidence ? `\n      ${f.file}${f.line ? ":" + f.line : ""}  ${f.evidence}` : ""}`);
  return `verdict: ${r.verdict}  ${name || r.repo || r.path || "command"}\n${lines.join("\n") || "  no red flags in the files checked"}`;
}
