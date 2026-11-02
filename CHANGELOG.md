# Changelog

## Hosted service 1.2.1 (2026-11-02)

- Paid full check is now 0.25 USDC (250000 units, USDC on Base, x402 v2 exact) per call of 1-3 repos, on `GET /v1/check` and on the new paid remote MCP tool `full_report` (x402 MCP transport: an unpaid call returns `PaymentRequired`; payment goes in `_meta["x402/payment"]`; it is settled only after every requested report is built).
- The deep report also reads the git tree, agent/MCP configs, Claude hooks, devcontainer, build.rs, pyproject, `pull_request_target` workflows and committed binaries, and returns `risk_score` and `next_steps`.
- `worker/src` and `shared/` now match the deployed Worker source.
- Free checks are unchanged and stay free.

## 1.1.1 (2026-11-02)

- CLI/stdio MCP: the `check_repo` description and `full_report_price_usdc` now show the hosted full check price of 0.25 USDC (was 0.005). No change to the offline checks.

## 1.1.0 (2026-10-30)

- The stdio MCP server (npm package, also what the Dockerfile runs) now registers its tools with `registerTool`, with a title, a longer description (what the tool does, when to use it and when not to, what it reads or sends, what it returns, limits), clearer parameter descriptions, a JSON output schema with `structuredContent`, and tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`).
- No change to the checks themselves, the hosted API, prices or payment flow. The remote MCP endpoint served by the Worker is unchanged in this release.
- `check_command` now also returns `advice`, like the other two tools.

## 1.0.0 (2026-10-30)

- First release: CLI and stdio MCP server on npm (`devx-repo-check`), and the Cloudflare Worker behind the hosted API and remote MCP endpoint.
