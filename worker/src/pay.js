// Shared x402 payment terms + facilitator calls for the paid HTTP route (/v1/check) and the paid MCP tool (full_report).
import { facilitate } from "../../shared/facilitator.js";
export const PAY_TO = "0xB3cDDccEe6B150c8efFD55B961afc0Ecefe7f247"; // MAIN wallet
export const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
export const PRICE = "250000"; // 0.25 USDC (6 decimals)
export const PRICE_USD = 0.25;
export const NETWORK = "eip155:8453";
export function requirements() { return { scheme: "exact", network: NETWORK, amount: PRICE, asset: USDC_BASE, payTo: PAY_TO, maxTimeoutSeconds: 120, extra: { name: "USD Coin", version: "2" } }; }
export async function facil(env, op, body) { const r = await facilitate(env || {}, op, body); delete r._status; return r; }
/** Does a v2 PaymentPayload's `accepted` match our terms exactly? */
export function matches(payload) {
  const a = (payload && payload.accepted) || {};
  return payload && payload.x402Version === 2 && a.scheme === "exact" && a.network === NETWORK && String(a.amount) === PRICE && (a.payTo || "").toLowerCase() === PAY_TO.toLowerCase() && (a.asset || "").toLowerCase() === USDC_BASE.toLowerCase();
}
