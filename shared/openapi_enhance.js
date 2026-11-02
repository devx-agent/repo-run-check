// Discovery metadata helpers (x402scan / AgentCash OpenAPI discovery spec + Bazaar output schemas).
// Pure functions: no pricing or payment logic lives here.
export function schemaFrom(v, depth = 0) {
  if (v === null) return { type: ["string", "number", "object", "null"] };
  if (Array.isArray(v)) return v.length ? { type: "array", items: schemaFrom(v[0], depth + 1) } : { type: "array" };
  if (typeof v === "object") {
    if (depth > 4) return { type: "object" };
    const properties = {};
    for (const [k, x] of Object.entries(v)) properties[k] = schemaFrom(x, depth + 1);
    return { type: "object", properties };
  }
  if (typeof v === "number") return { type: "number" };
  if (typeof v === "boolean") return { type: "boolean" };
  return { type: "string" };
}
// doc: OpenAPI object; o: { priceUsd: "0.002", guidance, tags: [], example, freeExamples: {path: example} }
export function enhanceDocs(doc, o) {
  doc.info["x-guidance"] = o.guidance;
  if (o.tags) doc.tags = o.tags.map((name) => ({ name }));
  for (const [path, ops] of Object.entries(doc.paths)) {
    for (const [m, op] of Object.entries(ops)) {
      if (op["x-payment-info"]) {
        op["x-payment-info"] = { price: { mode: "fixed", currency: "USD", amount: o.priceUsd }, protocols: [{ x402: {} }], ...op["x-payment-info"] };
        if (o.tags) op.tags = o.tags;
        if (o.example) op.responses[200] = { description: op.responses[200]?.description || "result", content: { "application/json": { schema: schemaFrom(o.example), example: o.example } } };
        op.responses[402] = op.responses[402] || { description: "Payment required (x402)" };
      } else {
        op.security = [];
        const ex = o.freeExamples && o.freeExamples[path];
        if (ex && !op.responses?.[200]?.content) op.responses[200] = { description: op.responses?.[200]?.description || "result", content: { "application/json": { schema: schemaFrom(ex) } } };
      }
    }
  }
  return doc;
}
