// Redis access: Upstash REST (production) or an in-memory executor (local dev / tests).
const REST = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
export const mode = REST ? "redis" : process.env.MXUI_MEMORY === "1" ? "memory" : "none";

const db = new Map();
export function memExec([c, k, ...a]) {
  const col = (init) => { if (!db.has(k)) db.set(k, init()); return db.get(k); };
  switch (String(c).toUpperCase()) {
    case "SET": if (a.includes("NX") && db.has(k)) return null; db.set(k, String(a[0])); return "OK";
    case "GET": return db.has(k) ? db.get(k) : null;
    case "DEL": return db.delete(k) ? 1 : 0;
    case "HSET": { const m = col(() => new Map()); let n = 0; for (let i = 0; i < a.length; i += 2) { if (!m.has(String(a[i]))) n++; m.set(String(a[i]), String(a[i + 1])); } return n; }
    case "HSETNX": { const m = col(() => new Map()); if (m.has(String(a[0]))) return 0; m.set(String(a[0]), String(a[1])); return 1; }
    case "HGETALL": return db.has(k) ? [...db.get(k)].flat() : [];
    case "HDEL": { const m = db.get(k); let n = 0; if (m) for (const f of a) if (m.delete(String(f))) n++; return n; }
    case "HINCRBY": { const m = col(() => new Map()), v = (+m.get(String(a[0])) || 0) + Number(a[1]); m.set(String(a[0]), String(v)); return v; }
    case "LPUSH": { const l = col(() => []); l.unshift(String(a[0])); return l.length; }
    case "LTRIM": { const l = db.get(k); if (l) db.set(k, l.slice(+a[0], +a[1] + 1)); return "OK"; }
    case "LRANGE": { const l = db.get(k) || []; return l.slice(+a[0], +a[1] === -1 ? undefined : +a[1] + 1); }
    default: throw new Error("unsupported command " + c);
  }
}

export async function run(cmds) {
  if (mode === "redis") {
    const r = await fetch(`${REST}/pipeline`, { method: "POST", headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" }, body: JSON.stringify(cmds) });
    const j = await r.json();
    if (!r.ok || !Array.isArray(j)) throw new Error("redis: " + (j?.error || r.status));
    return j.map((x) => { if (x.error) throw new Error("redis: " + x.error); return x.result; });
  }
  return cmds.map(memExec);
}
