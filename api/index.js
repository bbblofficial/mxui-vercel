import { createServer } from "node:http";
import net from "node:net";
import os from "node:os";
import crypto from "node:crypto";
import QRCode from "qrcode";
import { WebSocketServer, createWebSocketStream } from "ws";
import * as P from "../lib/pages.js";

const VERSION = "2.4.0", T0 = Date.now(), COOKIE = "mxui_session";
const REST = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
const ENV_PW = process.env.ADMIN_PASSWORD || "";
const KEY = "mxui:state", PROTOS = ["vless", "trojan"];
const H = { "Cache-Control": "no-store" };

/* ---------- state ---------- */
let mem = null;
const hex = (n) => crypto.randomBytes(n).toString("hex");
const mk = (o = {}) => ({
  label: "Config", limit_bytes: 0, used_bytes: 0, up_bytes: 0, down_bytes: 0, created_at: new Date().toISOString(),
  active: true, expires_at: null, note: "", is_default: false, protocols: ["vless", "trojan"], fingerprint: "chrome",
  alpn: "", ip_limit: 0, speed_limit_bytes: 0, last_used: null, ...o,
});
async function load() {
  let s = mem;
  if (REST) {
    const j = await (await fetch(`${REST}/get/${KEY}`, { headers: { Authorization: `Bearer ${TOKEN}` } })).json();
    s = j.result ? JSON.parse(j.result) : null;
  }
  s = mem = s || { links: {}, pw: "", secret: hex(24), total: 0, reqs: 0, rejected: 0, series: {}, logs: [], activity: [] };
  if (!Object.keys(s.links).length) { s.links[crypto.randomUUID()] = mk({ label: "Default", is_default: true }); await save(s); }
  return s;
}
async function save(s) {
  mem = s;
  if (REST) await fetch(`${REST}/set/${KEY}`, { method: "POST", headers: { Authorization: `Bearer ${TOKEN}` }, body: JSON.stringify(s) });
}
const note = (s, kind, message, level = "info") => {
  const time = new Date().toISOString();
  s.activity.push({ time, kind, message, level }); s.activity = s.activity.slice(-100);
  s.logs.push({ time, level, msg: `[${kind}] ${message}` }); s.logs = s.logs.slice(-500);
};

/* ---------- auth ---------- */
const secretOf = (s) => `${process.env.SECRET || ""}${ENV_PW ? "env:" + ENV_PW : s.secret}`;
const sign = (s, t) => crypto.createHmac("sha256", secretOf(s)).update(t).digest("hex");
const setupDone = (s) => !!(ENV_PW || s.pw);
function authed(req, s) {
  const m = new RegExp(`(?:^|; )${COOKIE}=(\\d+)\\.([a-f0-9]+)`).exec(req.headers.cookie || "");
  if (!m || !setupDone(s)) return false;
  const ok = sign(s, m[1]);
  return Date.now() - +m[1] < 6048e5 && m[2].length === ok.length && crypto.timingSafeEqual(Buffer.from(m[2]), Buffer.from(ok));
}
const hashPw = (pw) => { const salt = hex(8); return `scrypt$${salt}$${crypto.scryptSync(pw, salt, 32).toString("hex")}`; };
function checkPw(s, pw) {
  const a = ENV_PW ? crypto.createHash("sha256").update(ENV_PW).digest() : null;
  if (a) return crypto.timingSafeEqual(crypto.createHash("sha256").update(pw).digest(), a);
  const [, salt, h] = (s.pw || "").split("$");
  return !!h && crypto.timingSafeEqual(crypto.scryptSync(pw, salt, 32), Buffer.from(h, "hex"));
}
const cookie = (s) => { const t = String(Date.now()); return `${COOKIE}=${t}.${sign(s, t)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`; };
const fails = new Map();
const limited = (ip) => (fails.get(ip) || []).filter((t) => t > Date.now() - 6e5).length >= 8;

/* ---------- links ---------- */
const derive = (s, tag, uid) => crypto.createHash("sha256").update(`${tag}:${uid}:${s.secret}`).digest("hex").slice(0, 24);
const trojanPw = (s, uid) => derive(s, "trojan", uid);
const stateOf = (l) => !l.active ? "disabled" : (l.expires_at && Date.now() > Date.parse(l.expires_at)) ? "expired"
  : (l.limit_bytes > 0 && l.used_bytes >= l.limit_bytes) ? "depleted" : "active";
const hostOf = (req) => req.headers["x-forwarded-host"] || req.headers.host;
const qs = (o) => Object.entries(o).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
function variants(s, uid, l, host) {
  const ws = (path) => ({ security: "tls", type: "ws", host, path, sni: host, fp: l.fingerprint || "chrome", alpn: l.alpn || "http/1.1" });
  return l.protocols.map((p) => {
    const name = p === "vless" ? "VLESS" : "Trojan", rem = encodeURIComponent(`${l.label} · ${name}`);
    const url = p === "vless" ? `vless://${uid}@${host}:443?${qs({ encryption: "none", ...ws("/ws") })}#${rem}`
      : `trojan://${encodeURIComponent(trojanPw(s, uid))}@${host}:443?${qs(ws("/trojan"))}#${rem}`;
    return { protocol: p, label: name, where: "Domain", tag: `${name} · Domain`, address: host, port: 443, url };
  });
}
function pub(s, conns, uid, l, req) {
  const host = hostOf(req), base = `https://${host}`, v = variants(s, uid, l, host);
  const live = [...conns.values()].filter((c) => c.uuid === uid);
  return {
    uuid: uid, ...l, state: stateOf(l), expired: stateOf(l) === "expired",
    days_left: l.expires_at ? Math.max(0, (Date.parse(l.expires_at) - Date.now()) / 864e5) : null,
    trojan_password: trojanPw(s, uid), vless_link: v.find((x) => x.protocol === "vless")?.url || "",
    trojan_link: v.find((x) => x.protocol === "trojan")?.url || "", primary_link: v[0]?.url || "", variants: v,
    sub_url: `${base}/sub/${uid}`, info_url: `${base}/sub/${uid}/info`, connected_ips: new Set(live.map((c) => c.ip)).size,
    live_connections: live.length, applied_ips_count: 0,
  };
}
const UNITS = { KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4 };
const SPEED = { KBIT: 125, MBIT: 125000, KB: 1024, MB: 1024 ** 2 };
function applyLimits(l, b) {
  const n = (k) => Number(b[k]) || 0;
  if ("limit_value" in b) l.limit_bytes = n("limit_value") <= 0 ? 0 : Math.floor(n("limit_value") * (UNITS[b.limit_unit] || UNITS.GB));
  if ("expires_days" in b) l.expires_at = n("expires_days") > 0 ? new Date(Date.now() + n("expires_days") * 864e5).toISOString() : null;
  if ("expires_at" in b) { const d = b.expires_at && new Date(b.expires_at); if (d && isNaN(d)) throw new Error("Invalid expiry date"); l.expires_at = d ? d.toISOString() : null; }
  if ("ip_limit" in b) l.ip_limit = Math.max(0, Math.floor(n("ip_limit")));
  if ("speed_limit_value" in b) l.speed_limit_bytes = Math.floor(n("speed_limit_value") * (SPEED[b.speed_limit_unit] || SPEED.MBIT));
  if ("protocols" in b) { const w = PROTOS.filter((p) => [].concat(b.protocols).map((x) => String(x).replace("-ws", "")).includes(p)); if (w.length) l.protocols = w; }
  if ("fingerprint" in b) l.fingerprint = String(b.fingerprint || "chrome");
  if ("alpn" in b) l.alpn = String(b.alpn || "").slice(0, 100);
  if ("note" in b) l.note = String(b.note || "").slice(0, 300);
  if ("label" in b && String(b.label).trim()) l.label = String(b.label).trim().slice(0, 64);
}

/* ---------- portal ---------- */
const esc = (x) => String(x ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const gb = (n) => { n = +n || 0; for (const [u, z] of [["TB", 2 ** 40], ["GB", 2 ** 30], ["MB", 2 ** 20], ["KB", 1024]]) if (n >= z) return `${(n / z).toFixed(2)} ${u}`; return `${Math.floor(n)} B`; };
const fd = (i) => i ? new Date(i).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) : "Never";
async function portal(d) {
  const lim = d.limit_bytes, used = d.used_bytes, inf = lim <= 0, pct = inf ? 0 : Math.min(100, used / lim * 100);
  const [sc, st, lamp] = { active: ["", "Active", "live"], disabled: ["off", "Paused", "off"], expired: ["bad", "Expired", "cut"], depleted: ["warn", "Out of data", "warn"] }[d.state];
  const pill = (p) => `<span class="pp ${p}">${p === "vless" ? "VLESS" : "Trojan"}</span>`;
  const row = (id, tag, url) => `<div class="lrow"><span class="tag">${esc(tag)}</span><input id="${id}" readonly value="${esc(url)}"><button class="btn sm" data-copy="${id}"><span>Copy</span></button></div>`;
  const groups = d.protocols.map((p) => { const r = d.variants.filter((v) => v.protocol === p).map((v, i) => row(`lk${p}${i}`, v.where, v.url)).join("");
    return `<div class="group"><div class="group-h">${p === "vless" ? "VLESS" : "Trojan"}</div><div class="linkbox">${r}</div></div>`; }).join("");
  const qr = await QRCode.toDataURL(d.sub_url, { width: 360, margin: 2 });
  const body = `<body>${P.SPRITE}<div class="theme">${P.THEME_BTN}</div><div class="portalwrap"><article class="pass"><header class="head">${P.BRAND}<span class="sp"></span><span class="lamp ${lamp}"></span></header>
<div class="body"><section class="main"><div style="display:grid;gap:12px"><h1 class="name">${esc(d.label)}</h1><div class="ptags">${d.protocols.map(pill).join("")}<span class="stamp ${sc}"><span class="lamp ${lamp}"></span>${st}</span></div></div>
<div class="gauge"><div class="top"><b>${gb(used)}<em> / ${inf ? "∞" : gb(lim)}</em></b><span>${inf ? "unlimited" : pct.toFixed(0) + "% used"}</span></div>${inf ? '<div class="vu inf"><i></i></div>' : `<div class="vu"><i class="${pct > 90 ? "r" : pct > 70 ? "a" : ""}" style="width:${pct.toFixed(1)}%"></i></div>`}</div>
<div class="facts"><div><small>Remaining</small><b>${inf ? "∞" : gb(Math.max(0, lim - used))}</b></div><div><small>Expires</small><b>${d.expires_at ? fd(d.expires_at) : "Never"}</b><small>${d.expires_at ? Math.floor(d.days_left) + " day(s) left" : "No expiry"}</small></div><div><small>Last seen</small><b>${d.last_used ? fd(d.last_used) : "—"}</b></div><div><small>Live devices</small><b>${d.live_connections}</b></div></div>
<div class="sec"><b>Connection links</b><button class="btn sm" onclick="copyAll()"><span>Copy all</span></button></div>${groups}<div class="linkbox">${row("subUrl", "Subscription", d.sub_url)}</div></section>
<aside class="stub"><div class="qr"><img src="${qr}" alt="Subscription QR code"></div><small>Scan with your client<br>to import everything</small></aside></div>${P.FOOT}</article></div><div id="toast" class="toast" role="status"></div><script>${P.UTIL_JS}${P.PORTAL_JS}</script></body></html>`;
  return P.PORTAL_PRE.replace("@@TITLE@@", esc(d.label) + " · MX-UI") + body;
}

/* ---------- http ---------- */
const conns = new Map();
const out = (res, code, body, type = "application/json", h = {}) => { res.writeHead(code, { "Content-Type": type + "; charset=utf-8", ...H, ...h }); res.end(type === "application/json" ? JSON.stringify(body) : body); };
const err = (res, code, detail) => out(res, code, { detail });
const html = (res, s) => out(res, 200, s, "text/html");
const redir = (res, to) => { res.writeHead(302, { Location: to, ...H }); res.end(); };
const body = (req) => new Promise((ok) => { let d = ""; req.on("data", (c) => { d += c; if (d.length > 5e6) req.destroy(); }); req.on("end", () => { try { ok(JSON.parse(d || "{}")); } catch { ok({}); } }); });
const ipOf = (req) => String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x"), p = url.pathname, M = req.method;
    const s = await load(), auth = authed(req, s);
    let m;
    if (p === "/health" || p === "/healthz" || p === "/readyz") return out(res, 200, { status: "ok" });
    if (p === "/") return redir(res, !setupDone(s) ? "/setup" : auth ? "/dashboard" : "/login");
    if (p === "/login") return setupDone(s) ? html(res, P.LOGIN) : redir(res, "/setup");
    if (p === "/setup") return setupDone(s) ? redir(res, "/login") : html(res, P.SETUP);
    if (p === "/dashboard") return auth ? html(res, P.DASH) : redir(res, "/login");
    if (p === "/logs") return auth ? html(res, P.LOGS) : redir(res, "/login");

    /* subscriptions */
    if ((m = /^\/sub\/([0-9a-f-]{36})(\/info)?$/.exec(p)) || p === "/sub/user") {
      const uid = m ? m[1] : url.searchParams.get("uuid"), l = s.links[uid];
      if (!l) return err(res, 404, "not found");
      const wantsPage = m?.[2] || p === "/sub/user" || (/text\/html/.test(req.headers.accept || "") && !url.searchParams.has("raw"));
      if (wantsPage) return html(res, await portal(pub(s, conns, uid, l, req)));
      const lines = stateOf(l) === "active" ? variants(s, uid, l, hostOf(req)).map((v) => v.url) : [];
      const ex = l.expires_at ? `; expire=${Math.floor(Date.parse(l.expires_at) / 1000)}` : "";
      return out(res, 200, Buffer.from(lines.join("\n")).toString("base64"), "text/plain", {
        "subscription-userinfo": `upload=${l.up_bytes}; download=${Math.max(0, l.used_bytes - l.up_bytes)}; total=${l.limit_bytes}${ex}`,
        "profile-title": "base64:" + Buffer.from(l.label).toString("base64"), "profile-update-interval": "6" });
    }
    if (p === "/api/me") return out(res, 200, { authenticated: auth, version: VERSION });
    if (p === "/api/current-paths") return out(res, 200, { dashboard: "/dashboard", login: "/login", sub: "/sub", setup: "/setup" });

    if (p === "/api/setup" && M === "POST") {
      if (setupDone(s)) return err(res, 403, "Already set up");
      const pw = String((await body(req)).password || "");
      if (pw.length < 6) return err(res, 400, "Password needs 6+ characters");
      s.pw = hashPw(pw); note(s, "auth", "Panel set up", "ok"); await save(s);
      return out(res, 200, { ok: true }, "application/json", { "Set-Cookie": cookie(s) });
    }
    if (p === "/api/login" && M === "POST") {
      if (!setupDone(s)) return err(res, 403, "Setup required");
      const ip = ipOf(req); if (limited(ip)) return err(res, 429, "Too many attempts. Wait 10 minutes.");
      if (!checkPw(s, String((await body(req)).password || ""))) {
        fails.set(ip, [...(fails.get(ip) || []), Date.now()]); await new Promise((r) => setTimeout(r, 600));
        return err(res, 401, "Wrong password");
      }
      fails.delete(ip);
      return out(res, 200, { ok: true }, "application/json", { "Set-Cookie": cookie(s) });
    }
    if (p === "/api/logout") return out(res, 200, { ok: true }, "application/json", { "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; Max-Age=0` });

    if (p.startsWith("/api/") || p === "/stats" || p === "/sub-all") {
      if (!auth) return err(res, 401, "Not authenticated");
      if (p === "/api/change-password") {
        const b = await body(req);
        if (ENV_PW) return err(res, 400, "Password is managed by the ADMIN_PASSWORD environment variable");
        if (!checkPw(s, String(b.current_password || ""))) return err(res, 401, "Current password is wrong");
        if (String(b.new_password || "").length < 6) return err(res, 400, "New password needs 6+ characters");
        s.pw = hashPw(b.new_password); s.secret = hex(24); await save(s);
        return out(res, 200, { ok: true }, "application/json", { "Set-Cookie": `${COOKIE}=; Path=/; Max-Age=0` });
      }
      if (p === "/sub-all") {
        const all = Object.entries(s.links).filter(([, l]) => stateOf(l) === "active").flatMap(([u, l]) => variants(s, u, l, hostOf(req)).map((v) => v.url));
        return out(res, 200, Buffer.from(all.join("\n")).toString("base64"), "text/plain");
      }
      if (p === "/stats") {
        const L = Object.values(s.links), states = {}, protos = { vless: 0, trojan: 0, vmess: 0, ss: 0 };
        L.forEach((l) => { states[stateOf(l)] = (states[stateOf(l)] || 0) + 1; l.protocols.forEach((x) => protos[x]++); });
        const series = Array.from({ length: 24 }, (_, i) => { const k = new Date(Date.now() - (23 - i) * 36e5).toISOString().slice(0, 13); return { hour: k.slice(-2) + ":00", bytes: s.series[k] || 0 }; });
        const up = Math.floor((Date.now() - T0) / 1000), tm = os.totalmem(), fm = os.freemem(), cpus = os.cpus().length;
        return out(res, 200, { version: VERSION, uptime: `${Math.floor(up / 3600)}h ${Math.floor(up % 3600 / 60)}m`, timestamp: new Date().toISOString(),
          total_bytes: s.total, total_traffic_mb: +(s.total / 1048576).toFixed(2), total_requests: s.reqs, rejected: s.rejected,
          active_connections: conns.size, online_ips: new Set([...conns.values()].map((c) => c.ip)).size, links_count: L.length, active_links: states.active || 0,
          states, protocols: protos, series_24h: series, net: [], cpu_percent: Math.min(100, +(os.loadavg()[0] / cpus * 100).toFixed(1)), cpu_cores: cpus,
          load_avg: os.loadavg().map((x) => +x.toFixed(2)), ram_used_mb: Math.floor((tm - fm) / 1048576), ram_total_mb: Math.floor(tm / 1048576),
          ram_available_mb: Math.floor(fm / 1048576), ram_percent: +((tm - fm) / tm * 100).toFixed(1), swap_used_mb: 0, swap_total_mb: 0, swap_percent: 0,
          disk_used_gb: 0, disk_total_gb: 0, disk_percent: 0, xray: { running: true, version: "Vercel", restarts: 0 }, activity: s.activity.slice(-20) });
      }
      if (p === "/api/links" && M === "GET") {
        const list = Object.entries(s.links).map(([u, l]) => pub(s, conns, u, l, req)).sort((a, b) => String(b.created_at).localeCompare(a.created_at));
        return out(res, 200, { links: [...list.filter((x) => x.is_default), ...list.filter((x) => !x.is_default)] });
      }
      if (p === "/api/links" && M === "POST") {
        const b = await body(req), uid = crypto.randomUUID(), l = mk();
        try { applyLimits(l, { ...b, label: b.label || `Config ${Object.keys(s.links).length + 1}` }); } catch (e) { return err(res, 400, e.message); }
        s.links[uid] = l; note(s, "config", `Created ${l.label}`, "ok"); await save(s);
        return out(res, 200, pub(s, conns, uid, l, req));
      }
      if ((m = /^\/api\/links\/([0-9a-f-]{36})(\/toggle|\/reset-traffic)?$/.exec(p))) {
        const uid = m[1], l = s.links[uid]; if (!l) return err(res, 404, "Config not found");
        const b = M === "DELETE" || m[2] === "/reset-traffic" ? {} : await body(req);
        if (M === "DELETE") { if (l.is_default) return err(res, 403, "The default config can't be deleted"); delete s.links[uid]; note(s, "config", `Deleted ${l.label}`, "warn"); }
        else if (m[2] === "/toggle") { l.active = "active" in b ? !!b.active : !l.active; note(s, "config", `${l.label} ${l.active ? "enabled" : "disabled"}`); }
        else if (m[2]) l.used_bytes = l.up_bytes = l.down_bytes = 0;
        else { const k = l.is_default ? ["active", "fingerprint", "alpn", "protocols"] : null;
          const bb = k ? Object.fromEntries(Object.entries(b).filter(([x]) => k.includes(x))) : b;
          if ("active" in bb) l.active = !!bb.active;
          try { applyLimits(l, bb); } catch (e) { return err(res, 400, e.message); } }
        await save(s);
        return out(res, 200, M === "PATCH" && !m[2] ? pub(s, conns, uid, l, req) : m[2] === "/toggle" ? { ok: true, active: l.active } : { ok: true });
      }
      if (p === "/api/connections") return out(res, 200, { connections: [...conns.entries()].map(([id, c]) => ({ id, uuid: c.uuid, label: s.links[c.uuid]?.label || "?", proto: c.proto, ip: c.ip, since: c.since, up: c.up, down: c.down })).sort((a, b) => b.since - a.since) });
      if (p === "/api/qr") {
        const d = url.searchParams.get("data") || "", w = Math.max(120, Math.min(+url.searchParams.get("size") || 300, 1024));
        if (url.searchParams.get("format") === "image") { res.writeHead(200, { "Content-Type": "image/png" }); return res.end(await QRCode.toBuffer(d, { width: w, margin: 2 })); }
        return out(res, 200, { qr: await QRCode.toDataURL(d, { width: w, margin: 2 }) });
      }
      if (p === "/api/database/export") return out(res, 200, { version: VERSION, exported_at: new Date().toISOString(), links: s.links }, "application/json", { "Content-Disposition": 'attachment; filename="mx-ui-backup.json"' });
      if (p === "/api/database/import") {
        const b = await body(req); if (!b.links || typeof b.links !== "object") return err(res, 400, "Backup file has no 'links' object");
        if (b.mode === "replace") for (const u of Object.keys(s.links)) if (!s.links[u].is_default) delete s.links[u];
        let n = 0;
        for (const [u, l] of Object.entries(b.links)) { if (!/^[0-9a-f-]{36}$/.test(u) || typeof l !== "object") continue; s.links[u] = mk({ ...l, protocols: PROTOS.filter((x) => (l.protocols || []).includes(x)).length ? PROTOS.filter((x) => l.protocols.includes(x)) : PROTOS, is_default: !!l.is_default && !Object.values(s.links).some((x) => x.is_default) }); n++; }
        note(s, "backup", `Imported ${n} configs (${b.mode || "merge"})`, "ok"); await save(s);
        return out(res, 200, { ok: true, imported: n });
      }
      if (p === "/api/logs") { const lv = url.searchParams.get("level"), lim = +url.searchParams.get("limit") || 300; return out(res, 200, { logs: s.logs.filter((x) => !lv || x.level === lv).slice(-lim), activity: s.activity }); }
      if (p === "/api/logs/ports") return out(res, 200, { xray_running: true, listening: { 443: true } });
      if (p.startsWith("/api/logs/files/")) return out(res, 200, { lines: [] });
      if (p === "/api/logs/clear") { s.logs = []; s.activity = []; await save(s); return out(res, 200, { ok: true }); }
    }
    err(res, 404, "Not found");
  } catch (e) { err(res, 500, "Server error"); }
});

/* ---------- tunnels: VLESS (/ws) and Trojan (/trojan) over WebSocket ---------- */
function readAddr(buf, o, type) {
  if (type === 1) return [[...buf.subarray(o, o + 4)].join("."), o + 4];
  if (type === 2) { const n = buf[o]; return [buf.subarray(o + 1, o + 1 + n).toString(), o + 1 + n]; }
  const seg = []; for (let i = 0; i < 8; i++) seg.push(buf.readUInt16BE(o + i * 2).toString(16)); return [seg.join(":"), o + 16];
}
function parseVless(buf) {
  let o = 1; const id = buf.subarray(o, o + 16); o += 16; o += 1 + buf[o];
  const cmd = buf[o++], port = buf.readUInt16BE(o); o += 2; const t = buf[o++];
  const [host, end] = readAddr(buf, o, t);
  const h = id.toString("hex");
  return { uid: h.replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, "$1-$2-$3-$4-$5"), cmd, port, host, offset: end, reply: Buffer.from([buf[0], 0]) };
}
function parseTrojan(buf) {
  const hash = buf.subarray(0, 56).toString(); let o = 58; const cmd = buf[o++], t = buf[o++];
  const [host, e] = readAddr(buf, o, t === 3 ? 2 : t === 4 ? 3 : 1); o = e;
  const port = buf.readUInt16BE(o); return { hash, cmd, port, host, offset: o + 4 };
}
const wss = new WebSocketServer({ noServer: true });
server.on("upgrade", (req, sock, head) => {
  const p = new URL(req.url, "http://x").pathname;
  if (p === "/ws" || p === "/trojan") wss.handleUpgrade(req, sock, head, (ws) => onTunnel(ws, req, p));
  else sock.destroy();
});
function onTunnel(ws, req, path) {
  const ip = ipOf(req);
  ws.once("message", async (msg) => {
    try {
      const buf = Buffer.isBuffer(msg) ? msg : Buffer.from(msg), s = await load();
      let h, uid, proto = path === "/ws" ? "vless" : "trojan";
      if (proto === "vless") { h = parseVless(buf); uid = h.uid; }
      else { h = parseTrojan(buf); uid = Object.keys(s.links).find((u) => crypto.createHash("sha224").update(trojanPw(s, u)).digest("hex") === h.hash); }
      const l = s.links[uid], live = [...conns.values()].filter((c) => c.uuid === uid);
      s.reqs++;
      const bad = !l || h.cmd !== 1 || stateOf(l) !== "active" || !l.protocols.includes(proto)
        || (l.ip_limit > 0 && !live.some((c) => c.ip === ip) && new Set(live.map((c) => c.ip)).size >= l.ip_limit);
      if (bad) { s.rejected++; await save(s); return ws.close(); }
      const id = hex(4), c = { uuid: uid, ip, proto, since: Date.now(), up: buf.length - h.offset, down: 0 };
      conns.set(id, c);
      if (h.reply) ws.send(h.reply);
      const duplex = createWebSocketStream(ws);
      const sock = net.connect({ host: h.host, port: h.port }, () => { sock.write(buf.subarray(h.offset)); duplex.pipe(sock).pipe(duplex); });
      duplex.on("data", (d) => (c.up += d.length)); sock.on("data", (d) => (c.down += d.length));
      let done = false;
      const end = async () => {
        if (done) return; done = true; conns.delete(id); sock.destroy(); ws.terminate();
        try { const t = c.up + c.down, s2 = await load(), l2 = s2.links[uid], k = new Date().toISOString().slice(0, 13);
          if (l2 && t) { l2.used_bytes += t; l2.up_bytes += c.up; l2.last_used = new Date().toISOString(); s2.total += t; s2.series[k] = (s2.series[k] || 0) + t;
            Object.keys(s2.series).sort().slice(0, -48).forEach((x) => delete s2.series[x]); await save(s2); } } catch {}
      };
      duplex.on("error", () => {}); sock.on("error", () => {}); sock.on("close", end); duplex.on("close", end);
    } catch { ws.close(); }
  });
}

export default server;
