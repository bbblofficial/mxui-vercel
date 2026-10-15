# MX-UI v2.4.0 — Vercel edition

The Railway panel (same flat UI: dashboard, logs, sign-in, setup, subscription page) as a single Vercel function in JavaScript.
VLESS + Trojan over WebSocket + TLS. No Cloudflare IP/domain pinning, no Xray core.

## Deploy
1. Push to GitHub, import in Vercel.
2. **Storage → add Upstash Redis** (free plan is fine) and connect it to the project. This is required: Vercel runs many
   server instances, so the password, configs and usage must live in Redis. Without it the panel shows a setup notice.
3. **Redeploy**, bind a custom domain, open `https://your-domain/setup` and choose the admin password
   (or set `ADMIN_PASSWORD` to skip setup).

## Local run
`npm install && npm start` → http://localhost:3000 (in-memory store, lost on restart).

## Behaviour on Vercel
- Enable/disable, expiry, quota, device limit and reset are enforced when a connection starts; usage is added when it ends.
  Connections last at most 300 s, so clients reconnect.
- Device limit and "live connections" only see connections on the same function instance.
- Not available: VMess, Shadowsocks, speed limits, Xray logs, IP suggestions, health probe (they need a long-running server).
- Requires Fluid Compute (default on new projects).
