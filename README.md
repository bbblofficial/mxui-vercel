# MX-UI v2.4.0 — Vercel edition

The Railway panel (same flat UI: dashboard, logs, sign-in, setup, subscription page), ported to a single Vercel function in JavaScript.
VLESS + Trojan over WebSocket + TLS. No Cloudflare IP/domain pinning, no Xray core.

## Deploy
1. Push to GitHub, import in Vercel.
2. Add **Upstash Redis** (Vercel → Storage / Marketplace). Without it, state lives in memory and is lost on cold starts.
3. Deploy, bind a custom domain, open `https://your-domain/setup` and choose the admin password
   (or set `ADMIN_PASSWORD` to skip setup).

## Behaviour on Vercel
- Enable/disable, expiry, quota, device limit and reset are enforced when a connection starts; usage is added when it ends. Connections last at most 300 s, so clients reconnect.
- Device limit and "live connections" only see connections on the same function instance.
- Not available: VMess, Shadowsocks, speed limits, Xray logs, IP suggestions, health probe (they need a long-running server).
- Requires Fluid Compute (default on new projects).
