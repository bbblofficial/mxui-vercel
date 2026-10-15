# Changelog

## 2.4.0 — Vercel edition
- Templates extracted from MX-UI 2.4.0 (Railway): dashboard, logs, login, setup, subscription page.
- JS API compatible with the dashboard: configs CRUD, toggle, reset, QR, backup/restore, stats, logs, subscriptions, password change.
- VLESS + Trojan tunnels with quota, expiry, enable/disable and device-limit checks.
- State lives in Upstash Redis using atomic commands (no read-modify-write races); signed stateless session cookies
  work on every instance; a password change signs everyone out.
- Fix: sign-in/setup bouncing back to the login page (state was per-instance memory).
- Removed: Cloudflare IP suggestions/pinning and domain checks, health probe.
