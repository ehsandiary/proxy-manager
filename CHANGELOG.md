# Changelog

## 1.1.1
- Fix: the Health page and date filters on Events returned "Internal Server Error" (time-window and date values
  were sent to PostgreSQL with the wrong type).
- Logo and favicon.

## 1.1.0
- **Health page**: every outage (start, end, duration, reason, use case), flaky proxies (failed checks without going
  down, by timeouts / connection errors), and a per-provider comparison (failure rate, outages, speed, price).
  Past outages are rebuilt from existing events on first start.
- **Clear failure reasons**: timeout, connection refused, unreachable, wrong password (407), blocked (403), TLS, proxy error.
- **Events page**: plain-word filters (Health, Use cases, Status changes, Imports, Users & settings), "went down" /
  "recovered", search by proxy name / IP / use case, provider, person, date range, paging, CSV export.
- **Cost**: monthly price per provider (Settings) → total, per provider and per status on the Proxies page.
- **Provider column** in the proxies table.
- **Daily summary** (optional) to Telegram/Slack.
- **Data safety**: every upgrade backs up the database first and stops if the backup fails; daily backups at 03:30
  (kept 7 days); `proxymgr-backup` / `proxymgr-restore`. Events and outages are kept forever (only raw checks expire).
- Version shown in the footer and Settings.

## 1.0
- Dashboard, health checks, use cases, statuses (Ready / Active / Suspended / To delete / Trash), sheet import,
  users, Telegram/Slack alerts.
