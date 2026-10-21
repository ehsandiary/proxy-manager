# Proxy Manager

A small self-hosted dashboard for a fleet of your own HTTP(S) proxies (Squid on cheap VMs at any provider). It keeps the inventory, health-checks every proxy, and tracks which use case each proxy serves.

- **Inventory like a spreadsheet:** # · Name · Use case · Status · Health · IP:Port · Provider · Region, edited inline. Import by pasting rows from a sheet.
- **Statuses:** 🆗 Ready → ✅ Active → ❌ Suspended → 🗑 To delete → Trash. People decide; nothing is reassigned automatically.
- **Health checks:** an HTTPS request through every proxy every 30s. A proxy is marked down after 3 failures in a row. If almost every proxy fails at once, that's treated as your own network's problem and statuses aren't changed.
- **Health page:**
  - every outage, with duration and reason (timeout, refused, wrong password, …);
  - flaky proxies that fail some checks without going down;
  - a per-provider comparison of failure rate, outages, speed and price.
- **Events:** a searchable history of who did what and when, exportable to CSV.
- **Alerts:** Telegram and/or Slack messages that name the use case, plus an optional daily summary.
- **Cost:** a monthly price per provider, giving totals per provider and per status.
- **Users:** admins and normal users; every change is stamped with who made it.
- **Data safety:**
  - every upgrade backs up the database first, and stops if the backup fails;
  - daily backups;
  - one-command restore.

Stack: Python (Starlette + asyncpg), PostgreSQL, nginx, systemd. Runs on Ubuntu 24.04 / 26.04.

## Install

```bash
./build.sh                                   # creates dist/proxymgr-install.sh (installer with the app inside)
sudo bash dist/proxymgr-install.sh --domain proxies.example.com --email you@example.com
```

Every option is optional; run `sudo bash dist/proxymgr-install.sh --help` to see them. The installer prints the dashboard URL and first login, and saves them to `/root/proxymgr-credentials.txt`.

Settings live in `/etc/proxymgr/proxymgr.env` on the server, never in this repository.

## Upgrade

```bash
git pull
./build.sh && sudo bash dist/proxymgr-install.sh
```

1. The database is backed up first. If that fails, nothing is changed.
2. The app is replaced. Database changes only add things; existing data is never modified or removed.
3. If the new version doesn't start, the installer prints the one command to go back to the previous version.

## Backups

| Command | What it does |
|---|---|
| `sudo proxymgr-backup` | full backup now (default folder `/var/backups/proxymgr`) |
| (automatic) | daily at 03:30, kept `BACKUP_KEEP_DAYS` (7) days; the last 5 pre-upgrade backups are kept |
| `sudo proxymgr-restore FILE` | replace the database with a backup; takes a safety backup of the current one first |

Copy backups off the server from time to time. They contain proxy passwords, so keep them private.

## Daily use

- **Add proxies:** paste sheet rows (# · Name · Region · User:Pass · IP:Port · Use case · Status) on **Add**. Re-pasting updates rows instead of duplicating them.
- **Assign:** type a use case in a 🆗 Ready row and press Enter; it becomes ✅ Active.
- **Burned proxy:** set ❌ Suspended. It remembers what it was suspended on, and warns if it's given to that use case again.
- **Not needed:** set 🗑 To delete, delete the VM at the provider, then **Move to trash**. Until then you get a daily reminder of what it costs.
- **Investigate:** use **Health** for outages and flaky proxies, and **Events** for the full history.

## Operations

| Task | Command |
|---|---|
| Logs | `journalctl -u proxymgr-api -u proxymgr-checker -f` |
| Restart after editing settings | `sudo systemctl restart proxymgr-api proxymgr-checker` |
| Reset a password / add an admin | `sudo proxymgr-user set NAME [--admin]` |
| Users list | `sudo proxymgr-user list` |

## Repository layout

```
app/            web app (main.py), health checker (checker.py), outages (health.py), templates, static
tools/          proxymgr-backup, proxymgr-restore (installed to /usr/local/sbin)
install-main.sh installer / upgrader (build.sh appends the app to it)
build.sh        builds dist/proxymgr-install.sh
VERSION, CHANGELOG.md
```
