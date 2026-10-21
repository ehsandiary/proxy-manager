"""Outages (incidents), failure reasons and flaky-proxy statistics."""
import re

from . import db

# (key, label, regex on the error text) — first match wins
REASONS = [
    ("timeout", "Timeout", r"timeout|timed out"),
    ("auth", "Wrong password (407)", r"407|auth rejected"),
    ("unreachable", "Unreachable", r"unreachable|no route|name or service|not known"),
    ("refused", "Connection refused", r"refused|connect call failed|connect to proxy failed"),
    ("blocked", "Blocked by proxy (403)", r"connect 403|not allowed|ruleset"),
    ("tls", "TLS error", r"tls|ssl|certificate"),
    ("proxy_error", "Proxy error", r"closed the connection|bad response|connect \d{3}|target: http"),
]
LABELS = dict((k, l) for k, l, _ in REASONS)
LABELS["other"] = "Other"
_COMPILED = [(k, re.compile(rx, re.I)) for k, _, rx in REASONS]


def classify(error):
    for key, rx in _COMPILED:
        if error and rx.search(error):
            return key
    return "other"


def reason_sql(col="error"):
    """The same classification as a SQL CASE expression (for grouping raw checks)."""
    parts = ["WHEN %s ~* '%s' THEN '%s'" % (col, rx.replace("'", "''"), k) for k, _, rx in REASONS]
    return "(CASE %s ELSE 'other' END)" % " ".join(parts)


async def open_incident(p, error, usecase):
    await db.execute("""
        INSERT INTO incidents (proxy_id, started_at, reason, error, last_error, usecase, lifecycle)
        VALUES ($1, now(), $2, $3, $3, $4, $5)
        ON CONFLICT (proxy_id) WHERE ended_at IS NULL DO UPDATE SET last_error = EXCLUDED.last_error
    """, p["id"], classify(error), (error or "")[:500], usecase or "", p.get("lifecycle") or "")


async def close_incident(proxy_id, note):
    await db.execute("UPDATE incidents SET ended_at = now(), end_note = $2 WHERE proxy_id = $1 AND ended_at IS NULL",
                     proxy_id, note)


async def touch_open(rows):
    """rows: (proxy_id, error) for proxies still down — keep the latest error on the open incident."""
    await db.executemany("UPDATE incidents SET last_error = $2 WHERE proxy_id = $1 AND ended_at IS NULL "
                         "AND last_error IS DISTINCT FROM $2", rows)


STATUS_RE = re.compile(r": (\w+) -> (\w+)(?: \((.*)\))?$", re.S)


async def backfill(conn):
    """One-time: rebuild past outages from the status-change events already in the database."""
    rows = await conn.fetch("""
        SELECT e.proxy_id, e.ts, e.message FROM events e JOIN proxies p ON p.id = e.proxy_id
        WHERE e.kind = 'status' ORDER BY e.proxy_id, e.ts, e.id""")
    proxies = {r["id"]: dict(r) for r in await conn.fetch("SELECT * FROM proxies")}
    open_, out = {}, []
    for r in rows:
        m = STATUS_RE.search(r["message"])
        if not m:
            continue
        frm, to, err = m.group(1), m.group(2), m.group(3) or ""
        pid = r["proxy_id"]
        if to == "dead" and pid not in open_:
            open_[pid] = [pid, r["ts"], None, classify(err), err[:500], err[:500], "", ""]
        elif to != "dead" and pid in open_:
            inc = open_.pop(pid)
            inc[2], inc[7] = r["ts"], "recovered"
            out.append(inc)
    for pid, inc in open_.items():
        p = proxies.get(pid)
        if p is None:
            continue
        if p["deleted_at"] or not p["enabled"]:
            inc[2], inc[7] = p["deleted_at"] or p["status_changed_at"], "monitoring stopped"
        elif p["status"] != "dead":
            inc[2], inc[7] = p["status_changed_at"], "recovered"
        out.append(inc)
    for inc in out:
        p = proxies.get(inc[0]) or {}
        inc[6] = p.get("last_usecase") or ""
    if out:
        await conn.executemany("""
            INSERT INTO incidents (proxy_id, started_at, ended_at, reason, error, last_error, usecase, end_note, backfilled)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true) ON CONFLICT DO NOTHING""", [tuple(i) for i in out])
    return len(out)
