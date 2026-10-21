"""Health-check worker. Run as: python -m app.checker"""
import asyncio
import logging
import signal
import time

from . import alerts, assign, db, health
from .config import settings
from .probe import check_proxy, direct_http_ok

log = logging.getLogger("proxymgr.checker")

UPDATE_SQL = """
UPDATE proxies SET
    last_check_at = now(),
    http_ok = $2, smtp_ok = $3,
    last_latency_ms = $4, smtp_latency_ms = $5,
    last_error = $6,
    exit_ip = COALESCE($7, exit_ip),
    fail_streak = $8, ok_streak = $9,
    status_changed_at = CASE WHEN status <> $10 THEN now() ELSE status_changed_at END,
    status = $10,
    last_ok_at = CASE WHEN $11 THEN now() ELSE last_ok_at END
WHERE id = $1
"""

INSERT_CHECK_SQL = """
INSERT INTO checks (proxy_id, ok, http_ok, smtp_ok, latency_ms, smtp_latency_ms, error, exit_ip, mass)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
"""


def name_of(p):
    if p.get("label"):
        return "%s %s:%s" % (p["label"], p["host"], p["port"])
    return "%s:%s (%s)" % (p["host"], p["port"], p["provider"])

def next_state(p, ok):
    """Return (status, fail_streak, ok_streak)."""
    status = p["status"]
    if ok:
        oks, fails = p["ok_streak"] + 1, 0
        if status != "healthy" and (status == "unknown" or oks >= settings.recover_threshold):
            status = "healthy"
    else:
        oks, fails = 0, p["fail_streak"] + 1
        if status != "dead" and fails >= settings.fail_threshold:
            status = "dead"
    return status, fails, oks


async def check_rows(rows, guard=True):
    if not rows:
        return
    sem = asyncio.Semaphore(settings.check_concurrency)

    async def one(p):
        async with sem:
            return p, await check_proxy(p)

    results = await asyncio.gather(*(one(p) for p in rows))

    failed = sum(1 for _, r in results if not r["ok"])
    mass = bool(guard and len(results) >= settings.mass_failure_min and failed / len(results) >= settings.mass_failure_ratio)
    check_rows_data = [
        (p["id"], r["ok"], r["http_ok"], r["smtp_ok"], r["latency_ms"], r["smtp_latency_ms"], r["error"], r["exit_ip"],
         mass and not r["ok"])
        for p, r in results
    ]
    await db.executemany(INSERT_CHECK_SQL, check_rows_data)

    if mass:
        # Almost everything failed at once: most likely the check target or our own
        # network, not the proxies. Record the checks but don't flip statuses.
        sample = next((r["error"] for _, r in results if r["error"]), "")
        msg = "Mass failure: %d/%d proxies failed this round. Statuses left unchanged. Sample error: %s" % (
            failed, len(results), sample)
        log.warning(msg)
        await db.log_event("mass_failure", msg)
        await alerts.send("⚠️ " + msg, key="mass_failure")
        return

    updates, went_dead, went_up, still_down = [], [], [], []
    for p, r in results:
        status, fails, oks = next_state(p, r["ok"])
        updates.append((p["id"], r["http_ok"], r["smtp_ok"], r["latency_ms"], r["smtp_latency_ms"], r["error"],
                        r["exit_ip"], fails, oks, status, r["ok"]))
        if status != p["status"]:
            if status == "dead":
                went_dead.append((p, r))
            elif status == "healthy" and p["status"] == "dead":
                went_up.append((p, r))
            await db.log_event("status", "%s: %s -> %s%s" % (name_of(p), p["status"], status,
                                                              " (%s)" % r["error"] if r["error"] else ""), p["id"])
        elif status == "dead" and r["error"]:
            still_down.append((p["id"], r["error"][:500]))
    await db.executemany(UPDATE_SQL, updates)
    if went_dead:
        used = await apps_by_proxy([p["id"] for p, _ in went_dead])
        for p, r in went_dead:
            await health.open_incident(p, r["error"], used[p["id"]]["name"] if p["id"] in used else p.get("last_usecase"))
    for p, _ in went_up:
        await health.close_incident(p["id"], "recovered")
    await health.touch_open(still_down)
    await report_transitions(went_dead, went_up)


async def apps_by_proxy(ids):
    if not ids:
        return {}
    rows = await db.fetch("SELECT * FROM apps WHERE proxy_id = ANY($1::int[])", list(ids))
    return {a["proxy_id"]: a for a in rows}


async def report_transitions(went_dead, went_up):
    # suspended / to-delete proxies are out of service: no alerts for them
    went_dead = [(p, r) for p, r in went_dead if p.get("lifecycle") not in ("suspended", "to_delete")]
    went_up = [(p, r) for p, r in went_up if p.get("lifecycle") not in ("suspended", "to_delete")]
    if not went_dead and not went_up:
        return
    used = await apps_by_proxy([p["id"] for p, _ in went_dead] + [p["id"] for p, _ in went_up])
    lines = []

    dead_used = [(p, r) for p, r in went_dead if p["id"] in used]
    dead_free = [(p, r) for p, r in went_dead if p["id"] not in used]
    if dead_used:
        lines.append("🔴 %d active proxy(ies) DOWN:" % len(dead_used))
        for p, r in dead_used[:40]:
            app = used[p["id"]]
            lines.append("• %s — %s — %s" % (app["name"], name_of(p), r["error"] or "?"))
    if dead_free:
        lines.append("🔴 %d ready (unused) proxy(ies) down: %s" % (
            len(dead_free), ", ".join(name_of(p) for p, _ in dead_free[:20]) + (" …" if len(dead_free) > 20 else "")))
    if went_up:
        names = ["%s%s" % (name_of(p), " [%s]" % used[p["id"]]["name"] if p["id"] in used else "") for p, _ in went_up[:20]]
        lines.append("🟢 %d proxy(ies) recovered: %s" % (len(went_up), ", ".join(names)))
    await alerts.send("\n".join(lines))


async def waste_alert():
    """Once a day: proxies marked 'to delete' whose VM still exists are still billed."""
    rows = [p for p in await assign.waste()
            if p["lifecycle_at"] is None
            or (time.time() - p["lifecycle_at"].timestamp()) > settings.waste_after_hours * 3600]
    if not rows:
        return
    cost = len(rows) * settings.proxy_monthly_cost
    lines = ["🗑 %d proxy(ies) marked TO DELETE still exist at the provider (~$%.0f/month wasted). "
             "Delete the VMs, then 'Move to trash' on the dashboard:" % (len(rows), cost)]
    lines += ["• %s (%s%s)" % (name_of(p), p["provider"], ", was " + p["last_usecase"] if p["last_usecase"] else "")
              for p in rows[:40]]
    await alerts.send("\n".join(lines), key="waste", cooldown=86400)


async def pool_alert():
    await waste_alert()
    if settings.min_spares > 0:
        spare = await assign.spare_count()
        if spare < settings.min_spares:
            await alerts.send("🚨 Only %d Ready + healthy proxies left to pick from (minimum %d). Add proxies." % (
                spare, settings.min_spares), key="spares_low")
    if settings.min_healthy <= 0:
        return
    healthy = await db.fetchval("SELECT count(*) FROM proxies WHERE enabled AND status = 'healthy'")
    if healthy < settings.min_healthy:
        await alerts.send("🚨 Healthy proxy pool is low: %d (minimum %d)" % (healthy, settings.min_healthy),
                          key="pool_low")
    elif alerts._last_sent.get("pool_low"):
        alerts.reset("pool_low")
        await alerts.send("✅ Healthy proxy pool back to %d" % healthy)


async def full_round():
    ok, err = (True, None)
    if "http" in settings.check_modes:
        ok, err = await direct_http_ok()
    if not ok:
        msg = "Main server cannot reach %s directly (%s). Skipping this round." % (settings.check_url, err)
        log.warning(msg)
        await alerts.send("⚠️ " + msg, key="direct_fail")
        return
    rows = await db.fetch("SELECT * FROM proxies WHERE enabled ORDER BY id")
    t0 = time.monotonic()
    await check_rows(rows, guard=True)
    await pool_alert()
    await db.set_meta("last_round_at", str(time.time()))
    await db.set_meta("last_round_seconds", "%.1f" % (time.monotonic() - t0))
    log.info("round done: %d proxies in %.1fs", len(rows), time.monotonic() - t0)


async def daily_summary():
    """Plain-text summary of the last 24h (used for the daily message and 'Send one now')."""
    r = health.reason_sql("c.error")
    down = await db.fetch("""
        SELECT p.label, p.host, p.port, p.lifecycle, a.name AS usecase, i.reason, i.started_at
        FROM incidents i JOIN proxies p ON p.id = i.proxy_id LEFT JOIN apps a ON a.proxy_id = p.id
        WHERE i.ended_at IS NULL AND p.deleted_at IS NULL AND p.lifecycle IN ('active', 'ready')
        ORDER BY (p.lifecycle = 'active') DESC, i.started_at""")
    outages = await db.fetch("""SELECT reason, count(*) AS n FROM incidents WHERE started_at > now() - interval '24 hours'
                                GROUP BY 1 ORDER BY 2 DESC""")
    flaky = await db.fetch("""
        WITH s AS (SELECT c.proxy_id, count(*) AS checks, count(*) FILTER (WHERE NOT c.ok) AS failed,
                          count(*) FILTER (WHERE NOT c.ok AND {r} = 'timeout') AS timeouts
                   FROM checks c WHERE c.ts > now() - interval '24 hours' AND NOT c.mass GROUP BY 1)
        SELECT p.label, p.host, p.provider, a.name AS usecase, s.failed, s.checks, s.timeouts,
               round(100.0 * s.failed / s.checks, 1) AS pct
        FROM s JOIN proxies p ON p.id = s.proxy_id LEFT JOIN apps a ON a.proxy_id = p.id
        WHERE s.failed > 0 AND p.deleted_at IS NULL AND p.status <> 'dead' AND p.lifecycle IN ('active', 'ready')
        ORDER BY pct DESC LIMIT 10""".format(r=r))
    prov = await db.fetch("""
        SELECT p.provider, count(*) AS checks, count(*) FILTER (WHERE NOT c.ok) AS failed
        FROM checks c JOIN proxies p ON p.id = c.proxy_id
        WHERE c.ts > now() - interval '24 hours' AND NOT c.mass AND p.deleted_at IS NULL
        GROUP BY 1 ORDER BY 1""")
    waste = await assign.waste()
    last_b = await db.get_meta("last_backup")
    lines = ["📋 Proxy summary — last 24h"]
    lines.append("")
    if down:
        lines.append("🔴 Down now: %d" % len(down))
        lines += ["• %s%s — %s, %s" % (name_of(d), " [%s]" % d["usecase"] if d["usecase"] else "",
                                        health.LABELS.get(d["reason"], d["reason"]), _since(d["started_at"]))
                  for d in down[:15]]
    else:
        lines.append("🟢 Nothing down right now")
    if outages:
        lines.append("Outages: " + ", ".join("%s %d" % (health.LABELS.get(o["reason"], o["reason"]), o["n"]) for o in outages))
    if flaky:
        lines.append("")
        lines.append("⚠️ Flakiest (up, but failed checks):")
        lines += ["• %s%s — %s%% failed (%d timeouts)" % (f["label"] or f["host"], " [%s]" % f["usecase"] if f["usecase"] else "",
                                                       f["pct"], f["timeouts"]) for f in flaky]
    if prov:
        lines.append("")
        lines.append("Providers (failed checks): " + ", ".join(
            "%s %.2f%%" % (p["provider"], 100.0 * p["failed"] / p["checks"]) for p in prov if p["checks"]))
    if waste:
        lines.append("")
        lines.append("🗑 %d marked To delete still running: %s" % (len(waste), ", ".join(name_of(w) for w in waste[:10])))
    if last_b and last_b.count("|") >= 2:
        age_h = (time.time() - int(last_b.split("|")[0])) / 3600
        lines.append("")
        lines.append(("💾 Last backup %.0fh ago" % age_h) + (" ⚠️ check backups!" if age_h > 36 else ""))
    return "\n".join(lines)


def _since(ts):
    secs = int(time.time() - ts.timestamp())
    return "for %dh %02dm" % (secs // 3600, secs % 3600 // 60) if secs >= 3600 else "for %dm" % (secs // 60)


async def maybe_daily_summary():
    hour = await db.get_meta("digest_hour", "")
    if not hour or not hour.isdigit():
        return
    now = time.gmtime()
    today = time.strftime("%Y-%m-%d", now)
    if now.tm_hour != int(hour) or await db.get_meta("digest_last") == today:
        return
    await db.set_meta("digest_last", today)
    await alerts.send(await daily_summary())


async def cleanup():
    await db.execute("DELETE FROM checks WHERE ts < now() - make_interval(days => $1)", settings.retention_days)
    await db.execute("DELETE FROM reports WHERE ts < now() - make_interval(days => $1)", settings.retention_days)
    # events and incidents are kept forever (small); only raw checks/reports are trimmed


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    await db.init_pool()
    await db.apply_schema()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    log.info("checker started: every %ss, modes=%s, timeout=%ss", settings.check_interval,
             ",".join(settings.check_modes), settings.check_timeout)
    last_round, last_cleanup, last_digest = 0.0, 0.0, 0.0
    while not stop.is_set():
        now = time.monotonic()
        try:
            if now - last_round >= settings.check_interval:
                last_round = now
                await full_round()
            else:
                # on-demand rechecks (dashboard button / app failure reports)
                rows = await db.fetch("UPDATE proxies SET recheck = false WHERE recheck AND enabled RETURNING *")
                if rows:
                    await check_rows(rows, guard=False)
            if now - last_cleanup >= 3600:
                last_cleanup = now
                await cleanup()
            if now - last_digest >= 60:
                last_digest = now
                await maybe_daily_summary()
        except Exception:  # noqa: BLE001
            log.exception("checker loop error")
            await asyncio.sleep(5)
        try:
            await asyncio.wait_for(stop.wait(), timeout=2)
        except asyncio.TimeoutError:
            pass
    await db.close_pool()


if __name__ == "__main__":
    asyncio.run(main())
