"""Use cases <-> proxies, and the proxy status. Shared by the web app and the checker.

Everything here is manual: people pick proxies and set statuses. Nothing is reassigned automatically.

Status (set by people, separate from health):
  ready      🆗  unused — can be given to a use case
  active     ✅  a use case is using it
  suspended  ❌  got suspended on its use case; don't use it for that use case again
                 (it can still be reused for another kind of app)
  to_delete  🗑  not needed any more — delete the VM, then move it to Trash
deleted_at = moved to Trash (VM deleted at the provider). Monitoring stops; the row stays as a record.

Rules: a use case has at most one proxy and a proxy serves at most one use case.
"""
from . import db

LIFECYCLES = {"ready": "🆗 Ready", "active": "✅ Active", "suspended": "❌ Suspended", "to_delete": "🗑 To delete"}


class AssignError(Exception):
    pass


def label(p):
    if not p:
        return "none"
    if p.get("label"):
        return "%s (%s:%s)" % (p["label"], p["host"], p["port"])
    return "%s:%s (%s)" % (p["host"], p["port"], p["provider"])


async def spare_count():
    """Ready + healthy + not in trash = what can be picked for a new use case."""
    return await db.fetchval("""
        SELECT count(*) FROM proxies p
        WHERE p.enabled AND p.status = 'healthy' AND p.lifecycle = 'ready' AND p.deleted_at IS NULL
          AND NOT EXISTS (SELECT 1 FROM apps a WHERE a.proxy_id = p.id)""")


async def _get_proxy(pid):
    return await db.fetchrow("SELECT * FROM proxies WHERE id = $1", pid) if pid else None


def suspended_list(p):
    return [x for x in (p.get("suspended_for") or "").split(",") if x]


async def set_proxy(app, proxy_id, reason="manual"):
    """Point use case `app` at proxy_id (or None).

    The new proxy becomes Active. The old one remembers the use case (last_usecase) and,
    if it was Active, goes back to Ready; other statuses (Suspended, To delete) stay as they are.
    """
    old = await _get_proxy(app.get("proxy_id"))
    new = None
    if proxy_id is not None:
        new = await _get_proxy(int(proxy_id))
        if not new:
            raise AssignError("proxy %s not found" % proxy_id)
        if new["deleted_at"]:
            raise AssignError("%s is in the trash" % label(new))
        other = await db.fetchrow("SELECT name FROM apps WHERE proxy_id = $1 AND id <> $2", new["id"], app["id"])
        if other:
            raise AssignError("%s is already used by %s" % (label(new), other["name"]))
    if (old and old["id"]) == (new and new["id"]):
        return new
    try:
        await db.execute("UPDATE apps SET proxy_id = $2, assigned_at = CASE WHEN $3 THEN now() ELSE NULL END WHERE id = $1",
                         app["id"], new["id"] if new else None, new is not None)
    except Exception as e:  # noqa: BLE001  (unique index: proxy taken concurrently)
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            raise AssignError("%s was just taken by another use case" % label(new))
        raise
    app["proxy_id"] = new["id"] if new else None
    if old:
        await db.execute("""
            UPDATE proxies SET last_usecase = $2,
                lifecycle_at = CASE WHEN lifecycle = 'active' THEN now() ELSE lifecycle_at END,
                lifecycle = CASE WHEN lifecycle = 'active' THEN 'ready' ELSE lifecycle END
            WHERE id = $1""", old["id"], app["name"])
    if new:
        await db.execute("UPDATE proxies SET lifecycle = 'active', lifecycle_at = now(), last_usecase = $2 WHERE id = $1",
                         new["id"], app["name"])
    await db.log_event("assign", "%s: %s -> %s (%s)" % (app["name"], label(old), label(new), reason),
                       new["id"] if new else (old["id"] if old else None), app["id"])
    if old and new:
        await db.log_event("assign", "%s left %s" % (app["name"], label(old)), old["id"], app["id"])
    return new


async def app_on(proxy_id):
    return await db.fetchrow("SELECT * FROM apps WHERE proxy_id = $1", proxy_id)


async def set_usecase(proxy, name):
    """The use case typed in the proxies table. Returns a human message (starts with ⚠️ for warnings)."""
    name = (name or "").strip()
    current = await app_on(proxy["id"])
    if not name:
        if current:
            await set_proxy(current, None, "use case cleared")
            return "%s removed from %s%s." % (current["name"], label(proxy),
                                             " — it's Ready again" if proxy["lifecycle"] == "active" else "")
        return "No use case."
    if current and current["name"] == name:
        return "Unchanged."
    if proxy["deleted_at"]:
        raise AssignError("this proxy is in the trash")
    if current:
        await set_proxy(current, None, "replaced by %s" % name)
    app = await db.fetchrow("SELECT * FROM apps WHERE name = $1", name)
    if not app:
        app = await db.fetchrow("INSERT INTO apps (name) VALUES ($1) RETURNING *", name)
    previous = await _get_proxy(app["proxy_id"])
    await set_proxy(app, proxy["id"], "use case set")
    msg = "%s now on %s — Active." % (name, label(proxy))
    warn = []
    if name in suspended_list(proxy):
        warn.append("this proxy was SUSPENDED on %s before" % name)
    if proxy["enabled"] and proxy["status"] == "dead":
        warn.append("it is currently DOWN (%s)" % (proxy["last_error"] or "failing checks"))
    if warn:
        msg = "⚠️ " + msg + " Careful: " + "; ".join(warn) + "."
    elif proxy["status"] == "unknown":
        msg += " First health check still pending."
    if previous:
        msg += " (Moved from %s.)" % label(previous)
    return msg


async def set_lifecycle(proxy, state):
    """Change the status. Ready frees the proxy (removes its use case); the others keep it as a record."""
    if state not in LIFECYCLES:
        raise AssignError("unknown status %s" % state)
    if proxy["deleted_at"]:
        raise AssignError("proxy is in the trash — restore it first")
    if proxy["lifecycle"] == state:
        return "Unchanged."
    app = await app_on(proxy["id"])
    msg = "%s → %s." % (label(proxy), LIFECYCLES[state])
    if state == "ready" and app:
        await set_proxy(app, None, "status set to Ready")
        msg += " Use case %s removed from it." % app["name"]
    susp = suspended_list(proxy)
    if state == "suspended":
        who = app["name"] if app else proxy["last_usecase"]
        if who and who not in susp:
            susp.append(who)
        if who:
            msg += " Noted: don't use it for %s again." % who
    await db.execute("UPDATE proxies SET lifecycle = $2, lifecycle_at = now(), suspended_for = $3 WHERE id = $1",
                     proxy["id"], state, ",".join(susp))
    await db.log_event("lifecycle", "%s set to %s%s" % (label(proxy), LIFECYCLES[state],
                                                        " (was on %s)" % app["name"] if app else ""), proxy["id"])
    return msg


async def set_deleted(proxy, deleted=True):
    """Move to Trash (VM deleted at the provider — monitoring stops), or restore."""
    if deleted:
        app = await app_on(proxy["id"])
        if app:
            await set_proxy(app, None, "proxy moved to trash")
        await db.execute("UPDATE proxies SET deleted_at = now(), enabled = false, recheck = false WHERE id = $1", proxy["id"])
        await db.execute("UPDATE incidents SET ended_at = now(), end_note = 'moved to trash' "
                         "WHERE proxy_id = $1 AND ended_at IS NULL", proxy["id"])
        await db.log_event("lifecycle", "%s moved to trash (VM deleted)" % label(proxy), proxy["id"])
        return "%s moved to trash — monitoring stopped.%s" % (
            label(proxy), " %s no longer has a proxy." % app["name"] if app else "")
    await db.execute("""UPDATE proxies SET deleted_at = NULL, enabled = true, status = 'unknown', fail_streak = 0,
                        ok_streak = 0, recheck = true WHERE id = $1""", proxy["id"])
    await db.log_event("lifecycle", "%s restored from trash, monitoring again" % label(proxy), proxy["id"])
    return "%s restored — monitoring again." % label(proxy)


async def waste():
    """Marked 'to delete' but the VM still exists (not in trash) — still costing money."""
    return await db.fetch("""
        SELECT * FROM proxies WHERE lifecycle = 'to_delete' AND deleted_at IS NULL ORDER BY lifecycle_at NULLS FIRST""")
