"""Web app: dashboard + JSON API. Run with: uvicorn app.main:app"""
import contextlib
import functools
import ipaddress
import json
import os
import random
import re
import secrets
from datetime import datetime, timezone

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from . import alerts, assign, db, health
from .config import settings
from .security import LoginLimiter, csrf_token, hash_password, key_ok, verify_password

HERE = os.path.dirname(os.path.abspath(__file__))
try:
    APP_VERSION = open(os.path.join(HERE, "..", "VERSION")).read().strip()
except OSError:
    APP_VERSION = "dev"
templates = Jinja2Templates(directory=os.path.join(HERE, "templates"))
limiter = LoginLimiter()

STATUSES = ("healthy", "dead", "unknown")
SORTS = {
    "num": "p.seq", "id": "p.id", "host": "(CASE WHEN p.host ~ '^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$' THEN p.host::inet END)", "provider": "p.provider", "status": "p.status", "name": "NULLIF(p.label, '')",
    "life": "p.lifecycle", "region": "p.region", "usecase": "COALESCE(a.name, p.last_usecase)",
    "latency": "p.last_latency_ms", "uptime": "u.uptime", "checked": "p.last_check_at",
    "reports": "r.n", "app": "a.name",
}


# ---------- helpers ----------

def ago(dt):
    if not dt:
        return "never"
    if isinstance(dt, str):
        return dt
    s = int((datetime.now(timezone.utc) - dt).total_seconds())
    if s < 0:
        s = 0
    if s < 60:
        return "%ds ago" % s
    if s < 3600:
        return "%dm ago" % (s // 60)
    if s < 86400:
        return "%dh ago" % (s // 3600)
    return "%dd ago" % (s // 86400)


def fmt_ts(dt):
    if not dt:
        return ""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def dur(secs):
    if secs is None:
        return ""
    secs = int(secs)
    if secs < 60:
        return "%ds" % secs
    if secs < 3600:
        return "%dm %02ds" % (secs // 60, secs % 60) if secs < 600 else "%dm" % (secs // 60)
    if secs < 86400:
        return "%dh %02dm" % (secs // 3600, secs % 3600 // 60)
    return "%dd %dh" % (secs // 86400, secs % 86400 // 3600)


templates.env.filters["ago"] = ago
templates.env.filters["dur"] = dur
templates.env.filters["ts"] = fmt_ts


def client_ip(request):
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "")


def base_url(request):
    if settings.base_url:
        return settings.base_url
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return "%s://%s" % (proto, request.headers.get("host", request.url.netloc))


def flash(request, msg, kind="ok"):
    request.session.setdefault("flash", []).append([kind, msg])


def render(request, name, **ctx):
    u = request.scope.get("pm_user") or {}
    ctx.update(user=request.session.get("user"), is_admin=bool(u.get("is_admin")), csrf=csrf_token(request.session),
               app_version=APP_VERSION,
               flashes=request.session.pop("flash", []), nav=name.split(".")[0])
    return templates.TemplateResponse(request, name, ctx)


def _pw_stamp(u):
    return u["pw_changed_at"].isoformat() if u and u["pw_changed_at"] else ""


async def _session_user(request):
    """The logged-in user, re-checked against the DB on every request (deleted users and
    password resets end existing sessions)."""
    name = request.session.get("user")
    if not name:
        return None
    u = await db.fetchrow("SELECT * FROM users WHERE username = $1", name)
    if not u or request.session.get("pw") != _pw_stamp(u):
        request.session.clear()
        return None
    return u


def login_required(fn, admin=False):
    @functools.wraps(fn)
    async def wrapper(request):
        u = await _session_user(request)
        if not u:
            return RedirectResponse("/login?next=" + request.url.path, status_code=303)
        if admin and not u["is_admin"]:
            flash(request, "Only admins can open that page.", "err")
            return RedirectResponse("/", status_code=303)
        request.scope["pm_user"] = u
        db.current_actor.set(u["username"])
        if request.method == "POST":
            form = await request.form()
            if not secrets.compare_digest(str(form.get("csrf", "")), request.session.get("csrf", "")):
                return PlainTextResponse("CSRF check failed — reload the page and try again.", status_code=400)
        return await fn(request)
    return wrapper


def admin_required(fn):
    return login_required(fn, admin=True)


def api_auth(fn):
    @functools.wraps(fn)
    async def wrapper(request):
        key = request.headers.get("x-api-key") or request.query_params.get("key")
        if not settings.api_keys or not key_ok(key, settings.api_keys):
            return JSONResponse({"error": "invalid or missing API key"}, status_code=401)
        return await fn(request)
    return wrapper


def proxy_url(p):
    scheme = "socks5" if p["protocol"] == "socks5" else "http"
    if p["username"]:
        return "%s://%s:%s@%s:%s" % (scheme, p["username"], p["password"], p["host"], p["port"])
    return "%s://%s:%s" % (scheme, p["host"], p["port"])


def proxy_public(p):
    return {
        "id": p["id"], "protocol": p["protocol"], "host": p["host"], "port": p["port"],
        "username": p["username"], "password": p["password"], "url": proxy_url(p),
        "provider": p["provider"], "country": p["country"], "region": p["region"], "label": p["label"],
        "status": p["status"], "latency_ms": p["last_latency_ms"], "smtp_ok": p["smtp_ok"],
        "smtp_latency_ms": p["smtp_latency_ms"], "exit_ip": p["exit_ip"],
        "last_check_at": p["last_check_at"].isoformat() if p["last_check_at"] else None,
        "app": p.get("app_name"),
    }


def clean(s, n=64):
    return re.sub(r"[^\w .:@/+-]", "", str(s or "")).strip()[:n]


async def allowed_cidrs():
    """CIDRs allowed to reach the proxy ports on nodes. Empty user list -> open to everyone."""
    raw = await db.get_meta("allowed_cidrs", settings.default_client_cidrs)
    out = set()
    for part in re.split(r"[\s,]+", raw or ""):
        if part:
            try:
                out.add(str(ipaddress.ip_network(part, strict=False)))
            except ValueError:
                pass
    if not out:
        return ["0.0.0.0/0"]
    if settings.public_ip:
        try:
            out.add(str(ipaddress.ip_network(settings.public_ip, strict=False)))
        except ValueError:
            pass
    return sorted(out)


LINE_RE = re.compile(r"^(?:(?P<scheme>socks5h?|socks|https?)://)?(?P<rest>.+)$", re.I)


def parse_proxy_line(line, default_protocol):
    """Accepts host:port, host:port:user:pass, user:pass@host:port, scheme://user:pass@host:port."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = LINE_RE.match(line)
    scheme, rest = m.group("scheme"), m.group("rest")
    protocol = default_protocol
    if scheme:
        protocol = "socks5" if scheme.lower().startswith("socks") else "http"
    user = pw = ""
    if "@" in rest:
        cred, hp = rest.rsplit("@", 1)
        user, _, pw = cred.partition(":")
        host, _, port = hp.rpartition(":")
    else:
        parts = rest.split(":")
        if len(parts) == 2:
            host, port = parts
        elif len(parts) >= 4:
            host, port, user, pw = parts[0], parts[1], parts[2], ":".join(parts[3:])
        else:
            raise ValueError("unrecognised format")
    host = host.strip().strip("[]")
    if not host or not port.strip().isdigit() or not (0 < int(port) < 65536):
        raise ValueError("bad host or port")
    return {"protocol": protocol, "host": host, "port": int(port), "username": user, "password": pw}


# ---------- auth pages ----------

async def login(request):
    if request.method == "GET":
        return render(request, "login.html", next=request.query_params.get("next", "/"))
    form = await request.form()
    ip = client_ip(request)
    nxt = str(form.get("next") or "/")
    if not nxt.startswith("/") or nxt.startswith("//"):
        nxt = "/"
    if limiter.blocked(ip):
        flash(request, "Too many failed attempts. Try again in 15 minutes.", "err")
        return RedirectResponse("/login", status_code=303)
    user, pw = str(form.get("username", "")).strip().lower(), str(form.get("password", ""))
    u = await db.fetchrow("SELECT * FROM users WHERE username = $1", user)
    if u and verify_password(pw, u["pass_hash"]):
        limiter.clear(ip)
        request.session.clear()
        request.session["user"] = u["username"]
        request.session["pw"] = _pw_stamp(u)
        await db.execute("UPDATE users SET last_login_at = now() WHERE id = $1", u["id"])
        return RedirectResponse(nxt, status_code=303)
    if not u:
        verify_password(pw, "scrypt:00:00")  # same timing whether or not the user exists
    limiter.fail(ip)
    flash(request, "Wrong username or password.", "err")
    return RedirectResponse("/login?next=" + nxt, status_code=303)


async def logout(request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ---------- dashboard ----------

LIFE_FILTERS = ("live", "active", "ready", "suspended", "to_delete", "trash", "all")


@login_required
async def dashboard(request):
    q = request.query_params
    where, args = [], []

    def arg(v):
        args.append(v)
        return "$%d" % len(args)

    life = q.get("life", "live")
    if life == "live":
        where.append("p.deleted_at IS NULL")
    elif life in ("active", "ready", "suspended", "to_delete"):
        where.append("p.deleted_at IS NULL AND p.lifecycle = " + arg(life))
    elif life in ("trash", "deleted"):
        life = "trash"
        where.append("p.deleted_at IS NOT NULL")
    status = q.get("status", "")
    if status in STATUSES:
        where.append("p.enabled AND p.status = " + arg(status))
    elif status == "disabled":
        where.append("NOT p.enabled AND p.deleted_at IS NULL")
    if q.get("spare") == "1":
        where.append("p.enabled AND p.status = 'healthy' AND p.lifecycle = 'ready' AND a.id IS NULL")
    if q.get("provider"):
        where.append("p.provider = " + arg(q["provider"]))
    if q.get("country"):
        where.append("p.country = " + arg(q["country"]))
    if q.get("protocol") in ("http", "socks5"):
        where.append("p.protocol = " + arg(q["protocol"]))
    if q.get("smtp") == "fail":
        where.append("p.smtp_ok = false")
    if q.get("q"):
        like = arg("%" + q["q"] + "%")
        where.append("(p.host ILIKE {0} OR p.label ILIKE {0} OR p.notes ILIKE {0} OR p.exit_ip ILIKE {0} "
                     "OR a.name ILIKE {0} OR p.last_usecase ILIKE {0} OR p.region ILIKE {0})".format(like))
    sort = q.get("sort", "num")
    order = SORTS.get(sort, "p.num")
    direction = "DESC" if q.get("dir") == "desc" else "ASC"
    sql = """
        SELECT p.*, COALESCE(r.n, 0) AS reports_24h, u.uptime, a.name AS app_name, a.id AS app_id
        FROM (SELECT *, seq AS num FROM proxies) p
        LEFT JOIN apps a ON a.proxy_id = p.id
        LEFT JOIN (SELECT proxy_id, count(*) AS n FROM reports
                   WHERE ts > now() - interval '24 hours' GROUP BY proxy_id) r ON r.proxy_id = p.id
        LEFT JOIN (SELECT proxy_id, round(avg(ok::int) * 100, 1) AS uptime FROM checks
                   WHERE ts > now() - interval '24 hours' GROUP BY proxy_id) u ON u.proxy_id = p.id
        %s
        ORDER BY %s %s NULLS LAST, p.seq, p.id
    """ % ("WHERE " + " AND ".join(where) if where else "", order, direction)
    rows = await db.fetch(sql, *args)

    summary = await db.fetchrow("""
        SELECT count(*) FILTER (WHERE deleted_at IS NULL AND lifecycle = 'active') AS active,
               count(*) FILTER (WHERE deleted_at IS NULL AND lifecycle = 'active' AND enabled AND status = 'dead') AS active_dead,
               count(*) FILTER (WHERE deleted_at IS NULL AND lifecycle = 'ready') AS ready,
               count(*) FILTER (WHERE deleted_at IS NULL AND lifecycle = 'suspended') AS suspended,
               count(*) FILTER (WHERE deleted_at IS NULL AND lifecycle = 'to_delete') AS waste,
               count(*) FILTER (WHERE deleted_at IS NOT NULL) AS deleted,
               count(*) FILTER (WHERE deleted_at IS NULL AND enabled AND status = 'healthy') AS healthy,
               count(*) FILTER (WHERE deleted_at IS NULL AND enabled AND status = 'dead') AS dead,
               count(*) FILTER (WHERE deleted_at IS NULL AND enabled AND status = 'unknown') AS unknown,
               count(*) FILTER (WHERE deleted_at IS NULL) AS live,
               round(avg(last_latency_ms) FILTER (WHERE enabled AND status = 'healthy')) AS avg_latency,
               count(*) FILTER (WHERE enabled AND smtp_ok) AS smtp_ok,
               count(*) FILTER (WHERE enabled AND smtp_ok = false) AS smtp_fail
        FROM proxies
    """)
    summary["spare"] = await assign.spare_count()
    summary["waste_cost"] = summary["waste"] * settings.proxy_monthly_cost
    providers = await db.fetch("""
        SELECT provider, count(*) AS total,
               count(*) FILTER (WHERE enabled AND status = 'healthy') AS healthy,
               count(*) FILTER (WHERE enabled AND status = 'dead') AS dead,
               count(*) FILTER (WHERE lifecycle = 'active') AS n_active,
               count(*) FILTER (WHERE lifecycle = 'ready') AS n_ready,
               count(*) FILTER (WHERE lifecycle IN ('suspended', 'to_delete')) AS n_idle,
               count(*) FILTER (WHERE lifecycle = 'to_delete') AS n_to_delete
        FROM proxies WHERE deleted_at IS NULL GROUP BY provider ORDER BY provider
    """)
    prices = await provider_prices()
    cost = {"total": 0.0, "active": 0.0, "ready": 0.0, "idle": 0.0, "unpriced": []}
    for pr in providers:
        price = prices.get(pr["provider"])
        pr["price"] = price
        pr["cost"] = price * pr["total"] if price is not None else None
        if price is None:
            cost["unpriced"].append(pr["provider"])
            continue
        cost["total"] += pr["cost"]
        cost["active"] += price * pr["n_active"]
        cost["ready"] += price * pr["n_ready"]
        cost["idle"] += price * pr["n_idle"]
    summary["waste_cost"] = sum((pr["price"] or settings.proxy_monthly_cost) * pr["n_to_delete"] for pr in providers)
    last_round = await db.get_meta("last_round_at")
    last_round_secs = await db.get_meta("last_round_seconds")
    checker_age = None
    if last_round:
        checker_age = int(datetime.now(timezone.utc).timestamp() - float(last_round))
    events = await db.fetch("SELECT * FROM events ORDER BY ts DESC LIMIT 8")
    return render(request, "dashboard.html", rows=rows, summary=summary, providers=providers,
                  q=q, life=life, sort=sort, dir=direction.lower(), checker_age=checker_age,
                  last_round_secs=last_round_secs, events=events, interval=settings.check_interval,
                  modes=settings.check_modes, lifecycles=assign.LIFECYCLES, cost=cost)


@login_required
async def proxy_quick(request):
    """Inline edits from the proxies table: use case or status. Returns JSON."""
    pid = int(request.path_params["pid"])
    form = await request.form()
    p = await db.fetchrow("SELECT * FROM proxies WHERE id = $1", pid)
    if not p:
        return JSONResponse({"ok": False, "msg": "proxy not found"}, status_code=404)
    try:
        field = form.get("field")
        if field == "usecase":
            msg = await assign.set_usecase(p, str(form.get("value", ""))[:100])
        elif field == "lifecycle":
            msg = await assign.set_lifecycle(p, str(form.get("value", "")))
        else:
            return JSONResponse({"ok": False, "msg": "unknown field"}, status_code=400)
    except assign.AssignError as e:
        return JSONResponse({"ok": False, "msg": str(e)}, status_code=400)
    p = await db.fetchrow("SELECT p.*, a.name AS app_name FROM proxies p LEFT JOIN apps a ON a.proxy_id = p.id "
                          "WHERE p.id = $1", pid)
    return JSONResponse({"ok": True, "msg": msg, "lifecycle": p["lifecycle"], "usecase": p["app_name"] or "",
                         "last_usecase": p["last_usecase"]})


@login_required
async def proxy_detail(request):
    pid = int(request.path_params["pid"])
    p = await db.fetchrow("SELECT * FROM proxies WHERE id = $1", pid)
    if not p:
        flash(request, "Proxy not found.", "err")
        return RedirectResponse("/", status_code=303)
    checks = await db.fetch("""
        SELECT ts, ok, http_ok, smtp_ok, latency_ms, smtp_latency_ms, error, exit_ip FROM checks
        WHERE proxy_id = $1 AND ts > now() - interval '24 hours' ORDER BY ts DESC LIMIT 3000
    """, pid)
    uptime = await db.fetchrow("""
        SELECT round(avg(ok::int) FILTER (WHERE ts > now() - interval '1 hour') * 100, 1) AS h1,
               round(avg(ok::int) FILTER (WHERE ts > now() - interval '24 hours') * 100, 1) AS h24,
               round(avg(ok::int) * 100, 1) AS d7
        FROM checks WHERE proxy_id = $1 AND ts > now() - interval '7 days'
    """, pid)
    events = await db.fetch("SELECT * FROM events WHERE proxy_id = $1 ORDER BY ts DESC LIMIT 30", pid)
    app_row = await db.fetchrow("SELECT * FROM apps WHERE proxy_id = $1", pid)
    outages = await db.fetch("""SELECT *, EXTRACT(EPOCH FROM (COALESCE(ended_at, now()) - started_at))::int AS secs
                                FROM incidents WHERE proxy_id = $1 ORDER BY started_at DESC LIMIT 25""", pid)
    fails = await db.fetch("""SELECT %s AS reason, count(*) AS n, max(ts) AS last FROM checks
                              WHERE proxy_id = $1 AND NOT ok AND NOT mass AND ts > now() - interval '24 hours'
                              GROUP BY 1 ORDER BY 2 DESC""" % health.reason_sql(), pid)
    reports = await db.fetch("SELECT * FROM reports WHERE proxy_id = $1 ORDER BY ts DESC LIMIT 30", pid)
    chart = [{"t": c["ts"].isoformat(), "l": c["latency_ms"], "s": c["smtp_latency_ms"], "ok": c["ok"]}
             for c in reversed(checks)]
    return render(request, "proxy.html", p=p, checks=checks[:60], uptime=uptime, events=events, reports=reports,
                  chart_json=json.dumps(chart), url=proxy_url(p), app=app_row, modes=settings.check_modes,
                  lifecycles=assign.LIFECYCLES, cost=settings.proxy_monthly_cost, outages=outages, fails=fails,
                  reasons=health.LABELS)


@login_required
async def proxy_action(request):
    pid = int(request.path_params["pid"])
    form = await request.form()
    action = form.get("action")
    p = await db.fetchrow("SELECT * FROM proxies WHERE id = $1", pid)
    if not p:
        return RedirectResponse("/", status_code=303)
    back = "/proxy/%d" % pid
    try:
        if action == "usecase":
            flash(request, await assign.set_usecase(p, str(form.get("value", ""))[:100]))
        elif action in assign.LIFECYCLES:
            flash(request, await assign.set_lifecycle(p, action))
        elif action == "mark_deleted":
            flash(request, await assign.set_deleted(p, True))
        elif action == "undelete":
            flash(request, await assign.set_deleted(p, False))
    except assign.AssignError as e:
        flash(request, str(e), "err")
    if action == "enable":
        await db.execute("UPDATE proxies SET enabled = true, status = 'unknown', fail_streak = 0, ok_streak = 0, recheck = true WHERE id = $1", pid)
        flash(request, "Enabled. Checking now.")
    elif action == "disable":
        await db.execute("UPDATE proxies SET enabled = false WHERE id = $1", pid)
        await db.execute("UPDATE incidents SET ended_at = now(), end_note = 'monitoring stopped' "
                         "WHERE proxy_id = $1 AND ended_at IS NULL", pid)
        flash(request, "Disabled — it won't be handed out to apps.")
    elif action == "recheck":
        await db.execute("UPDATE proxies SET recheck = true WHERE id = $1", pid)
        flash(request, "Recheck queued; refresh in a few seconds.")
    elif action == "delete":
        await db.execute("DELETE FROM proxies WHERE id = $1", pid)
        await db.log_event("deleted", "Removed record of %s" % assign.label(p))
        flash(request, "Removed %s from the dashboard." % assign.label(p))
        back = "/"
    elif action == "edit":
        seq = str(form.get("seq", "")).strip()
        await db.execute(
            "UPDATE proxies SET label = $2, provider = $3, country = $4, region = $5, notes = $6, "
            "seq = COALESCE($7::int, seq) WHERE id = $1",
            pid, clean(form.get("label")), clean(form.get("provider"), 32) or "other",
            clean(form.get("country"), 8).upper() or "US", clean(form.get("region"), 32),
            str(form.get("notes", ""))[:1000], int(seq) if seq.isdigit() else None)
        dup = await db.fetchval("SELECT string_agg(COALESCE(NULLIF(label, ''), host), ', ') FROM proxies "
                                "WHERE seq = $1 AND id <> $2", int(seq) if seq.isdigit() else -1, pid)
        flash(request, "Saved." + (" Note: #%s is also used by %s." % (seq, dup) if dup else ""), "err" if dup else "ok")
    return RedirectResponse(back, status_code=303)


@login_required
async def bulk_action(request):
    form = await request.form()
    ids = [int(i) for i in form.getlist("ids") if str(i).isdigit()]
    action = form.get("action")
    if not ids:
        flash(request, "Select at least one proxy.", "err")
    elif action == "enable":
        await db.execute("UPDATE proxies SET enabled = true, status = 'unknown', fail_streak = 0, ok_streak = 0, recheck = true WHERE id = ANY($1::int[])", ids)
        flash(request, "Enabled %d." % len(ids))
    elif action == "disable":
        await db.execute("UPDATE proxies SET enabled = false WHERE id = ANY($1::int[])", ids)
        await db.execute("UPDATE incidents SET ended_at = now(), end_note = 'monitoring stopped' "
                         "WHERE proxy_id = ANY($1::int[]) AND ended_at IS NULL", ids)
        flash(request, "Disabled %d." % len(ids))
    elif action == "recheck":
        await db.execute("UPDATE proxies SET recheck = true WHERE id = ANY($1::int[])", ids)
        flash(request, "Recheck queued for %d." % len(ids))
    elif action in tuple(assign.LIFECYCLES) + ("mark_deleted", "undelete"):
        done, errs = 0, []
        for p in await db.fetch("SELECT * FROM proxies WHERE id = ANY($1::int[]) ORDER BY label, host", ids):
            try:
                if action in ("mark_deleted", "undelete"):
                    await assign.set_deleted(p, action == "mark_deleted")
                else:
                    await assign.set_lifecycle(p, action)
                done += 1
            except assign.AssignError as e:
                errs.append("%s: %s" % (assign.label(p), e))
        names = {"ready": "set to Ready", "active": "set to Active", "suspended": "set to Suspended",
                 "to_delete": "marked To delete", "mark_deleted": "moved to trash", "undelete": "restored from trash"}
        flash(request, "%d %s." % (done, names[action]) + (" Problems: " + "; ".join(errs[:10]) if errs else ""),
              "err" if errs else "ok")
    elif action == "delete":
        await db.execute("DELETE FROM proxies WHERE id = ANY($1::int[])", ids)
        await db.log_event("deleted", "Removed %d proxy records" % len(ids))
        flash(request, "Removed %d from the dashboard." % len(ids))
    back = str(form.get("back") or "/")
    if not back.startswith("/") or back.startswith("//"):
        back = "/"
    return RedirectResponse(back, status_code=303)


IPPORT_RE = re.compile(r"^(?:(?:https?|socks5h?)://)?(?:([^@\s]+)@)?(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$", re.I)
GCP_ZONE_RE = re.compile(r"^[a-z]+-[a-z]+\d+(-[a-z])?$")


def _status_of(cell):
    low = cell.lower().strip()
    if "✅" in cell or low in ("active", "✅ active"):
        return "active"
    if "🆗" in cell or low in ("ready", "ok", "🆗 ready"):
        return "ready"
    if "❌" in cell or "✖" in cell or low in ("suspended", "x", "❌ suspended"):
        return "suspended"
    if "🗑" in cell or low.replace("_", " ") in ("to delete", "todelete", "delete"):
        return "to_delete"
    return None


def parse_sheet_row(line, default_protocol):
    """A row copied from the proxy sheet: Name | Region | User:Pass | IP:Port | Use case | Status | Deleted.
    Status: ✅ active, 🆗 ready, ❌ suspended, 🗑/"to delete". A "Deleted" cell = VM deleted -> Trash.
    Cells are found by what they look like, so missing/extra columns are tolerated. Returns None for header/blank rows."""
    cells = [c.strip() for c in (line.split("\t") if "\t" in line else line.split())]
    cells = [c for c in cells if c]
    num = None
    if cells and cells[0].isdigit():  # the sheet's "#" column
        num, cells = int(cells[0]), cells[1:]
    ip_idx = next((i for i, c in enumerate(cells) if IPPORT_RE.match(c)), None)
    if ip_idx is None:
        return None
    m = IPPORT_RE.match(cells[ip_idx])
    item = {"protocol": default_protocol, "host": m.group(2), "port": int(m.group(3)), "username": "", "password": "",
            "name": "", "region": "", "usecase": "", "lifecycle": None, "deleted": False, "num": num}
    if m.group(1):
        item["username"], _, item["password"] = m.group(1).partition(":")
    if cells[ip_idx].lower().startswith("socks"):
        item["protocol"] = "socks5"
    before, after = [], []
    for i, c in enumerate(cells):
        if i == ip_idx:
            continue
        if "deleted" in c.lower():
            item["deleted"] = True
            continue
        st = _status_of(c)
        if st:
            item["lifecycle"] = st
            continue
        if not item["username"] and ":" in c and not IPPORT_RE.match(c):
            item["username"], _, item["password"] = c.partition(":")
            continue
        (before if i < ip_idx else after).append(c)
    if before:
        item["name"] = before[0][:64]
    if len(before) > 1:
        item["region"] = before[1][:32]
    if after:
        item["usecase"] = after[0][:100]
    return item


async def import_sheet_row(item, provider, country):
    """Upsert one sheet row and apply its status, use case and deleted flag. Returns (inserted, note).
    A row with only "#" and IP:port just renumbers an existing proxy and changes nothing else."""
    only_num = (item["num"] is not None and not any(
        (item["name"], item["region"], item["username"], item["usecase"], item["lifecycle"], item["deleted"])))
    if only_num:
        r = await db.fetchrow("UPDATE proxies SET seq = $3 WHERE host = $1 AND port = $2 RETURNING id",
                              item["host"], item["port"], item["num"])
        if not r:
            raise ValueError("%s:%s is not in the dashboard yet" % (item["host"], item["port"]))
        return False, "renumbered"
    life = item["lifecycle"] or ("active" if item["usecase"] else "ready")
    deleted = item["deleted"]
    prov = provider or ("gcp" if GCP_ZONE_RE.match(item["region"] or "") else "other")
    row = await db.fetchrow("""
        INSERT INTO proxies (label, provider, country, region, protocol, host, port, username, password, source,
                             recheck, enabled, lifecycle, deleted_at, last_usecase, lifecycle_at, suspended_for, seq)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'import', $10, $10, $11,
                CASE WHEN $12 THEN now() END, $13, now(), CASE WHEN $11 = 'suspended' THEN $13 ELSE '' END, $14::int)
        ON CONFLICT (host, port) DO UPDATE SET
            seq = COALESCE($14::int, proxies.seq),
            label = CASE WHEN EXCLUDED.label <> '' THEN EXCLUDED.label ELSE proxies.label END,
            region = CASE WHEN EXCLUDED.region <> '' THEN EXCLUDED.region ELSE proxies.region END,
            protocol = EXCLUDED.protocol, username = EXCLUDED.username, password = EXCLUDED.password,
            lifecycle = EXCLUDED.lifecycle, enabled = EXCLUDED.enabled, recheck = EXCLUDED.recheck,
            deleted_at = CASE WHEN EXCLUDED.deleted_at IS NULL THEN NULL ELSE COALESCE(proxies.deleted_at, EXCLUDED.deleted_at) END,
            lifecycle_at = CASE WHEN EXCLUDED.lifecycle <> proxies.lifecycle THEN now() ELSE proxies.lifecycle_at END,
            suspended_for = CASE WHEN EXCLUDED.lifecycle = 'suspended' AND EXCLUDED.last_usecase <> ''
                                  AND position(EXCLUDED.last_usecase IN proxies.suspended_for) = 0
                             THEN trim(BOTH ',' FROM proxies.suspended_for || ',' || EXCLUDED.last_usecase)
                             ELSE proxies.suspended_for END,
            last_usecase = CASE WHEN EXCLUDED.last_usecase <> '' THEN EXCLUDED.last_usecase ELSE proxies.last_usecase END
        RETURNING *, (xmax = 0) AS inserted
    """, item["name"], prov, country, item["region"], item["protocol"], item["host"], item["port"],
        item["username"], item["password"], not deleted, life, deleted, item["usecase"], item["num"])
    note = ""
    if deleted:
        await db.execute("UPDATE incidents SET ended_at = now(), end_note = 'moved to trash' "
                         "WHERE proxy_id = $1 AND ended_at IS NULL", row["id"])
        app = await assign.app_on(row["id"])
        if app:
            await assign.set_proxy(app, None, "proxy in trash (import)")
    elif item["usecase"] and life not in ("suspended", "to_delete"):
        note = await assign.set_usecase(row, item["usecase"])
        if life == "ready":  # sheet says ready even though a use case is written: keep the sheet's word
            await db.execute("UPDATE proxies SET lifecycle = 'ready' WHERE id = $1", row["id"])
    return row["inserted"], note


@login_required
async def add_proxies(request):
    if request.method == "GET":
        return render(request, "add.html", result=None)
    form = await request.form()
    protocol = form.get("protocol") if form.get("protocol") in ("http", "socks5") else "http"
    provider = clean(form.get("provider"), 32)
    country = clean(form.get("country"), 8).upper() or "US"
    region = clean(form.get("region"), 32)
    label = clean(form.get("label"))
    added, updated, renumbered, errors = 0, 0, 0, []
    for n, line in enumerate(str(form.get("lines", "")).splitlines(), 1):
        if not line.strip() or line.strip().startswith("#"):
            continue
        try:
            if "\t" in line.strip() or len(line.split()) > 1:
                item = parse_sheet_row(line, protocol)
                if item is None:
                    continue  # header or row without IP:port
                inserted, note = await import_sheet_row(item, provider, country)
                if note == "renumbered":
                    renumbered += 1
                else:
                    added, updated = added + inserted, updated + (not inserted)
                continue
            item = parse_proxy_line(line, protocol)
        except (ValueError, assign.AssignError) as e:
            errors.append("line %d: %s — %s" % (n, e, line.strip()[:60]))
            continue
        if not item:
            continue
        row = await db.fetchrow("""
            INSERT INTO proxies (label, provider, country, region, protocol, host, port, username, password, source, recheck)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'manual', true)
            ON CONFLICT (host, port) DO UPDATE SET protocol = EXCLUDED.protocol, username = EXCLUDED.username,
                password = EXCLUDED.password, provider = EXCLUDED.provider, country = EXCLUDED.country,
                region = EXCLUDED.region, recheck = true,
                label = CASE WHEN EXCLUDED.label <> '' THEN EXCLUDED.label ELSE proxies.label END
            RETURNING (xmax = 0) AS inserted
        """, label, provider or "other", country, region, item["protocol"], item["host"], item["port"],
            item["username"], item["password"])
        if row["inserted"]:
            added += 1
        else:
            updated += 1
    if added or updated or renumbered:
        await db.log_event("import", "Added %d, updated %d, renumbered %d proxies" % (added, updated, renumbered))
    flash(request, "Added %d, updated %d%s." % (added, updated, ", renumbered %d" % renumbered if renumbered else ""),
          "err" if errors else "ok")
    return render(request, "add.html", result={"added": added, "updated": updated, "errors": errors})


@login_required
async def proxies_csv(request):
    """Same columns as the proxy sheet, so it can be pasted back."""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["#", "Name", "Region", "User:Pass", "IP:Port", "Use case", "Status", "Deleted", "Health", "Provider",
                "Latency ms", "Last check (UTC)"])
    rows = await db.fetch("""SELECT p.*, a.name AS app_name FROM proxies p LEFT JOIN apps a ON a.proxy_id = p.id
                             ORDER BY p.seq, p.id""")
    for p in rows:
        w.writerow([p["seq"], p["label"], p["region"], "%s:%s" % (p["username"], p["password"]) if p["username"] else "",
                    "%s:%s" % (p["host"], p["port"]), p["app_name"] or p["last_usecase"],
                    assign.LIFECYCLES.get(p["lifecycle"], p["lifecycle"]), "Deleted" if p["deleted_at"] else "",
                    p["status"] if p["enabled"] else "not monitored", p["provider"], p["last_latency_ms"] or "",
                    p["last_check_at"].astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M") if p["last_check_at"] else ""])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="proxies-%s.csv"' % stamp})


EVENT_GROUPS = {
    "health": ("Health", ("status", "mass_failure")),
    "usecase": ("Use cases", ("assign", "app")),
    "status": ("Status changes", ("lifecycle", "deleted")),
    "import": ("Imports & new nodes", ("import", "enroll")),
    "admin": ("Users & settings", ("user", "settings")),
}
KIND_GROUP = {k: g for g, (_, kinds) in EVENT_GROUPS.items() for k in kinds}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
EVENTS_PER_PAGE = 100


def _events_query(q):
    where, args = ["TRUE"], []

    def arg(v):
        args.append(v)
        return "$%d" % len(args)

    g = q.get("group", "")
    if g in EVENT_GROUPS:
        where.append("e.kind = ANY(%s::text[])" % arg(list(EVENT_GROUPS[g][1])))
    if q.get("health") == "down":
        where.append("e.kind = 'status' AND e.message LIKE '%% -> dead%%'")
    elif q.get("health") == "up":
        where.append("e.kind = 'status' AND e.message LIKE '%% -> healthy%%'")
    if q.get("actor") == "system":
        where.append("e.actor IN ('', 'system')")
    elif q.get("actor"):
        where.append("e.actor = " + arg(q["actor"]))
    if q.get("provider"):
        where.append("p.provider = " + arg(q["provider"]))
    if DATE_RE.match(q.get("from", "")):
        where.append("e.ts >= %s::text::date" % arg(q["from"]))
    if DATE_RE.match(q.get("to", "")):
        where.append("e.ts < %s::text::date + 1" % arg(q["to"]))
    if q.get("q"):
        like = arg("%" + q["q"] + "%")
        where.append("(e.message ILIKE {0} OR p.label ILIKE {0} OR p.host ILIKE {0} OR a.name ILIKE {0})".format(like))
    frm = """FROM events e LEFT JOIN proxies p ON p.id = e.proxy_id LEFT JOIN apps a ON a.id = e.app_id
             WHERE %s""" % " AND ".join(where)
    return frm, args


@login_required
async def events_page(request):
    q = request.query_params
    frm, args = _events_query(q)
    total = await db.fetchval("SELECT count(*) " + frm, *args)
    page = max(1, int(q["page"])) if q.get("page", "").isdigit() else 1
    pages = max(1, (total + EVENTS_PER_PAGE - 1) // EVENTS_PER_PAGE)
    page = min(page, pages)
    rows = await db.fetch("SELECT e.*, p.seq, p.label, p.host, p.port, p.provider " + frm +
                          " ORDER BY e.ts DESC, e.id DESC LIMIT %d OFFSET %d" % (EVENTS_PER_PAGE, (page - 1) * EVENTS_PER_PAGE),
                          *args)
    actors = [r["actor"] for r in await db.fetch(
        "SELECT DISTINCT actor FROM events WHERE actor NOT IN ('', 'system') ORDER BY 1")]
    providers = [r["provider"] for r in await db.fetch("SELECT DISTINCT provider FROM proxies ORDER BY 1")]
    return render(request, "events.html", rows=rows, q=q, total=total, page=page, pages=pages, groups=EVENT_GROUPS,
                  kind_group=KIND_GROUP, actors=actors, providers=providers)


@login_required
async def events_csv(request):
    import csv
    import io
    frm, args = _events_query(request.query_params)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Time (UTC)", "Type", "#", "Proxy", "IP:Port", "Provider", "What happened", "By"])
    for e in await db.fetch("SELECT e.*, p.seq, p.label, p.host, p.port, p.provider " + frm +
                            " ORDER BY e.ts DESC, e.id DESC LIMIT 100000", *args):
        w.writerow([fmt_ts(e["ts"]), EVENT_GROUPS.get(KIND_GROUP.get(e["kind"]), (e["kind"],))[0], e["seq"] or "",
                    e["label"] or "", "%s:%s" % (e["host"], e["port"]) if e["host"] else "", e["provider"] or "",
                    e["message"], e["actor"] if e["actor"] not in ("", "system") else ""])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="events-%s.csv"' % stamp})


@admin_required
async def settings_page(request):
    if request.method == "POST":
        form = await request.form()
        if form.get("action") == "cidrs":
            good, bad = [], []
            for part in re.split(r"[\s,]+", str(form.get("cidrs", ""))):
                if not part:
                    continue
                try:
                    good.append(str(ipaddress.ip_network(part, strict=False)))
                except ValueError:
                    bad.append(part)
            if bad:
                flash(request, "Not saved — invalid entries: %s" % ", ".join(bad[:10]), "err")
            else:
                await db.set_meta("allowed_cidrs", "\n".join(sorted(set(good))))
                await db.log_event("settings", "Allowed client IPs updated (%d entries)" % len(good))
                flash(request, "Saved. Nodes pick this up on their next sync (within 5 minutes).")
        elif form.get("action") == "prices":
            prices = {}
            for k, v in form.multi_items():
                if k.startswith("price_"):
                    name = clean(k[6:], 32)
                    v = str(v).strip().replace("$", "").replace(",", ".")
                    if v:
                        try:
                            prices[name] = round(float(v), 2)
                        except ValueError:
                            flash(request, "Not a number for %s: %s" % (name, v), "err")
                            return RedirectResponse("/settings#prices", status_code=303)
                    else:
                        prices[name] = None
            await db.set_meta("provider_prices", json.dumps(prices))
            await db.log_event("settings", "Provider prices updated")
            flash(request, "Prices saved.")
            return RedirectResponse("/settings#prices", status_code=303)
        elif form.get("action") == "digest":
            hour = str(form.get("hour", "")).strip()
            if hour and not (hour.isdigit() and 0 <= int(hour) <= 23):
                flash(request, "Hour must be 0–23.", "err")
            else:
                await db.set_meta("digest_hour", hour)
                await db.log_event("settings", "Daily summary %s" % ("at %s:00 UTC" % hour if hour else "turned off"))
                flash(request, "Daily summary %s." % ("will be sent at %s:00 UTC" % hour if hour else "turned off"))
            return RedirectResponse("/settings#digest", status_code=303)
        elif form.get("action") == "digest_now":
            from .checker import daily_summary
            text = await daily_summary()
            ok = await alerts.send(text) if alerts.enabled() else False
            flash(request, "Summary sent." if ok else "No alert channel configured or sending failed — preview below.",
                  "ok" if ok else "err")
            request.session["digest_preview"] = text
            return RedirectResponse("/settings#digest", status_code=303)
        elif form.get("action") == "test_alert":
            if alerts.enabled():
                ok = await alerts.send("✅ Test alert from Proxy Manager")
                flash(request, "Test alert sent." if ok else "Sending failed — check the token / webhook and the logs.",
                      "ok" if ok else "err")
            else:
                flash(request, "No alert channel configured (TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID, or SLACK_WEBHOOK_URL).", "err")
        return RedirectResponse("/settings", status_code=303)
    raw = await db.get_meta("allowed_cidrs", settings.default_client_cidrs) or ""
    stale = await db.fetch("""
        SELECT DISTINCT host, provider, max(last_seen_sync_at) AS seen FROM proxies
        WHERE source = 'enrolled' GROUP BY host, provider
        HAVING max(last_seen_sync_at) IS NULL OR max(last_seen_sync_at) < now() - interval '15 minutes'
        ORDER BY seen NULLS FIRST LIMIT 50
    """)
    providers = [r["provider"] for r in await db.fetch(
        "SELECT provider FROM proxies WHERE deleted_at IS NULL GROUP BY 1 ORDER BY count(*) DESC")]
    prices = await provider_prices()
    backup = None
    raw_b = await db.get_meta("last_backup")
    if raw_b and raw_b.count("|") >= 2:
        ts, path, size = raw_b.split("|", 2)
        backup = {"at": datetime.fromtimestamp(int(ts), timezone.utc), "path": path, "size": size,
                  "old": datetime.now(timezone.utc).timestamp() - int(ts) > 36 * 3600}
    return render(request, "settings.html", base=base_url(request), s=settings, providers=providers, prices=prices,
                  backup=backup, digest_hour=await db.get_meta("digest_hour", ""), version=APP_VERSION,
                  digest_preview=request.session.pop("digest_preview", None),
                  cidrs="\n".join(c for c in re.split(r"[\s,]+", raw) if c), effective=await allowed_cidrs(),
                  telegram=alerts.telegram_on(), slack=alerts.slack_on(), stale=stale,
                  insecure=_is_ip_url(base_url(request)))


# ---------- apps (one proxy per app) ----------

APP_NAME_RE = re.compile(r"^[\w.@:/+ -]{1,100}$")

APPS_SQL = """
    SELECT a.*, p.host, p.port, p.protocol, p.username, p.password, p.status, p.enabled, p.provider, p.country,
           p.region, p.last_latency_ms, p.last_error, p.last_check_at, p.status_changed_at, p.label,
           p.lifecycle, p.deleted_at
    FROM apps a LEFT JOIN proxies p ON p.id = a.proxy_id
"""


def app_state(a):
    if not a["proxy_id"]:
        return "unassigned"
    if a.get("lifecycle") in ("suspended", "to_delete"):
        return a["lifecycle"]
    if not a["enabled"]:
        return "disabled"
    return a["status"]


async def _find_or_create_proxy(text, defaults):
    """For mapping import: 'host', 'host:port' or a full proxy line. Returns proxy row."""
    text = text.strip()
    if re.fullmatch(r"[\w.-]+", text):  # bare host -> existing proxy on that host
        rows = await db.fetch("SELECT * FROM proxies WHERE host = $1 ORDER BY (protocol = 'http') DESC, id", text)
        if not rows:
            raise ValueError("no proxy with host %s — include port and credentials to create it" % text)
        return rows[0]
    item = parse_proxy_line(text, defaults["protocol"])
    existing = await db.fetchrow("SELECT * FROM proxies WHERE host = $1 AND port = $2", item["host"], item["port"])
    if existing and (not item["username"] or (existing["username"], existing["password"]) == (item["username"], item["password"])):
        return existing
    return await db.fetchrow("""
        INSERT INTO proxies (provider, country, region, protocol, host, port, username, password, source, recheck)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'manual', true)
        ON CONFLICT (host, port) DO UPDATE SET protocol = EXCLUDED.protocol, username = EXCLUDED.username,
            password = EXCLUDED.password, recheck = true
        RETURNING *
    """, defaults["provider"], defaults["country"], defaults["region"], item["protocol"], item["host"], item["port"],
        item["username"], item["password"])


@login_required
async def apps_page(request):
    q = request.query_params
    where, args = [], []
    state = q.get("state", "")
    if state == "problem":
        where.append("a.proxy_id IS NOT NULL AND (NOT p.enabled OR p.status <> 'healthy' OR p.lifecycle <> 'active')")
    elif state == "unassigned":
        where.append("a.proxy_id IS NULL")
    elif state == "ok":
        where.append("p.enabled AND p.status = 'healthy' AND p.lifecycle = 'active'")
    if q.get("q"):
        args.append("%" + q["q"] + "%")
        where.append("(a.name ILIKE $1 OR p.host ILIKE $1 OR p.label ILIKE $1 OR a.notes ILIKE $1)")
    order = "a.name"
    rows = await db.fetch(APPS_SQL + ("WHERE " + " AND ".join(where) if where else "") + " ORDER BY " + order, *args)
    for r in rows:
        r["state"] = app_state(r)
    summary = await db.fetchrow("""
        SELECT count(*) AS total,
               count(*) FILTER (WHERE p.enabled AND p.status = 'healthy' AND p.lifecycle = 'active') AS ok,
               count(*) FILTER (WHERE a.proxy_id IS NOT NULL AND (NOT p.enabled OR p.status <> 'healthy' OR p.lifecycle <> 'active')) AS problem,
               count(*) FILTER (WHERE a.proxy_id IS NULL) AS unassigned
        FROM apps a LEFT JOIN proxies p ON p.id = a.proxy_id
    """)
    return render(request, "apps.html", rows=rows, summary=summary, q=q, lifecycles=assign.LIFECYCLES,
                  result=request.session.pop("import_result", None))


@login_required
async def apps_import(request):
    """Lines: 'use-case' or 'use-case, <proxy>' (proxy = host, host:port, host:port:user:pass or URL)."""
    form = await request.form()
    defaults = {"protocol": "http", "provider": clean(form.get("provider"), 32) or "other",
                "country": "US", "region": ""}
    created = assigned = 0
    errors = []
    for n, line in enumerate(str(form.get("lines", "")).splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, proxy_text = _split_app_line(line)
        if not APP_NAME_RE.match(name):
            errors.append("line %d: bad name %r" % (n, name[:40]))
            continue
        app_row = await db.fetchrow("SELECT * FROM apps WHERE name = $1", name)
        if not app_row:
            app_row = await db.fetchrow("INSERT INTO apps (name) VALUES ($1) RETURNING *", name)
            created += 1
        if not proxy_text:
            continue
        try:
            p = await _find_or_create_proxy(proxy_text, defaults)
            await assign.set_proxy(app_row, p["id"], "import")
            assigned += 1
        except (ValueError, assign.AssignError) as e:
            errors.append("line %d (%s): %s" % (n, name, e))
    await db.log_event("import", "Use cases import: %d new, %d proxies linked, %d errors" % (created, assigned, len(errors)))
    request.session["import_result"] = {"errors": errors[:50]}
    flash(request, "%d new use cases, %d proxies linked." % (created, assigned), "err" if errors else "ok")
    return RedirectResponse("/apps", status_code=303)


def _split_app_line(line):
    m = re.match(r"^(.+?)\s*[,;\t]\s*(.+)$", line)
    if m:
        return m.group(1).strip(), ",", m.group(2).strip()
    parts = line.split(None, 1)
    if len(parts) == 2 and (":" in parts[1] or "." in parts[1]):
        return parts[0], " ", parts[1].strip()
    return line, "", ""


@login_required
async def apps_bulk(request):
    form = await request.form()
    ids = [int(i) for i in form.getlist("ids") if str(i).isdigit()]
    if not ids:
        flash(request, "Nothing selected.", "err")
        return RedirectResponse("/apps", status_code=303)
    n = 0
    if form.get("action") == "delete":
        for a in await db.fetch("SELECT * FROM apps WHERE id = ANY($1::int[])", ids):
            if a["proxy_id"]:
                await assign.set_proxy(a, None, "use case deleted")
            await db.execute("DELETE FROM apps WHERE id = $1", a["id"])
            await db.log_event("app", "Deleted use case %s" % a["name"])
            n += 1
        flash(request, "Deleted %d use case(s). Their proxies keep the name as “was …”." % n)
    return RedirectResponse("/apps", status_code=303)


@login_required
async def app_detail(request):
    aid = int(request.path_params["aid"])
    a = await db.fetchrow(APPS_SQL + " WHERE a.id = $1", aid)
    if not a:
        flash(request, "Use case not found.", "err")
        return RedirectResponse("/apps", status_code=303)
    a["state"] = app_state(a)
    if request.method == "POST":
        form = await request.form()
        action = form.get("action")
        try:
            if action == "unassign" and a["proxy_id"]:
                await assign.set_proxy(a, None, "unassigned")
                flash(request, "Proxy unlinked from %s." % a["name"])
            elif action == "delete":
                if a["proxy_id"]:
                    await assign.set_proxy(a, None, "use case deleted")
                await db.execute("DELETE FROM apps WHERE id = $1", aid)
                await db.log_event("app", "Deleted use case %s" % a["name"])
                flash(request, "Deleted %s." % a["name"])
                return RedirectResponse("/apps", status_code=303)
            elif action == "save":
                name = str(form.get("name", "")).strip()
                if not APP_NAME_RE.match(name):
                    raise assign.AssignError("invalid name")
                if name != a["name"] and await db.fetchval("SELECT 1 FROM apps WHERE name = $1", name):
                    raise assign.AssignError("a use case named %s already exists" % name)
                await db.execute("UPDATE apps SET name = $2, notes = $3 WHERE id = $1", aid, name,
                                 str(form.get("notes", ""))[:1000])
                if name != a["name"]:
                    await db.log_event("app", "Renamed use case %s -> %s" % (a["name"], name), a["proxy_id"], aid)
                    if a["proxy_id"]:
                        await db.execute("UPDATE proxies SET last_usecase = $2 WHERE id = $1", a["proxy_id"], name)
                flash(request, "Saved.")
        except assign.AssignError as e:
            flash(request, str(e), "err")
        return RedirectResponse("/apps/%d" % aid, status_code=303)
    events = await db.fetch("SELECT * FROM events WHERE app_id = $1 ORDER BY ts DESC LIMIT 100", aid)
    past = await db.fetch("""SELECT id, label, host, port, lifecycle, deleted_at FROM proxies
                             WHERE (last_usecase = $1 OR position($1 IN suspended_for) > 0) AND id IS DISTINCT FROM $2
                             ORDER BY id""", a["name"], a["proxy_id"])
    url = proxy_url(a) if a["proxy_id"] else ""
    return render(request, "app.html", a=a, events=events, url=url, past=past, lifecycles=assign.LIFECYCLES)


@login_required
async def apps_csv(request):
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["app", "proxy_url", "host", "port", "protocol", "username", "password", "status", "provider",
                "country", "region", "assigned_at", "notes"])
    for a in await db.fetch(APPS_SQL + " ORDER BY a.name"):
        has = bool(a["proxy_id"])
        w.writerow([a["name"], proxy_url(a) if has else "", a["host"] or "", a["port"] or "", a["protocol"] or "",
                    a["username"] or "", a["password"] or "", app_state(a), a["provider"] or "", a["country"] or "",
                    a["region"] or "", a["assigned_at"].isoformat() if a["assigned_at"] else "", a["notes"]])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="app-proxies-%s.csv"' % stamp})


@api_auth
async def api_apps(request):
    out = []
    for a in await db.fetch(APPS_SQL + " ORDER BY a.name"):
        out.append({"name": a["name"], "state": app_state(a),
                    "proxy": ({"id": a["proxy_id"], "url": proxy_url(a), "host": a["host"], "port": a["port"],
                               "protocol": a["protocol"], "status": a["status"], "provider": a["provider"],
                               "country": a["country"]} if a["proxy_id"] else None)})
    return JSONResponse({"count": len(out), "apps": out})


@api_auth
async def api_app_proxy(request):
    """The proxy currently assigned to one app. Apps that read this pick up replacements automatically."""
    a = await db.fetchrow(APPS_SQL + " WHERE a.name = $1", request.path_params["name"])
    if not a:
        return JSONResponse({"error": "unknown app"}, status_code=404)
    if not a["proxy_id"]:
        return JSONResponse({"error": "app has no proxy assigned"}, status_code=404)
    if request.query_params.get("format") == "url":
        return PlainTextResponse(proxy_url(a) + "\n")
    return JSONResponse({"app": a["name"], "state": app_state(a), "url": proxy_url(a), "host": a["host"],
                         "port": a["port"], "protocol": a["protocol"], "username": a["username"],
                         "password": a["password"], "status": a["status"], "provider": a["provider"],
                         "latency_ms": a["last_latency_ms"]})


def _is_ip_url(url):
    """Dashboard reached by bare IP -> it uses the self-signed cert, so node installs need -k/--insecure."""
    from urllib.parse import urlsplit
    try:
        ipaddress.ip_address(urlsplit(url).hostname or "")
        return True
    except ValueError:
        return False


# ---------- health: incidents, flaky proxies, providers ----------

INC_WINDOWS = {"24h": "24 hours", "7d": "7 days", "30d": "30 days", "all": None}
CHECK_WINDOWS = {"1h": "1 hour", "24h": "24 hours", "7d": "7 days", "14d": "14 days"}


def _incident_query(q):
    where, args = ["TRUE"], []

    def arg(v):
        args.append(v)
        return "$%d" % len(args)

    win = q.get("win", "7d") if q.get("win") in INC_WINDOWS else "7d"
    if INC_WINDOWS[win]:
        where.append("(i.ended_at IS NULL OR i.started_at > now() - %s::text::interval)" % arg(INC_WINDOWS[win]))
    if q.get("open") == "1":
        where.append("i.ended_at IS NULL")
    if q.get("provider"):
        where.append("p.provider = " + arg(q["provider"]))
    if q.get("reason") in health.LABELS:
        where.append("i.reason = " + arg(q["reason"]))
    if q.get("life") in assign.LIFECYCLES:
        where.append("p.lifecycle = " + arg(q["life"]) + " AND p.deleted_at IS NULL")
    if q.get("q"):
        like = arg("%" + q["q"] + "%")
        where.append("(p.label ILIKE {0} OR p.host ILIKE {0} OR i.usecase ILIKE {0} OR a.name ILIKE {0} "
                     "OR i.error ILIKE {0})".format(like))
    sql = """
        SELECT i.*, p.seq, p.label, p.host, p.port, p.provider, p.region, p.lifecycle AS now_life, p.deleted_at,
               a.name AS now_usecase,
               EXTRACT(EPOCH FROM (COALESCE(i.ended_at, now()) - i.started_at))::int AS secs
        FROM incidents i JOIN proxies p ON p.id = i.proxy_id LEFT JOIN apps a ON a.proxy_id = p.id
        WHERE %s
        ORDER BY i.ended_at IS NOT NULL, i.started_at DESC
    """ % " AND ".join(where)
    return win, sql, args


async def _check_stats(win_key, provider=""):
    interval = CHECK_WINDOWS.get(win_key, "24 hours")
    r = health.reason_sql("c.error")
    return await db.fetch("""
        WITH s AS (
            SELECT c.proxy_id, count(*) AS checks, count(*) FILTER (WHERE NOT c.ok) AS failed,
                   count(*) FILTER (WHERE NOT c.ok AND {r} = 'timeout') AS timeouts,
                   count(*) FILTER (WHERE NOT c.ok AND {r} IN ('refused', 'unreachable')) AS conn,
                   count(*) FILTER (WHERE NOT c.ok AND {r} = 'auth') AS auth,
                   count(*) FILTER (WHERE NOT c.ok AND {r} NOT IN ('timeout', 'refused', 'unreachable', 'auth')) AS other,
                   max(c.ts) FILTER (WHERE NOT c.ok) AS last_fail,
                   round(avg(c.latency_ms) FILTER (WHERE c.ok)) AS avg_ms
            FROM checks c WHERE c.ts > now() - $1::text::interval AND NOT c.mass
            GROUP BY c.proxy_id)
        SELECT s.*, round(100.0 * s.failed / s.checks, 1) AS fail_pct,
               p.id, p.seq, p.label, p.host, p.port, p.provider, p.region, p.status, p.enabled, p.lifecycle,
               a.name AS usecase, p.last_usecase
        FROM s JOIN proxies p ON p.id = s.proxy_id LEFT JOIN apps a ON a.proxy_id = p.id
        WHERE p.deleted_at IS NULL AND ($2 = '' OR p.provider = $2)
    """.format(r=r), interval, provider or "")


@login_required
async def health_page(request):
    q = request.query_params
    tab = q.get("tab", "incidents")
    providers = [r["provider"] for r in await db.fetch(
        "SELECT DISTINCT provider FROM proxies WHERE deleted_at IS NULL ORDER BY 1")]
    top = await db.fetchrow("""
        SELECT count(*) FILTER (WHERE i.ended_at IS NULL) AS open,
               count(*) FILTER (WHERE i.ended_at IS NULL AND p.lifecycle = 'active') AS open_active,
               count(*) FILTER (WHERE i.started_at > now() - interval '24 hours') AS day,
               COALESCE(sum(EXTRACT(EPOCH FROM (COALESCE(i.ended_at, now())
                        - greatest(i.started_at, now() - interval '24 hours'))))
                        FILTER (WHERE COALESCE(i.ended_at, now()) > now() - interval '24 hours'), 0)::bigint AS down_secs_24h,
               percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (i.ended_at - i.started_at)))
                        FILTER (WHERE i.ended_at IS NOT NULL AND i.started_at > now() - interval '7 days') AS mttr
        FROM incidents i JOIN proxies p ON p.id = i.proxy_id
    """)
    ctx = dict(tab=tab, q=q, providers=providers, top=top, reasons=health.LABELS, lifecycles=assign.LIFECYCLES)
    if tab == "flaky":
        win = q.get("win", "24h") if q.get("win") in CHECK_WINDOWS else "24h"
        rows = [r for r in await _check_stats(win, q.get("provider", "")) if r["failed"]]
        if q.get("health", "up") == "up":
            rows = [r for r in rows if r["enabled"] and r["status"] != "dead"]
        if q.get("life") in assign.LIFECYCLES:
            rows = [r for r in rows if r["lifecycle"] == q["life"]]
        col = {"timeout": "timeouts", "conn": "conn", "auth": "auth", "other": "other"}.get(q.get("reason", ""))
        if col:
            rows = [r for r in rows if r[col]]
        sort = q.get("sort", "fail_pct")
        if sort not in ("fail_pct", "failed", "timeouts", "conn", "last_fail", "avg_ms", "seq"):
            sort = "fail_pct"
        rows.sort(key=lambda r: (r[sort] is None, r[sort] or 0), reverse=sort != "seq")
        ctx.update(rows=rows[:1000], win=win, windows=CHECK_WINDOWS, sort=sort)
    elif tab == "providers":
        win = q.get("win", "24h") if q.get("win") in CHECK_WINDOWS else "24h"
        stats = await _check_stats(win)
        live = await db.fetch("""
            SELECT provider, count(*) AS proxies,
                   count(*) FILTER (WHERE lifecycle = 'active') AS active,
                   count(*) FILTER (WHERE enabled AND status = 'dead') AS down
            FROM proxies WHERE deleted_at IS NULL GROUP BY provider""")
        inc = {r["provider"]: r for r in await db.fetch("""
            SELECT p.provider, count(*) AS n, count(*) FILTER (WHERE i.reason = 'timeout') AS timeouts
            FROM incidents i JOIN proxies p ON p.id = i.proxy_id
            WHERE i.started_at > now() - $1::text::interval GROUP BY p.provider""", CHECK_WINDOWS[win])}
        prices = await provider_prices()
        out = []
        for lv in live:
            st = [r for r in stats if r["provider"] == lv["provider"]]
            checks = sum(r["checks"] for r in st)
            failed = sum(r["failed"] for r in st)
            lat = [r["avg_ms"] for r in st if r["avg_ms"] is not None]
            out.append(dict(lv, checks=checks, failed=failed,
                            fail_pct=round(100.0 * failed / checks, 2) if checks else None,
                            flaky=sum(1 for r in st if r["failed"]),
                            timeouts=sum(r["timeouts"] for r in st),
                            avg_ms=round(sum(lat) / len(lat)) if lat else None,
                            incidents=(inc.get(lv["provider"]) or {}).get("n", 0),
                            price=prices.get(lv["provider"])))
        out.sort(key=lambda r: (r["fail_pct"] is None, -(r["fail_pct"] or 0)))
        ctx.update(rows=out, win=win, windows=CHECK_WINDOWS)
    else:
        win, sql, args = _incident_query(q)
        rows = await db.fetch(sql + " LIMIT 1000", *args)
        ctx.update(tab="incidents", rows=rows, win=win, windows=INC_WINDOWS)
    return render(request, "health.html", **ctx)


@login_required
async def incidents_csv(request):
    import csv
    import io
    _, sql, args = _incident_query(request.query_params)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["#", "Name", "IP:Port", "Provider", "Region", "Use case", "Started (UTC)", "Ended (UTC)",
                "Duration (min)", "Reason", "First error", "Last error", "How it ended"])
    for r in await db.fetch(sql, *args):
        w.writerow([r["seq"], r["label"], "%s:%s" % (r["host"], r["port"]), r["provider"], r["region"],
                    r["usecase"] or r["now_usecase"] or "", fmt_ts(r["started_at"]), fmt_ts(r["ended_at"]) or "ongoing",
                    round(r["secs"] / 60, 1), health.LABELS.get(r["reason"], r["reason"]), r["error"], r["last_error"],
                    r["end_note"]])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="incidents-%s.csv"' % stamp})


DEFAULT_PRICES = {"gcp": 8.0, "do": 4.0, "digitalocean": 4.0, "vu": 5.0, "vultr": 5.0, "cherry": 3.51}


async def provider_prices():
    raw = await db.get_meta("provider_prices")
    try:
        saved = json.loads(raw) if raw else {}
    except ValueError:
        saved = {}
    out = dict(DEFAULT_PRICES)
    out.update({k: float(v) for k, v in saved.items() if v not in (None, "")})
    return out


# ---------- users ----------

USERNAME_RE = re.compile(r"^[a-z0-9._-]{2,32}$")


def _new_password():
    return secrets.token_urlsafe(9)


@admin_required
async def users_page(request):
    me = request.scope["pm_user"]
    if request.method == "POST":
        form = await request.form()
        action = form.get("action")
        target = None
        if form.get("uid", "").isdigit():
            target = await db.fetchrow("SELECT * FROM users WHERE id = $1", int(form["uid"]))
        admins = await db.fetchval("SELECT count(*) FROM users WHERE is_admin")
        if action == "add":
            name = str(form.get("username", "")).strip().lower()
            pw = str(form.get("password", "")).strip() or _new_password()
            if not USERNAME_RE.match(name):
                flash(request, "Username: 2–32 characters, lowercase letters, digits, dot, dash, underscore.", "err")
            elif len(pw) < 8:
                flash(request, "Password must be at least 8 characters (or leave it empty to generate one).", "err")
            elif await db.fetchval("SELECT 1 FROM users WHERE username = $1", name):
                flash(request, "User %s already exists." % name, "err")
            else:
                admin = form.get("is_admin") == "1"
                await db.execute("INSERT INTO users (username, pass_hash, is_admin) VALUES ($1, $2, $3)",
                                 name, hash_password(pw), admin)
                await db.log_event("user", "Added %s %s" % ("admin" if admin else "user", name))
                flash(request, "Added %s. Password: %s — send it to them; they can change it under their name (top right)."
                      % (name, pw))
        elif target and action == "reset":
            pw = _new_password()
            await db.execute("UPDATE users SET pass_hash = $2, pw_changed_at = now() WHERE id = $1",
                             target["id"], hash_password(pw))
            await db.log_event("user", "Reset password of %s" % target["username"])
            flash(request, "New password for %s: %s — their old sessions are logged out." % (target["username"], pw))
            if target["id"] == me["id"]:
                return RedirectResponse("/login", status_code=303)
        elif target and action == "toggle_admin":
            if target["is_admin"] and admins <= 1:
                flash(request, "Can't remove the last admin.", "err")
            else:
                await db.execute("UPDATE users SET is_admin = NOT is_admin WHERE id = $1", target["id"])
                await db.log_event("user", "%s is now %s" % (target["username"], "a normal user" if target["is_admin"] else "an admin"))
                flash(request, "%s is now %s." % (target["username"], "a normal user" if target["is_admin"] else "an admin"))
        elif target and action == "delete":
            if target["id"] == me["id"]:
                flash(request, "You can't delete yourself.", "err")
            elif target["is_admin"] and admins <= 1:
                flash(request, "Can't delete the last admin.", "err")
            else:
                await db.execute("DELETE FROM users WHERE id = $1", target["id"])
                await db.log_event("user", "Deleted user %s" % target["username"])
                flash(request, "Deleted %s — they're logged out." % target["username"])
        return RedirectResponse("/users", status_code=303)
    users = await db.fetch("""
        SELECT u.*, (SELECT count(*) FROM events e WHERE e.actor = u.username AND e.ts > now() - interval '7 days') AS changes
        FROM users u ORDER BY is_admin DESC, username""")
    return render(request, "users.html", users=users, me=me)


@login_required
async def account_page(request):
    me = request.scope["pm_user"]
    if request.method == "POST":
        form = await request.form()
        cur, new, again = str(form.get("current", "")), str(form.get("new", "")), str(form.get("again", ""))
        if not verify_password(cur, me["pass_hash"]):
            flash(request, "Current password is wrong.", "err")
        elif len(new) < 8:
            flash(request, "New password must be at least 8 characters.", "err")
        elif new != again:
            flash(request, "The two new passwords don't match.", "err")
        else:
            await db.execute("UPDATE users SET pass_hash = $2, pw_changed_at = now() WHERE id = $1",
                             me["id"], hash_password(new))
            u = await db.fetchrow("SELECT * FROM users WHERE id = $1", me["id"])
            request.session["pw"] = _pw_stamp(u)  # stay logged in here; other sessions end
            await db.log_event("user", "%s changed their password" % me["username"])
            flash(request, "Password changed. Other devices are logged out.")
        return RedirectResponse("/account", status_code=303)
    return render(request, "account.html", me=me)


# ---------- public endpoints ----------

async def healthz(request):
    try:
        await db.fetchval("SELECT 1")
        return JSONResponse({"ok": True})
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": str(e)}, status_code=503)


async def favicon(request):
    return FileResponse(os.path.join(HERE, "static", "favicon.ico"), media_type="image/x-icon",
                        headers={"Cache-Control": "public, max-age=604800"})


async def node_script(request):
    return FileResponse(os.path.join(HERE, "static", "install-node.sh"), media_type="text/plain")


async def api_ip(request):
    return PlainTextResponse(client_ip(request) + "\n")


# ---------- API ----------

async def _select_proxies(request):
    q = request.query_params
    where, args = ["p.enabled"], []

    def arg(v):
        args.append(v)
        return "$%d" % len(args)

    status = q.get("status", "healthy")
    if status != "all":
        where.append("p.status = " + arg(status))
    if q.get("free") in ("1", "true"):
        where.append("a.id IS NULL AND p.lifecycle = 'ready' AND p.deleted_at IS NULL")
    protocol = q.get("protocol", "all")
    if protocol in ("http", "socks5"):
        where.append("p.protocol = " + arg(protocol))
    for field in ("provider", "country", "region"):
        if q.get(field):
            vals = [v.strip() for v in q[field].split(",") if v.strip()]
            where.append("p.%s = ANY(%s::text[])" % (field, arg(vals)))
    if q.get("smtp") in ("1", "true", "ok"):
        where.append("p.smtp_ok IS TRUE")
    if q.get("max_latency", "").isdigit():
        where.append("p.last_latency_ms <= " + arg(int(q["max_latency"])))
    rows = await db.fetch("SELECT p.*, a.name AS app_name FROM proxies p LEFT JOIN apps a ON a.proxy_id = p.id "
                          "WHERE %s ORDER BY p.last_latency_ms NULLS LAST, p.id" % " AND ".join(where), *args)
    if q.get("shuffle") in ("1", "true"):
        random.shuffle(rows)
    if q.get("limit", "").isdigit():
        rows = rows[: int(q["limit"])]
    return rows


@api_auth
async def api_proxies(request):
    rows = await _select_proxies(request)
    fmt = request.query_params.get("format", "json")
    if fmt == "txt":
        return PlainTextResponse("".join("%s:%s:%s:%s\n" % (p["host"], p["port"], p["username"], p["password"]) for p in rows))
    if fmt == "url":
        return PlainTextResponse("".join(proxy_url(p) + "\n" for p in rows))
    return JSONResponse({"count": len(rows), "proxies": [proxy_public(p) for p in rows]})


@api_auth
async def api_random(request):
    rows = await _select_proxies(request)
    if not rows:
        return JSONResponse({"error": "no healthy proxy matches"}, status_code=404)
    return JSONResponse(proxy_public(random.choice(rows)))


@api_auth
async def api_report(request):
    """Apps call this when a proxy fails them. It's logged and the proxy is rechecked immediately."""
    try:
        data = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    p = None
    if str(data.get("proxy_id", "")).isdigit():
        p = await db.fetchrow("SELECT * FROM proxies WHERE id = $1", int(data["proxy_id"]))
    elif data.get("host"):
        if str(data.get("port", "")).isdigit():
            p = await db.fetchrow("SELECT * FROM proxies WHERE host = $1 AND port = $2", str(data["host"]), int(data["port"]))
        else:
            p = await db.fetchrow("SELECT * FROM proxies WHERE host = $1 ORDER BY id LIMIT 1", str(data["host"]))
    if not p:
        return JSONResponse({"error": "proxy not found"}, status_code=404)
    await db.execute("INSERT INTO reports (proxy_id, source, error) VALUES ($1, $2, $3)",
                     p["id"], clean(data.get("source"), 64), str(data.get("error", ""))[:500])
    await db.execute("UPDATE proxies SET recheck = true WHERE id = $1", p["id"])
    return JSONResponse({"ok": True, "proxy_id": p["id"], "rechecking": True})


@api_auth
async def api_stats(request):
    s = await db.fetchrow("""
        SELECT count(*) FILTER (WHERE enabled AND status = 'healthy') AS healthy,
               count(*) FILTER (WHERE enabled AND status = 'dead') AS dead,
               count(*) FILTER (WHERE enabled AND status = 'unknown') AS unknown,
               count(*) FILTER (WHERE NOT enabled) AS disabled,
               count(*) AS total
        FROM proxies
    """)
    return JSONResponse({k: int(v) for k, v in s.items()})


async def api_enroll(request):
    """Called by install-node.sh / proxynode-sync on each node. Idempotent."""
    try:
        data = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    token = request.headers.get("x-enroll-token") or data.get("token")
    if not settings.enroll_token or not key_ok(token, [settings.enroll_token]):
        return JSONResponse({"error": "invalid enroll token"}, status_code=403)
    ip = str(data.get("public_ip") or "").strip() or client_ip(request)
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return JSONResponse({"error": "could not determine node public IP"}, status_code=400)
    provider = clean(data.get("provider"), 32) or "other"
    country = clean(data.get("country"), 8).upper() or "US"
    region = clean(data.get("region"), 32)
    label = clean(data.get("label"))
    wanted = []
    if data.get("socks", False):
        wanted.append(("socks5", int(data.get("socks_port") or settings.node_socks_port)))
    if data.get("http", True):
        wanted.append(("http", int(data.get("http_port") or settings.node_http_port)))

    existing = await db.fetchrow(
        "SELECT username, password FROM proxies WHERE host = $1 AND source = 'enrolled' AND username <> '' ORDER BY id LIMIT 1", ip)
    if existing:
        user, pw = existing["username"], existing["password"]
    else:
        user, pw = "px" + secrets.token_hex(4), secrets.token_urlsafe(18).replace("-", "x").replace("_", "y")

    created = 0
    for protocol, port in wanted:
        row = await db.fetchrow("""
            INSERT INTO proxies (label, provider, country, region, protocol, host, port, username, password, source,
                                 recheck, last_seen_sync_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'enrolled', true, now())
            ON CONFLICT (host, port) DO UPDATE SET last_seen_sync_at = now(), protocol = EXCLUDED.protocol,
                username = EXCLUDED.username, password = EXCLUDED.password, source = 'enrolled'
            RETURNING (xmax = 0) AS inserted
        """, label, provider, country, region, protocol, ip, port, user, pw)
        created += 1 if row["inserted"] else 0
    if created:
        msg = "Node enrolled: %s (%s, %s%s)" % (ip, provider, country, ", " + label if label else "")
        await db.log_event("enroll", msg)
        await alerts.send("🆕 " + msg)
    return JSONResponse({
        "username": user, "password": pw,
        "socks_port": next((p for proto, p in wanted if proto == "socks5"), None),
        "http_port": next((p for proto, p in wanted if proto == "http"), None),
        "allowed_cidrs": await allowed_cidrs(),
        "public_ip": ip, "created": bool(created),
    })


# ---------- app ----------

@contextlib.asynccontextmanager
async def lifespan(app):
    await db.init_pool()
    await db.apply_schema()
    yield
    await db.close_pool()


routes = [
    Route("/", dashboard),
    Route("/login", login, methods=["GET", "POST"]),
    Route("/logout", logout),
    Route("/proxy/{pid:int}", proxy_detail),
    Route("/proxy/{pid:int}/action", proxy_action, methods=["POST"]),
    Route("/proxy/{pid:int}/quick", proxy_quick, methods=["POST"]),
    Route("/export/proxies.csv", proxies_csv),
    Route("/bulk", bulk_action, methods=["POST"]),
    Route("/add", add_proxies, methods=["GET", "POST"]),
    Route("/events", events_page),
    Route("/events.csv", events_csv),
    Route("/health", health_page),
    Route("/health/incidents.csv", incidents_csv),
    Route("/apps", apps_page),
    Route("/apps/import", apps_import, methods=["POST"]),
    Route("/apps/bulk", apps_bulk, methods=["POST"]),
    Route("/apps/export.csv", apps_csv),
    Route("/apps/{aid:int}", app_detail, methods=["GET", "POST"]),
    Route("/settings", settings_page, methods=["GET", "POST"]),
    Route("/users", users_page, methods=["GET", "POST"]),
    Route("/account", account_page, methods=["GET", "POST"]),
    Route("/healthz", healthz),
    Route("/favicon.ico", favicon),
    Route("/install-node.sh", node_script),
    Route("/api/v1/ip", api_ip),
    Route("/api/v1/proxies", api_proxies),
    Route("/api/v1/proxies/random", api_random),
    Route("/api/v1/report", api_report, methods=["POST"]),
    Route("/api/v1/stats", api_stats),
    Route("/api/v1/apps", api_apps),
    Route("/api/v1/apps/{name:path}/proxy", api_app_proxy),
    Route("/api/v1/nodes/enroll", api_enroll, methods=["POST"]),
    Mount("/static", app=StaticFiles(directory=os.path.join(HERE, "static")), name="static"),
]

app = Starlette(
    routes=routes,
    lifespan=lifespan,
    middleware=[Middleware(SessionMiddleware, secret_key=settings.secret_key, session_cookie="pm_session",
                           max_age=7 * 86400, same_site="lax", https_only=settings.cookie_secure)],
)
