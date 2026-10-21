"""Thin asyncpg wrapper."""
import contextvars
import os

import asyncpg

from .config import settings

_pool = None
# who is acting (dashboard username, or "system" for the checker); stamped on events
current_actor = contextvars.ContextVar("actor", default="system")


async def init_pool():
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=settings.db_pool_size)
    return _pool


async def close_pool():
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
# who is acting (dashboard username, or "system" for the checker); stamped on events
current_actor = contextvars.ContextVar("actor", default="system")


async def fetch(query, *args):
    async with _pool.acquire() as c:
        return [dict(r) for r in await c.fetch(query, *args)]


async def fetchrow(query, *args):
    async with _pool.acquire() as c:
        r = await c.fetchrow(query, *args)
        return dict(r) if r is not None else None


async def fetchval(query, *args):
    async with _pool.acquire() as c:
        return await c.fetchval(query, *args)


async def execute(query, *args):
    async with _pool.acquire() as c:
        return await c.execute(query, *args)


async def executemany(query, rows):
    if not rows:
        return
    async with _pool.acquire() as c:
        await c.executemany(query, rows)


async def apply_schema():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
    with open(path) as fh:
        sql = fh.read()
    async with _pool.acquire() as c:
        # API workers and the checker start together; serialize schema creation
        await c.execute("SELECT pg_advisory_lock(80420261)")
        try:
            await c.execute(sql)
            # one-time: proxies that already had an app become "active"
            if not await c.fetchval("SELECT value FROM meta WHERE key = 'migr_lifecycle_v1'"):
                await c.execute("UPDATE proxies SET lifecycle = 'active', last_usecase = a.name "
                                "FROM apps a WHERE a.proxy_id = proxies.id")
                await c.execute("INSERT INTO meta (key, value) VALUES ('migr_lifecycle_v1', '1') ON CONFLICT DO NOTHING")
            # one-time (1.1.0): rebuild past outages from status events; flag past mass-failure checks
            if not await c.fetchval("SELECT value FROM meta WHERE key = 'migr_incidents_v1'"):
                from . import health
                n = await health.backfill(c)
                await c.execute("""UPDATE checks c SET mass = true FROM events e
                                   WHERE e.kind = 'mass_failure' AND NOT c.ok
                                     AND c.ts BETWEEN e.ts - interval '3 minutes' AND e.ts + interval '1 minute'""")
                await c.execute("INSERT INTO meta (key, value) VALUES ('migr_incidents_v1', $1) ON CONFLICT DO NOTHING",
                                "backfilled %d incidents" % n)
            # first start with the users table: the env-file admin becomes the first admin user
            if not await c.fetchval("SELECT count(*) FROM users") and settings.admin_pass_hash:
                await c.execute("INSERT INTO users (username, pass_hash, is_admin) VALUES ($1, $2, true) "
                                "ON CONFLICT (username) DO NOTHING", settings.admin_user.lower(), settings.admin_pass_hash)
        finally:
            await c.execute("SELECT pg_advisory_unlock(80420261)")


async def get_meta(key, default=None):
    v = await fetchval("SELECT value FROM meta WHERE key = $1", key)
    return default if v is None else v


async def set_meta(key, value):
    await execute(
        "INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        key, value,
    )


async def log_event(kind, message, proxy_id=None, app_id=None):
    await execute("INSERT INTO events (kind, message, proxy_id, app_id, actor) VALUES ($1, $2, $3, $4, $5)",
                  kind, message, proxy_id, app_id, current_actor.get())
