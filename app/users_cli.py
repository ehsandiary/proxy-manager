"""Manage dashboard users from the server shell (installed as `proxymgr-user`).

  proxymgr-user list
  proxymgr-user set NAME [--password PASS] [--admin | --no-admin]   create or update (password generated if omitted)
  proxymgr-user delete NAME
"""
import asyncio
import secrets
import sys

from . import db
from .security import hash_password


async def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    await db.init_pool()
    await db.apply_schema()
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "list":
            for u in await db.fetch("SELECT * FROM users ORDER BY is_admin DESC, username"):
                print("%-20s %-6s last login: %s" % (u["username"], "admin" if u["is_admin"] else "user",
                                                    u["last_login_at"] or "never"))
            return 0
        if cmd in ("set", "delete") and not rest:
            print("username required")
            return 2
        name = rest[0].strip().lower() if rest else ""
        if cmd == "delete":
            n = await db.fetchval("DELETE FROM users WHERE username = $1 RETURNING 1", name)
            print("deleted %s" % name if n else "no such user %s" % name)
            return 0 if n else 1
        if cmd == "set":
            pw, admin = None, None
            i = 1
            while i < len(rest):
                if rest[i] == "--password" and i + 1 < len(rest):
                    pw = rest[i + 1]
                    i += 2
                    continue
                if rest[i] == "--admin":
                    admin = True
                elif rest[i] == "--no-admin":
                    admin = False
                i += 1
            generated = pw is None
            pw = pw or secrets.token_urlsafe(9)
            existing = await db.fetchrow("SELECT * FROM users WHERE username = $1", name)
            if existing:
                await db.execute("""UPDATE users SET pass_hash = $2, pw_changed_at = now(),
                                    is_admin = COALESCE($3, is_admin) WHERE id = $1""",
                                 existing["id"], hash_password(pw), admin)
            else:
                await db.execute("INSERT INTO users (username, pass_hash, is_admin) VALUES ($1, $2, $3)",
                                 name, hash_password(pw), bool(admin))
            print("%s %s%s" % ("updated" if existing else "created", name,
                               " — password: %s" % pw if generated else ""))
            return 0
        print(__doc__.strip())
        return 2
    finally:
        await db.close_pool()


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
