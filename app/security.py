"""Password hashing, CSRF and API-key helpers."""
import hashlib
import hmac
import secrets
import time


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt:%s:%s" % (salt, dk.hex())


def verify_password(password, stored):
    try:
        algo, salt, digest = stored.split(":")
    except (ValueError, AttributeError):
        return False
    if algo != "scrypt":
        return False
    return hmac.compare_digest(hash_password(password, salt), stored)


def const_eq(a, b):
    return bool(a) and bool(b) and hmac.compare_digest(str(a), str(b))


def key_ok(provided, keys):
    return any(const_eq(provided, k) for k in keys)


def csrf_token(session):
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(24)
        session["csrf"] = tok
    return tok


class LoginLimiter:
    """At most `limit` failed logins per IP per `window` seconds."""

    def __init__(self, limit=10, window=900):
        self.limit, self.window, self.fails = limit, window, {}

    def blocked(self, ip):
        now = time.time()
        recent = [t for t in self.fails.get(ip, []) if now - t < self.window]
        self.fails[ip] = recent
        return len(recent) >= self.limit

    def fail(self, ip):
        self.fails.setdefault(ip, []).append(time.time())

    def clear(self, ip):
        self.fails.pop(ip, None)


if __name__ == "__main__":
    import getpass
    import sys

    pw = sys.argv[1] if len(sys.argv) > 1 else getpass.getpass("Password: ")
    print(hash_password(pw))
