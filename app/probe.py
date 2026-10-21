"""Proxy probes using plain asyncio sockets (no HTTP library needed).

Each probe opens a tunnel through the proxy (HTTP CONNECT or SOCKS5 with
user/password), then either fetches CHECK_URL over it (to learn the exit IP)
or reads the SMTP greeting from SMTP_CHECK_HOST:PORT.
"""
import asyncio
import base64
import errno
import ipaddress
import re
import ssl
import struct
import time
from urllib.parse import urlsplit

from .config import settings

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


class ProbeError(Exception):
    pass


def _ssl_ctx():
    ctx = ssl.create_default_context()
    return ctx


async def _read_until(reader, marker, limit=65536):
    data = b""
    while marker not in data:
        chunk = await reader.read(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            break
    return data


async def _socks5_tunnel(reader, writer, user, password, host, port):
    if user:
        writer.write(b"\x05\x01\x02")
    else:
        writer.write(b"\x05\x01\x00")
    await writer.drain()
    resp = await reader.readexactly(2)
    if resp[0] != 5:
        raise ProbeError("socks: bad greeting")
    if resp[1] == 0x02:
        u, p = user.encode(), password.encode()
        writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        await writer.drain()
        auth = await reader.readexactly(2)
        if auth[1] != 0:
            raise ProbeError("socks: auth rejected")
    elif resp[1] != 0x00:
        raise ProbeError("socks: no acceptable auth method")

    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            addr = b"\x01" + ip.packed
        else:
            addr = b"\x04" + ip.packed
    except ValueError:
        h = host.encode()
        addr = b"\x03" + bytes([len(h)]) + h
    writer.write(b"\x05\x01\x00" + addr + struct.pack(">H", port))
    await writer.drain()
    head = await reader.readexactly(4)
    if head[1] != 0:
        codes = {1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable",
                 4: "host unreachable", 5: "connection refused", 6: "TTL expired"}
        raise ProbeError("socks: " + codes.get(head[1], "error %d" % head[1]))
    atyp = head[3]
    if atyp == 1:
        await reader.readexactly(4 + 2)
    elif atyp == 4:
        await reader.readexactly(16 + 2)
    else:
        n = (await reader.readexactly(1))[0]
        await reader.readexactly(n + 2)


async def _http_connect_tunnel(reader, writer, user, password, host, port):
    req = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (host, port, host, port)
    if user:
        token = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        req += "Proxy-Authorization: Basic %s\r\n" % token
    req += "\r\n"
    writer.write(req.encode())
    await writer.drain()
    data = await _read_until(reader, b"\r\n\r\n")
    line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = line.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise ProbeError("http proxy: bad response")
    code = int(parts[1])
    if code == 407:
        raise ProbeError("http proxy: auth rejected (407)")
    if code != 200:
        raise ProbeError("http proxy: CONNECT %d" % code)


async def open_tunnel(proxy, host, port):
    """proxy: dict with protocol/host/port/username/password, or None for direct."""
    if proxy is None:
        return await asyncio.open_connection(host, port)
    try:
        reader, writer = await asyncio.open_connection(proxy["host"], int(proxy["port"]))
    except OSError as e:
        why = {errno.ECONNREFUSED: "connection refused", errno.EHOSTUNREACH: "no route to host",
               errno.ENETUNREACH: "network unreachable", errno.ETIMEDOUT: "timeout",
               errno.ECONNRESET: "connection reset"}.get(e.errno, e.strerror or str(e))
        raise ProbeError("connect to proxy failed: %s" % why)
    try:
        if proxy["protocol"] == "socks5":
            await _socks5_tunnel(reader, writer, proxy.get("username") or "", proxy.get("password") or "", host, port)
        else:
            await _http_connect_tunnel(reader, writer, proxy.get("username") or "", proxy.get("password") or "", host, port)
    except asyncio.IncompleteReadError:
        writer.close()
        raise ProbeError("proxy closed the connection")
    except Exception:
        writer.close()
        raise
    return reader, writer


def _decode_chunked(body):
    out = b""
    while body:
        line, _, rest = body.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return out
        if size == 0:
            break
        out += rest[:size]
        body = rest[size + 2:]
    return out


async def _http_probe(proxy):
    u = urlsplit(settings.check_url)
    host = u.hostname
    tls = u.scheme == "https"
    port = u.port or (443 if tls else 80)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    reader, writer = await open_tunnel(proxy, host, port)
    try:
        if tls:
            await writer.start_tls(_ssl_ctx(), server_hostname=host)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: proxymgr-check/1.0\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n") % (path, host)
        writer.write(req.encode())
        await writer.drain()
        data = b""
        while len(data) < 262144:
            chunk = await reader.read(16384)
            if not chunk:
                break
            data += chunk
    finally:
        writer.close()
    head, _, body = data.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise ProbeError("target: bad HTTP response")
    code = int(parts[1])
    if code >= 400:
        raise ProbeError("target: HTTP %d" % code)
    if b"transfer-encoding: chunked" in head.lower():
        body = _decode_chunked(body)
    m = IP_RE.search(body[:4096].decode("latin-1", "replace"))
    return m.group(1) if m else None


async def _smtp_probe(proxy):
    reader, writer = await open_tunnel(proxy, settings.smtp_check_host, settings.smtp_check_port)
    try:
        line = await reader.readline()
        text = line.decode("latin-1", "replace").strip()
        if not text:
            raise ProbeError("smtp: no greeting (port %d blocked?)" % settings.smtp_check_port)
        if not text.startswith("220"):
            raise ProbeError("smtp: unexpected greeting: %s" % text[:80])
        try:
            writer.write(b"QUIT\r\n")
            await writer.drain()
        except Exception:
            pass
        return text
    finally:
        writer.close()


def _err(e):
    if isinstance(e, asyncio.TimeoutError):
        return "timeout"
    if isinstance(e, ProbeError):
        return str(e)
    if isinstance(e, ssl.SSLError):
        return "tls: %s" % (e.reason or e)
    if isinstance(e, OSError):
        return "net: %s" % (e.strerror or e)
    return "%s: %s" % (type(e).__name__, e)


async def timed(coro_fn, proxy):
    t0 = time.perf_counter()
    try:
        val = await asyncio.wait_for(coro_fn(proxy), timeout=settings.check_timeout)
        return True, int((time.perf_counter() - t0) * 1000), None, val
    except Exception as e:  # noqa: BLE001
        return False, None, _err(e), None


async def check_proxy(proxy):
    """Run the configured probes. Returns a result dict."""
    res = {"http_ok": None, "smtp_ok": None, "latency_ms": None, "smtp_latency_ms": None,
           "error": None, "exit_ip": None}
    errors = []
    tasks = {}
    if "http" in settings.check_modes:
        tasks["http"] = asyncio.create_task(timed(_http_probe, proxy))
    if "smtp" in settings.check_modes:
        tasks["smtp"] = asyncio.create_task(timed(_smtp_probe, proxy))
    if "http" in tasks:
        ok, ms, err, ip = await tasks["http"]
        res.update(http_ok=ok, latency_ms=ms, exit_ip=ip)
        if err:
            errors.append(("http " + err) if len(tasks) > 1 else err)
    if "smtp" in tasks:
        ok, ms, err, _ = await tasks["smtp"]
        res.update(smtp_ok=ok, smtp_latency_ms=ms)
        if err:
            errors.append(err if err.startswith("smtp") else "smtp " + err)
    res["ok"] = all(v for k, v in res.items() if k in ("http_ok", "smtp_ok") and v is not None) and bool(tasks)
    res["error"] = "; ".join(errors)[:500] or None
    return res


async def direct_http_ok():
    """Can the main server itself reach CHECK_URL? Used to avoid blaming proxies for our own outage."""
    ok, _, err, _ = await timed(_http_probe, None)
    return ok, err
