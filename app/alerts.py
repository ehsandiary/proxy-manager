"""Alerts to Telegram and/or Slack (stdlib only). Configure either or both in the env file."""
import asyncio
import json
import logging
import time
import urllib.request

from .config import settings

log = logging.getLogger("proxymgr.alerts")
_last_sent = {}


def telegram_on():
    return bool(settings.telegram_bot_token and settings.telegram_chat_id)


def slack_on():
    return bool(settings.slack_webhook_url)


def enabled():
    return telegram_on() or slack_on()


def _post_json(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()


def _send_all(text):
    errors = []
    if telegram_on():
        try:
            _post_json("https://api.telegram.org/bot%s/sendMessage" % settings.telegram_bot_token,
                       {"chat_id": settings.telegram_chat_id, "text": text[:4000], "disable_web_page_preview": True})
        except Exception as e:  # noqa: BLE001
            errors.append("telegram: %s" % e)
    if slack_on():
        try:
            _post_json(settings.slack_webhook_url, {"text": text[:3900]})
        except Exception as e:  # noqa: BLE001
            errors.append("slack: %s" % e)
    return errors


async def send(text, key=None, cooldown=None):
    """Send to every configured channel. With `key`, repeats are suppressed for `cooldown` seconds."""
    if key:
        cd = settings.alert_cooldown if cooldown is None else cooldown
        now = time.time()
        if now - _last_sent.get(key, 0) < cd:
            return False
        _last_sent[key] = now
    log.info("ALERT: %s", text.replace("\n", " | ")[:300])
    if not enabled():
        return False
    errors = await asyncio.to_thread(_send_all, text)
    for e in errors:
        log.warning("alert send failed: %s", e)
    return not errors


def reset(key):
    _last_sent.pop(key, None)
