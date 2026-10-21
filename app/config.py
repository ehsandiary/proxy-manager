"""Settings, read from environment (/etc/proxymgr/proxymgr.env in production)."""
import os


def _s(name, default=""):
    return os.environ.get(name, default).strip()


def _i(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return int(default)


def _f(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return float(default)


def _b(name, default="false"):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


class Settings:
    def __init__(self):
        self.database_url = _s("DATABASE_URL", "postgresql://proxymgr:proxymgr@127.0.0.1:5432/proxymgr")
        self.db_pool_size = _i("DB_POOL_SIZE", 10)
        self.secret_key = _s("SECRET_KEY", "change-me")
        self.admin_user = _s("ADMIN_USER", "admin")
        self.admin_pass_hash = _s("ADMIN_PASS_HASH")
        self.api_keys = [k.strip() for k in _s("API_KEYS").split(",") if k.strip()]
        self.enroll_token = _s("ENROLL_TOKEN")
        self.public_ip = _s("PUBLIC_IP")
        self.base_url = _s("BASE_URL").rstrip("/")
        self.cookie_secure = _b("COOKIE_SECURE", "true")
        self.app_dir = _s("APP_DIR", os.path.dirname(os.path.abspath(__file__)))

        # Health checks
        self.check_interval = _i("CHECK_INTERVAL", 30)
        self.check_timeout = _f("CHECK_TIMEOUT", 10)
        self.check_concurrency = _i("CHECK_CONCURRENCY", 100)
        # which probes decide health: "http", "smtp" or "http,smtp"
        self.check_modes = [m.strip() for m in _s("CHECK_MODES", "http").split(",") if m.strip()]
        self.check_url = _s("CHECK_URL", "https://api.ipify.org/")
        self.smtp_check_host = _s("SMTP_CHECK_HOST", "gmail-smtp-in.l.google.com")
        self.smtp_check_port = _i("SMTP_CHECK_PORT", 25)
        self.fail_threshold = _i("FAIL_THRESHOLD", 3)
        self.recover_threshold = _i("RECOVER_THRESHOLD", 2)
        # if this share of proxies fails in one round, assume the problem is on our side
        self.mass_failure_ratio = _f("MASS_FAILURE_RATIO", 0.9)
        self.mass_failure_min = _i("MASS_FAILURE_MIN", 5)
        self.retention_days = _i("RETENTION_DAYS", 14)

        # Alerts
        self.telegram_bot_token = _s("TELEGRAM_BOT_TOKEN")
        self.telegram_chat_id = _s("TELEGRAM_CHAT_ID")
        self.slack_webhook_url = _s("SLACK_WEBHOOK_URL")
        self.min_healthy = _i("MIN_HEALTHY", 0)
        self.min_spares = _i("MIN_SPARES", 0)
        self.alert_cooldown = _i("ALERT_COOLDOWN", 1800)
        # monthly cost of one proxy VM, used for the "suspended but not deleted" waste reminder
        self.proxy_monthly_cost = _f("PROXY_MONTHLY_COST", 8)
        self.waste_after_hours = _i("WASTE_AFTER_HOURS", 6)

        # Node defaults handed out at enrollment
        self.node_http_port = _i("NODE_HTTP_PORT", 3128)
        self.node_socks_port = _i("NODE_SOCKS_PORT", 1080)
        self.default_client_cidrs = _s("ALLOWED_CLIENT_CIDRS")


settings = Settings()
