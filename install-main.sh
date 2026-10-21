#!/usr/bin/env bash
# Proxy Manager — main server installer (dashboard, health checker, pool API).
# Installs PostgreSQL, nginx (TLS), a Python app and two systemd services on Ubuntu 24.04 / 26.04.
#
#   sudo bash proxymgr-install.sh [options]
#
# Options (all optional):
#   --domain NAME         DNS name pointing at this server -> free Let's Encrypt certificate.
#                         Without it a self-signed certificate is used (browser warning).
#   --email ADDR          email for Let's Encrypt (recommended with --domain)
#   --admin-user NAME     dashboard login (default: admin)
#   --admin-pass PASS     dashboard password for --admin-user (generated on first install; on a re-run it resets it)
#   --telegram-token T    Telegram bot token for alerts
#   --telegram-chat ID    Telegram chat/group id for alerts
#   --slack-webhook URL   Slack incoming-webhook URL for alerts
#   --client-cidrs LIST   comma-separated IPs/CIDRs of your app servers allowed to use the proxies
#                         (empty = open to any IP, password auth only)
#   --min-healthy N       alert when fewer than N proxies are healthy
#   --min-spares N        alert when fewer than N spare healthy proxies are left
#
# Re-running upgrades the app in place and keeps the database, secrets and settings.
# Options given on a re-run update the matching settings.
set -euo pipefail

BACKUP_FILE=""
DOMAIN="" EMAIL="" ADMIN_USER="" ADMIN_PASS="" TG_TOKEN="" TG_CHAT="" SLACK_URL="" CLIENT_CIDRS="" MIN_HEALTHY="" MIN_SPARES=""
die() { echo "ERROR: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --admin-user) ADMIN_USER="$2"; shift 2 ;;
    --admin-pass) ADMIN_PASS="$2"; shift 2 ;;
    --telegram-token) TG_TOKEN="$2"; shift 2 ;;
    --telegram-chat) TG_CHAT="$2"; shift 2 ;;
    --slack-webhook) SLACK_URL="$2"; shift 2 ;;
    --client-cidrs) CLIENT_CIDRS="$2"; shift 2 ;;
    --min-healthy) MIN_HEALTHY="$2"; shift 2 ;;
    --min-spares) MIN_SPARES="$2"; shift 2 ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash $0)"
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || die "Ubuntu 24.04 or 26.04 required (found ${PRETTY_NAME:-unknown})"
grep -q '^__PAYLOAD__$' "$0" 2>/dev/null || die "run the downloaded file directly (sudo bash proxymgr-install.sh), not through a pipe"

APP=/opt/proxymgr
ETC=/etc/proxymgr
ENVF=$ETC/proxymgr.env
FIRST_INSTALL=1
[ -f "$ENVF" ] && FIRST_INSTALL=0

# Unpack into a staging folder first: nothing on the server changes until the backup below succeeded.
STAGE="$(mktemp -d /tmp/proxymgr-stage.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT
sed -n '/^__PAYLOAD__$/,$p' "$0" | tail -n +2 | base64 -d | tar xz -C "$STAGE"
NEW_VERSION="$(cat "$STAGE/VERSION" 2>/dev/null || echo unknown)"
OLD_VERSION="$(cat "$APP/current/VERSION" 2>/dev/null || echo "1.0 (before versioning)")"
install -m 755 "$STAGE/tools/proxymgr-backup" /usr/local/sbin/proxymgr-backup
install -m 755 "$STAGE/tools/proxymgr-restore" /usr/local/sbin/proxymgr-restore

if [ "$FIRST_INSTALL" = 0 ]; then
  echo "==> Upgrading $OLD_VERSION -> $NEW_VERSION"
  echo "==> Backing up the database before changing anything"
  if sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='proxymgr'" 2>/dev/null | grep -q 1; then
    BACKUP_FILE="$(/usr/local/sbin/proxymgr-backup pre-upgrade)" || die "database backup FAILED — nothing was changed. Free some disk space or check PostgreSQL, then re-run."
    echo "    $BACKUP_FILE"
  else
    echo "    (no proxymgr database yet — nothing to back up)"
  fi
fi

echo "==> Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-venv python3-dev build-essential postgresql nginx ufw curl openssl certbot iproute2 >/dev/null

echo "==> Unpacking application"
id proxymgr >/dev/null 2>&1 || useradd -r -m -d "$APP" -s /usr/sbin/nologin proxymgr
REL="$APP/releases/$(date +%Y%m%d-%H%M%S)"
install -d "$REL"
cp -a "$STAGE/." "$REL/"
ln -sfn "$REL" "$APP/current"
# keep the 3 newest releases
ls -1dt "$APP"/releases/* | tail -n +4 | xargs -r rm -rf
chown -R proxymgr:proxymgr "$APP"

echo "==> Python environment"
[ -x "$APP/venv/bin/python" ] || sudo -u proxymgr python3 -m venv "$APP/venv"
sudo -u proxymgr "$APP/venv/bin/pip" install -q --upgrade pip
sudo -u proxymgr "$APP/venv/bin/pip" install -q -r "$APP/current/requirements.txt"

PUBLIC_IP="$(curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)"
[ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
[ -n "$PUBLIC_IP" ] || die "could not detect this server's public IP"
rand() { openssl rand -hex "$1"; }

set_env() {  # set_env KEY VALUE  (replace or append in $ENVF)
  python3 - "$ENVF" "$1" "$2" <<'PY'
import sys
path, key, val = sys.argv[1:4]
lines = open(path).read().splitlines()
out, done = [], False
for l in lines:
    if l.split("=", 1)[0] == key:
        out.append("%s=%s" % (key, val)); done = True
    else:
        out.append(l)
if not done:
    out.append("%s=%s" % (key, val))
open(path, "w").write("\n".join(out) + "\n")
PY
}
get_env() { grep -E "^$1=" "$ENVF" 2>/dev/null | head -1 | cut -d= -f2-; }
ensure_env() {  # add KEY=VALUE only if KEY is missing (never touches existing settings)
  grep -qE "^$1=" "$ENVF" 2>/dev/null || printf '%s=%s\n' "$1" "$2" >> "$ENVF"
}

install -d -m 750 -o root -g proxymgr "$ETC"
if [ "$FIRST_INSTALL" = 1 ]; then
  echo "==> Generating secrets"
  DB_PASS="$(rand 16)"
  [ -n "$ADMIN_PASS" ] || ADMIN_PASS="$(rand 9)"
  GENERATED_ADMIN_PASS="$ADMIN_PASS"
  cat > "$ENVF" <<EOF
# Proxy Manager settings. After editing: systemctl restart proxymgr-api proxymgr-checker
APP_DIR=$APP/current/app
DATABASE_URL=postgresql://proxymgr:$DB_PASS@127.0.0.1:5432/proxymgr
SECRET_KEY=$(rand 32)
ADMIN_USER=${ADMIN_USER:-admin}
ADMIN_PASS_HASH=
# comma-separated; give each app its own key if you like
API_KEYS=$(rand 20)
ENROLL_TOKEN=$(rand 16)
PUBLIC_IP=$PUBLIC_IP
BASE_URL=
COOKIE_SECURE=true

# Health checks
CHECK_INTERVAL=30
CHECK_TIMEOUT=10
CHECK_CONCURRENCY=100
# http = HTTPS request through the proxy (also records the exit IP).
# Add ,smtp to also require an SMTP greeting from SMTP_CHECK_HOST:SMTP_CHECK_PORT through it.
CHECK_MODES=http
CHECK_URL=https://api.ipify.org/
SMTP_CHECK_HOST=gmail-smtp-in.l.google.com
SMTP_CHECK_PORT=25
FAIL_THRESHOLD=3
RECOVER_THRESHOLD=2
RETENTION_DAYS=14

# Alerts
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
# Slack: an Incoming Webhook URL (https://hooks.slack.com/services/...)
SLACK_WEBHOOK_URL=
MIN_HEALTHY=0
# alert when fewer than N healthy proxies are free for new/replaced apps
MIN_SPARES=0
ALERT_COOLDOWN=1800
# monthly cost of one proxy VM, for the 'suspended but not deleted' reminder
PROXY_MONTHLY_COST=8
WASTE_AFTER_HOURS=6

# Defaults handed to new nodes
NODE_SOCKS_PORT=1080
NODE_HTTP_PORT=3128
# Empty = proxy ports open to any IP (password auth only, like the old GCP Squids).
# Better: list your app servers' IPs here or on the Settings page.
ALLOWED_CLIENT_CIDRS=
EOF
fi
chown root:proxymgr "$ENVF"; chmod 640 "$ENVF"
# settings added in later versions (existing values are kept)
ensure_env BACKUP_DIR /var/backups/proxymgr
ensure_env BACKUP_KEEP_DAYS 7

[ -n "$ADMIN_USER" ] && set_env ADMIN_USER "$ADMIN_USER"
if [ -n "$ADMIN_PASS" ]; then
  set_env ADMIN_PASS_HASH "$("$APP/venv/bin/python" "$APP/current/app/security.py" "$ADMIN_PASS")"
fi
[ -n "$TG_TOKEN" ] && set_env TELEGRAM_BOT_TOKEN "$TG_TOKEN"
[ -n "$TG_CHAT" ] && set_env TELEGRAM_CHAT_ID "$TG_CHAT"
[ -n "$SLACK_URL" ] && set_env SLACK_WEBHOOK_URL "$SLACK_URL"
[ -n "$CLIENT_CIDRS" ] && set_env ALLOWED_CLIENT_CIDRS "$CLIENT_CIDRS"
[ -n "$MIN_HEALTHY" ] && set_env MIN_HEALTHY "$MIN_HEALTHY"
[ -n "$MIN_SPARES" ] && set_env MIN_SPARES "$MIN_SPARES"
set_env APP_DIR "$APP/current/app"
set_env PUBLIC_IP "$PUBLIC_IP"
if [ -n "$DOMAIN" ]; then set_env BASE_URL "https://$DOMAIN"; fi
[ -z "$(get_env BASE_URL)" ] && set_env BASE_URL "https://$PUBLIC_IP"

echo "==> PostgreSQL"
systemctl enable --now postgresql >/dev/null
DB_PASS="$(get_env DATABASE_URL | sed -E 's#^postgresql://proxymgr:([^@]+)@.*#\1#')"
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='proxymgr'" | grep -q 1; then
  sudo -u postgres psql -q -c "ALTER ROLE proxymgr WITH LOGIN PASSWORD '$DB_PASS'"
else
  sudo -u postgres psql -q -c "CREATE ROLE proxymgr WITH LOGIN PASSWORD '$DB_PASS'"
fi
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='proxymgr'" | grep -q 1 \
  || sudo -u postgres createdb -O proxymgr proxymgr

echo "==> systemd services"
cat > /etc/systemd/system/proxymgr-api.service <<EOF
[Unit]
Description=Proxy Manager web/API
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
User=proxymgr
Group=proxymgr
EnvironmentFile=$ENVF
WorkingDirectory=$APP/current
ExecStart=$APP/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2 --proxy-headers --forwarded-allow-ips 127.0.0.1 --no-access-log
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/proxymgr-checker.service <<EOF
[Unit]
Description=Proxy Manager health checker
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
User=proxymgr
Group=proxymgr
EnvironmentFile=$ENVF
WorkingDirectory=$APP/current
ExecStart=$APP/venv/bin/python -m app.checker
Restart=always
RestartSec=5
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/proxymgr-backup.service <<EOF
[Unit]
Description=Proxy Manager daily database backup
After=postgresql.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/proxymgr-backup daily
EOF
cat > /etc/systemd/system/proxymgr-backup.timer <<EOF
[Unit]
Description=Proxy Manager daily database backup

[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=20min
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable proxymgr-api proxymgr-checker >/dev/null
systemctl enable --now proxymgr-backup.timer >/dev/null
systemctl restart proxymgr-api proxymgr-checker

cat > /usr/local/bin/proxymgr-user <<EOF
#!/usr/bin/env bash
# Manage dashboard users: proxymgr-user list | set NAME [--password P] [--admin|--no-admin] | delete NAME
set -a; . $ENVF; set +a
cd $APP/current && PYTHONDONTWRITEBYTECODE=1 exec $APP/venv/bin/python -m app.users_cli "\$@"
EOF
chmod 750 /usr/local/bin/proxymgr-user

echo "==> nginx + TLS"
install -d -m 755 /var/www/acme "$ETC/tls"
if [ ! -f "$ETC/tls/cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout "$ETC/tls/key.pem" -out "$ETC/tls/cert.pem" \
    -subj "/CN=${DOMAIN:-$PUBLIC_IP}" -addext "subjectAltName=IP:$PUBLIC_IP${DOMAIN:+,DNS:$DOMAIN}" 2>/dev/null
  chmod 600 "$ETC/tls/key.pem"
fi
CERT="$ETC/tls/cert.pem" KEY="$ETC/tls/key.pem"
[ -n "$DOMAIN" ] && [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ] && \
  CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem" KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

write_nginx() {
  cat > /etc/nginx/sites-available/proxymgr <<EOF
limit_req_zone \$binary_remote_addr zone=pm_login:10m rate=10r/m;

server {
    listen 80 default_server;
    server_name _;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl default_server;
    server_name ${DOMAIN:-_};
    ssl_certificate $1;
    ssl_certificate_key $2;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 4m;
    server_tokens off;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy same-origin always;

    location = /login {
        limit_req zone=pm_login burst=5 nodelay;
        proxy_pass http://127.0.0.1:8000;
        include /etc/nginx/proxy_params;
    }
    location / {
        proxy_pass http://127.0.0.1:8000;
        include /etc/nginx/proxy_params;
        proxy_read_timeout 60s;
    }
}
EOF
  ln -sfn /etc/nginx/sites-available/proxymgr /etc/nginx/sites-enabled/proxymgr
  rm -f /etc/nginx/sites-enabled/default
  nginx -t -q && systemctl reload nginx
}
systemctl enable --now nginx >/dev/null
write_nginx "$CERT" "$KEY"

echo "==> Firewall"
SSH_PORT="$(ss -tlnpH 2>/dev/null | awk '/sshd/ {n=split($4,a,":"); print a[n]; exit}' || true)"
ufw allow "${SSH_PORT:-22}/tcp" >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null

if [ -n "$DOMAIN" ] && [ "$CERT" = "$ETC/tls/cert.pem" ]; then
  echo "==> Requesting Let's Encrypt certificate for $DOMAIN"
  if [ -n "$EMAIL" ]; then CB_MAIL=(-m "$EMAIL"); else CB_MAIL=(--register-unsafely-without-email); fi
  if certbot certonly --webroot -w /var/www/acme -d "$DOMAIN" --non-interactive --agree-tos \
       "${CB_MAIL[@]}" --deploy-hook "systemctl reload nginx"; then
    write_nginx "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
  else
    echo "    WARNING: certificate request failed (does $DOMAIN point to $PUBLIC_IP, and is port 80 open"
    echo "    in your provider's firewall?). Keeping the self-signed certificate; re-run this installer to retry."
  fi
fi

echo "==> Waiting for the app"
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1 && break
  sleep 1
done
if ! curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1; then
  journalctl -u proxymgr-api -n 40 --no-pager
  PREV="$(ls -1dt "$APP"/releases/* | sed -n 2p)"
  echo >&2
  echo "The new version did not start. Your data is safe${BACKUP_FILE:+ (backup: $BACKUP_FILE)}." >&2
  [ -n "$PREV" ] && echo "Go back to the previous version:  sudo ln -sfn $PREV $APP/current && sudo systemctl restart proxymgr-api proxymgr-checker" >&2
  die "app did not start"
fi

if [ -n "$ADMIN_PASS" ]; then
  /usr/local/bin/proxymgr-user set "$(get_env ADMIN_USER)" --password "$ADMIN_PASS" --admin >/dev/null
fi

BASE="$(get_env BASE_URL)"
INSECURE_FLAG=""
CURLK="curl -fsSL"
if [ -z "$DOMAIN" ] || [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then INSECURE_FLAG=" --insecure"; CURLK="curl -fsSLk"; fi

SUMMARY="$(cat <<EOF
Proxy Manager $NEW_VERSION is running.${BACKUP_FILE:+
  Backup taken before upgrading: $BACKUP_FILE}

  Dashboard:     $BASE
  Login:         $(get_env ADMIN_USER) / ${GENERATED_ADMIN_PASS:-${ADMIN_PASS:-(unchanged)}}
  API key:       $(get_env API_KEYS | cut -d, -f1)
  Enroll token:  $(get_env ENROLL_TOKEN)

Add a proxy node (run on each new Ubuntu VM):
  $CURLK $BASE/install-node.sh | sudo bash -s -- --main $BASE --token $(get_env ENROLL_TOKEN) --provider digitalocean --country US --region nyc1$INSECURE_FLAG

Users: add more on the dashboard's Users page, or: sudo proxymgr-user set NAME
Backups: daily at 03:30 in $(get_env BACKUP_DIR) (kept $(get_env BACKUP_KEEP_DAYS) days)  ·  now: sudo proxymgr-backup  ·  restore: sudo proxymgr-restore FILE
Settings: $ENVF   Logs: journalctl -u proxymgr-api -u proxymgr-checker -f
EOF
)"
echo
echo "$SUMMARY"
umask 077
echo "$SUMMARY" > /root/proxymgr-credentials.txt
echo
echo "(Saved to /root/proxymgr-credentials.txt)"
exit 0
