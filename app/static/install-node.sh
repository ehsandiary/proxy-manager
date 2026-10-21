#!/usr/bin/env bash
# Proxy node installer — turns a fresh Ubuntu 24.04/26.04 VM into an HTTP(S) proxy (Squid, port 3128)
# that is registered with, and monitored by, the Proxy Manager main server.
#
# Do NOT run this on a proxy that apps already use with other credentials: it sets a new
# username/password. Add those proxies on the dashboard's Add page instead.
#
#   curl -fsSL https://MAIN/install-node.sh | sudo bash -s -- \
#       --main https://MAIN --token ENROLL_TOKEN --provider digitalocean --country US --region nyc1
#
# Options:
#   --main URL          main server base URL (required)
#   --token TOKEN       enroll token from the main server (required)
#   --provider NAME     gcp | digitalocean | vultr | cherry | scaleway | ... (default: other)
#   --country CC        default US
#   --region NAME       e.g. us-central1, nyc1
#   --label TEXT        free text shown in the dashboard
#   --http-port N       default 3128
#   --socks             also run a SOCKS5 proxy (Dante)
#   --socks-port N      default 1080 (with --socks)
#   --no-http           SOCKS5 only (implies --socks)
#   --insecure          main server uses a self-signed certificate
#
# Re-running is safe. The node re-syncs with the main server every 5 minutes
# (credentials, allowed client IPs) via the proxynode-sync.timer.
set -euo pipefail

MAIN="" TOKEN="" PROVIDER="other" COUNTRY="US" REGION="" LABEL=""
SOCKS=0 HTTP=1 SOCKS_PORT=1080 HTTP_PORT=3128 INSECURE=0

die() { echo "ERROR: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --main) MAIN="${2%/}"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --provider) PROVIDER="$2"; shift 2 ;;
    --country) COUNTRY="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --socks-port) SOCKS_PORT="$2"; shift 2 ;;
    --http-port) HTTP_PORT="$2"; shift 2 ;;
    --socks) SOCKS=1; shift ;;
    --no-http) HTTP=0; SOCKS=1; shift ;;
    --no-socks) SOCKS=0; shift ;;
    --insecure) INSECURE=1; shift ;;
    -h|--help) sed -n '2,28p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[ -n "$MAIN" ] || die "--main is required"
[ -n "$TOKEN" ] || die "--token is required"
[ -n "$LABEL" ] || LABEL="$(hostname -s 2>/dev/null || true)"   # VM name becomes the dashboard name
[ "$SOCKS" = 1 ] || [ "$HTTP" = 1 ] || die "--no-http and --no-socks together leave nothing to run"
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || echo "WARNING: tested on Ubuntu 24.04/26.04 only; continuing on ${PRETTY_NAME:-unknown}"

echo "==> Installing packages"
export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -o DPkg::Lock::Timeout=600)   # first boot: wait for cloud-init/unattended-upgrades
"${APT[@]}" update -q
PKGS="curl ca-certificates openssl ufw python3 iproute2"
if [ "$SOCKS" = 1 ]; then PKGS="$PKGS dante-server"; fi
if [ "$HTTP" = 1 ]; then PKGS="$PKGS squid"; fi
# shellcheck disable=SC2086
"${APT[@]}" install -y -q $PKGS >/dev/null

echo "==> Writing /etc/proxynode/node.conf"
install -d -m 700 /etc/proxynode
q() { printf '%q' "$1"; }
cat > /etc/proxynode/node.conf <<EOF
MAIN=$(q "$MAIN")
TOKEN=$(q "$TOKEN")
PROVIDER=$(q "$PROVIDER")
COUNTRY=$(q "$COUNTRY")
REGION=$(q "$REGION")
LABEL=$(q "$LABEL")
SOCKS=$SOCKS
HTTP=$HTTP
SOCKS_PORT=$SOCKS_PORT
HTTP_PORT=$HTTP_PORT
INSECURE=$INSECURE
EOF
chmod 600 /etc/proxynode/node.conf

echo "==> Installing proxynode-sync"
cat > /usr/local/sbin/proxynode-sync <<'SYNC'
#!/usr/bin/env bash
# Registers this node with the main server and applies credentials + firewall allowlist.
set -euo pipefail
set -a; . /etc/proxynode/node.conf; set +a
STATE=/etc/proxynode/state
CURL=(curl -fsS --max-time 20 --retry 2)
if [ "$INSECURE" = 1 ]; then CURL+=(-k); fi
log() { echo "[proxynode-sync] $*"; }

PUBIP="$("${CURL[@]}" "$MAIN/api/v1/ip" 2>/dev/null | tr -d '[:space:]' || true)"
PAYLOAD="$(PUBIP="$PUBIP" python3 - <<'PY'
import json, os
env = os.environ
print(json.dumps({
    "token": env["TOKEN"], "public_ip": env.get("PUBIP") or None,
    "provider": env["PROVIDER"], "country": env["COUNTRY"], "region": env["REGION"], "label": env["LABEL"],
    "socks": env["SOCKS"] == "1", "http": env["HTTP"] == "1",
    "socks_port": int(env["SOCKS_PORT"]), "http_port": int(env["HTTP_PORT"]),
}))
PY
)"
RESP="$("${CURL[@]}" -H 'Content-Type: application/json' -d "$PAYLOAD" "$MAIN/api/v1/nodes/enroll")" \
  || { log "enroll request failed (main server unreachable or token rejected)"; exit 1; }
eval "$(RESP="$RESP" python3 - <<'PY'
import json, os, shlex
d = json.loads(os.environ["RESP"])
print("PX_USER=%s" % shlex.quote(d["username"]))
print("PX_PASS=%s" % shlex.quote(d["password"]))
print("PX_CIDRS=%s" % shlex.quote(" ".join(d.get("allowed_cidrs") or [])))
print("PX_IP=%s" % shlex.quote(d.get("public_ip") or ""))
PY
)"
[ -n "$PX_USER" ] && [ -n "$PX_PASS" ] || { log "bad enroll response"; exit 1; }

DESIRED="$(printf '%s|%s|%s|%s|%s|%s|%s|v1' "$PX_USER" "$PX_PASS" "$PX_CIDRS" "$SOCKS" "$HTTP" "$SOCKS_PORT" "$HTTP_PORT" | sha256sum | cut -d' ' -f1)"
CURRENT="$(cat "$STATE" 2>/dev/null || true)"

ensure_running() {
  if [ "$SOCKS" = 1 ]; then systemctl is-active --quiet danted || systemctl restart danted || true; fi
  if [ "$HTTP" = 1 ]; then systemctl is-active --quiet squid || systemctl restart squid || true; fi
  return 0
}

if [ "$DESIRED" = "$CURRENT" ]; then
  ensure_running
  exit 0
fi
log "applying new config (ip=$PX_IP user=$PX_USER clients=[$PX_CIDRS])"

IFACE="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
[ -n "$IFACE" ] || IFACE=eth0

if [ "$SOCKS" = 1 ]; then
  id "$PX_USER" >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin "$PX_USER"
  echo "$PX_USER:$PX_PASS" | chpasswd
  cat > /etc/danted.conf <<EOF
# managed by proxynode-sync
logoutput: syslog
internal: 0.0.0.0 port = $SOCKS_PORT
external: $IFACE
socksmethod: username
clientmethod: none
user.privileged: root
user.unprivileged: nobody
timeout.negotiate: 30
timeout.io: 3600
client pass {
  from: 0.0.0.0/0 to: 0.0.0.0/0
  log: error
}
socks pass {
  from: 0.0.0.0/0 to: 0.0.0.0/0
  command: connect
  socksmethod: username
  log: error
}
EOF
  systemctl enable danted >/dev/null 2>&1 || true
  systemctl restart danted
fi

if [ "$HTTP" = 1 ]; then
  printf '%s:%s\n' "$PX_USER" "$(openssl passwd -apr1 "$PX_PASS")" > /etc/squid/proxynode.passwd
  chown root:proxy /etc/squid/proxynode.passwd 2>/dev/null || true
  chmod 640 /etc/squid/proxynode.passwd
  NCSA=/usr/lib/squid/basic_ncsa_auth
  [ -x "$NCSA" ] || [ ! -x /usr/lib/squid3/basic_ncsa_auth ] || NCSA=/usr/lib/squid3/basic_ncsa_auth
  cat > /etc/squid/squid.conf <<EOF
# managed by proxynode-sync
http_port $HTTP_PORT
auth_param basic program $NCSA /etc/squid/proxynode.passwd
auth_param basic realm proxy
auth_param basic credentialsttl 2 hours
acl authed proxy_auth REQUIRED
auth_param basic children 10
# mail ports blocked: these IPs are for HTTP(S) traffic, keep their reputation clean
acl mail_ports port 25 465 587
http_access deny mail_ports
http_access allow authed
http_access deny all
# anonymization (same as the original GCP Squids)
forwarded_for delete
via off
request_header_access X-Forwarded-For deny all
request_header_access Via deny all
request_header_access Cache-Control deny all
cache deny all
cache_mem 8 MB
max_filedescriptors 65535
dns_nameservers 8.8.8.8 1.1.1.1
access_log daemon:/var/log/squid/access.log squid
logfile_rotate 3
shutdown_lifetime 2 seconds
EOF
  systemctl enable squid >/dev/null 2>&1 || true
  systemctl restart squid
fi

# Firewall: SSH open, proxy ports only for allowed client IPs.
SSH_PORT="$(ss -tlnpH 2>/dev/null | awk '/sshd/ {n=split($4,a,":"); print a[n]; exit}' || true)"
ufw allow "${SSH_PORT:-22}/tcp" >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
# drop our old rules (highest number first so numbering stays valid)
ufw status numbered | grep 'proxynode' | sed -E 's/^\[ *([0-9]+)\].*/\1/' | sort -rn | while read -r n; do
  ufw --force delete "$n" >/dev/null
done
for c in $PX_CIDRS; do
  if [ "$SOCKS" = 1 ]; then ufw allow proto tcp from "$c" to any port "$SOCKS_PORT" comment proxynode >/dev/null; fi
  if [ "$HTTP" = 1 ]; then ufw allow proto tcp from "$c" to any port "$HTTP_PORT" comment proxynode >/dev/null; fi
done
ufw --force enable >/dev/null

echo "$DESIRED" > "$STATE"
chmod 600 "$STATE"
log "done"
SYNC
chmod 700 /usr/local/sbin/proxynode-sync

echo "==> Raising file limits for proxy services"
for svc in danted squid; do
  install -d "/etc/systemd/system/$svc.service.d"
  printf '[Service]\nLimitNOFILE=65535\nRestart=always\nRestartSec=3\n' > "/etc/systemd/system/$svc.service.d/proxynode.conf"
done
systemctl daemon-reload

echo "==> Installing 5-minute sync timer"
cat > /etc/systemd/system/proxynode-sync.service <<'EOF'
[Unit]
Description=Sync proxy node with Proxy Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/proxynode-sync
EOF
cat > /etc/systemd/system/proxynode-sync.timer <<'EOF'
[Unit]
Description=Sync proxy node with Proxy Manager every 5 minutes

[Timer]
OnBootSec=30s
OnUnitActiveSec=5min
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload

echo "==> Registering with $MAIN"
rm -f /etc/proxynode/state
/usr/local/sbin/proxynode-sync
systemctl enable --now proxynode-sync.timer >/dev/null

echo
echo "Done. This node should appear in the dashboard within a minute."
if [ "$SOCKS" = 1 ]; then echo "  SOCKS5: port $SOCKS_PORT"; fi
if [ "$HTTP" = 1 ]; then echo "  HTTP:   port $HTTP_PORT"; fi
echo "  Provider firewalls (GCP VPC rules, DO/Vultr cloud firewalls) must also allow these ports from your app servers and the main server."
echo "  Test from anywhere allowed:  curl -x http://USER:PASS@THIS_IP:$HTTP_PORT https://api.ipify.org"
