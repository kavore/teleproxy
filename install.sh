#!/bin/sh
# Teleproxy one-liner installer for bare-metal Linux servers.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
#
# Environment variables (set before running to customize):
#   PORT              Client port (default: 443)
#   STATS_PORT        Stats port (default: 8888)
#   WORKERS           Worker processes (default: 1)
#   SECRET            Pre-set secret(s), comma-separated (default: auto-generated)
#   SECRET_COUNT      Auto-generate this many secrets (1-16)
#   SECRET_1..16      Numbered secrets (combined with SECRET if both set)
#   SECRET_LABEL_1..16  Labels for numbered secrets
#   SECRET_LIMIT_1..16  Per-secret connection limits
#   EE_DOMAIN         Enable fake-TLS with this domain
#   TELEPROXY_VERSION Pin a specific version (default: latest)
#
# Flags:
#   --uninstall       Remove Teleproxy and its config
#   --generate-config Print the TOML config to stdout and exit (no install)
#
# Uninstall:
#   curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh -s -- --uninstall

set -eu

GITHUB_REPO="teleproxy/teleproxy"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/teleproxy"
CONFIG_FILE="$CONFIG_DIR/config.toml"
SERVICE_FILE="/etc/systemd/system/teleproxy.service"
SERVICE_USER="teleproxy"

# Defaults (overridable via env)
PORT="${PORT:-443}"
STATS_PORT="${STATS_PORT:-8888}"
WORKERS="${WORKERS:-1}"
SECRET="${SECRET:-}"
SECRET_COUNT="${SECRET_COUNT:-}"
EE_DOMAIN="${EE_DOMAIN:-}"
TELEPROXY_VERSION="${TELEPROXY_VERSION:-}"

# Colors (only when stdout is a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' NC=''
fi

info()  { printf "${GREEN}[+]${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$1"; }
die()   { printf "${RED}[x]${NC} %s\n" "$1" >&2; exit 1; }

# ── Uninstall ──────────────────────────────────────────────────

do_uninstall() {
    info "Uninstalling Teleproxy..."
    systemctl disable --now teleproxy 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    rm -f "$INSTALL_DIR/teleproxy"
    rm -rf "$CONFIG_DIR"
    userdel "$SERVICE_USER" 2>/dev/null || true
    info "Teleproxy uninstalled."
    exit 0
}

# Handle flags
GENERATE_CONFIG_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --uninstall) do_uninstall ;;
        --generate-config) GENERATE_CONFIG_ONLY=1 ;;
    esac
done

# ── Install (skipped in --generate-config mode) ───────────────

if [ "$GENERATE_CONFIG_ONLY" -eq 0 ]; then

[ "$(id -u)" -ne 0 ] && die "Run as root (or with sudo)"

OS=$(uname -s)
[ "$OS" = "Linux" ] || die "This installer supports Linux only (detected: $OS)"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH_SUFFIX="amd64" ;;
    aarch64) ARCH_SUFFIX="arm64" ;;
    *)       die "Unsupported architecture: $ARCH (need x86_64 or aarch64)" ;;
esac

if [ ! -d /run/systemd/system ]; then
    die "systemd not detected. Use Docker or set up the service manually."
fi

# Prefer curl, fall back to wget
if command -v curl >/dev/null 2>&1; then
    DL="curl -fsSL -o"
elif command -v wget >/dev/null 2>&1; then
    DL="wget -qO"
else
    die "Neither curl nor wget found"
fi

# ── Download binary ────────────────────────────────────────────

if [ -n "$TELEPROXY_VERSION" ]; then
    URL="https://github.com/$GITHUB_REPO/releases/download/v${TELEPROXY_VERSION}/teleproxy-linux-${ARCH_SUFFIX}"
else
    URL="https://github.com/$GITHUB_REPO/releases/latest/download/teleproxy-linux-${ARCH_SUFFIX}"
fi

RUNNING=0
if systemctl is-active --quiet teleproxy 2>/dev/null; then
    RUNNING=1
    info "Stopping running teleproxy service..."
    systemctl stop teleproxy
fi

info "Downloading teleproxy ($ARCH_SUFFIX)..."
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
$DL "$TMP" "$URL" || die "Download failed. Check your network or version."
chmod +x "$TMP"
mv "$TMP" "$INSTALL_DIR/teleproxy"
trap - EXIT
info "Installed to $INSTALL_DIR/teleproxy"

# ── Create system user ─────────────────────────────────────────

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    info "Created system user: $SERVICE_USER"
fi

mkdir -p "$CONFIG_DIR"

fi  # GENERATE_CONFIG_ONLY

# ── Collect secrets ───────────────────────────────────────────
# Collected into SEC_FILE (one KEY:LABEL:LIMIT per line), mirroring
# the Docker entrypoint (start.sh) for consistent behaviour.

SEC_FILE=$(mktemp)
trap 'rm -f "$SEC_FILE"' EXIT

_generate_one() {
    "$INSTALL_DIR/teleproxy" generate-secret 2>/dev/null || \
        head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

# 1) Comma-separated SECRET=s1,s2,s3
if [ -n "$SECRET" ]; then
    _save_ifs="$IFS"
    IFS=','
    for _s in $SECRET; do
        IFS="$_save_ifs"
        _s=$(printf '%s' "$_s" | tr -d '[:space:]')
        [ -n "$_s" ] && echo "$_s" >> "$SEC_FILE"
    done
    IFS="$_save_ifs"
fi

# 2) Numbered SECRET_1..SECRET_16 with optional labels/limits
_i=1
while [ "$_i" -le 16 ]; do
    eval "_val=\${SECRET_${_i}:-}"
    _val=$(printf '%s' "$_val" | tr -d '[:space:]')
    if [ -n "$_val" ]; then
        eval "_lbl=\${SECRET_LABEL_${_i}:-}"
        _lbl=$(printf '%s' "$_lbl" | tr -d '[:space:]')
        eval "_lim=\${SECRET_LIMIT_${_i}:-}"
        _lim=$(printf '%s' "$_lim" | tr -d '[:space:]')
        _suffix=""
        if [ -n "$_lbl" ] || [ -n "$_lim" ]; then
            _suffix=":${_lbl}"
        fi
        if [ -n "$_lim" ]; then
            _suffix="${_suffix}:${_lim}"
        fi
        echo "${_val}${_suffix}" >> "$SEC_FILE"
    fi
    _i=$((_i + 1))
done

# 3) SECRET_COUNT=N — auto-generate N secrets
_sec_count=$(wc -l < "$SEC_FILE" | tr -d '[:space:]')
if [ "$_sec_count" -eq 0 ] && [ -n "$SECRET_COUNT" ]; then
    case "$SECRET_COUNT" in
        ''|*[!0-9]*) die "SECRET_COUNT must be a number between 1 and 16 (got: $SECRET_COUNT)" ;;
    esac
    [ "$SECRET_COUNT" -ge 1 ] && [ "$SECRET_COUNT" -le 16 ] || \
        die "SECRET_COUNT must be between 1 and 16 (got: $SECRET_COUNT)"
    _n=1
    while [ "$_n" -le "$SECRET_COUNT" ]; do
        _gen=$(_generate_one)
        echo "${_gen}:secret_${_n}" >> "$SEC_FILE"
        _n=$((_n + 1))
    done
    info "Auto-generated $SECRET_COUNT secret(s)"
elif [ "$_sec_count" -gt 0 ] && [ -n "$SECRET_COUNT" ]; then
    warn "SECRET_COUNT ignored because explicit secrets were provided"
fi

# 4) Fallback: generate one secret if none collected
_sec_count=$(wc -l < "$SEC_FILE" | tr -d '[:space:]')
if [ "$_sec_count" -eq 0 ]; then
    _gen=$(_generate_one)
    echo "${_gen}:default" >> "$SEC_FILE"
fi

# 5) Validate max 16
_sec_count=$(wc -l < "$SEC_FILE" | tr -d '[:space:]')
[ "$_sec_count" -le 16 ] || die "Maximum 16 secrets supported, got $_sec_count"

info "Configured $_sec_count secret(s)"

# ── Generate TOML config ─────────────────────────────────────

_generate_toml() {
    echo "# Teleproxy configuration"
    echo "# Edit and run: systemctl reload teleproxy"
    echo "port = $PORT"
    echo "stats_port = $STATS_PORT"
    echo "http_stats = true"
    echo "user = \"$SERVICE_USER\""
    echo "direct = true"
    echo "workers = $WORKERS"
    if [ -n "$EE_DOMAIN" ]; then
        echo "domain = \"$EE_DOMAIN\""
    fi
    echo ""
    while IFS= read -r _line; do
        _key=$(printf '%s' "$_line" | cut -d: -f1)
        _label=$(printf '%s' "$_line" | cut -d: -f2 -s)
        _limit=$(printf '%s' "$_line" | cut -d: -f3 -s)
        echo "[[secret]]"
        echo "key = \"$_key\""
        [ -n "$_label" ] && echo "label = \"$_label\""
        [ -n "$_limit" ] && echo "limit = $_limit"
        echo ""
    done < "$SEC_FILE"
}

if [ "$GENERATE_CONFIG_ONLY" -eq 1 ]; then
    _generate_toml
    exit 0
fi

if [ -f "$CONFIG_FILE" ]; then
    info "Keeping existing config: $CONFIG_FILE"
else
    _generate_toml > "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
    chown root:"$SERVICE_USER" "$CONFIG_FILE"
    info "Generated config: $CONFIG_FILE"
fi

# ── Systemd unit ───────────────────────────────────────────────

cat > "$SERVICE_FILE" << 'UNIT'
[Unit]
Description=Teleproxy MTProto Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=teleproxy
ExecStart=/usr/local/bin/teleproxy --config /etc/teleproxy/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/teleproxy

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
info "Installed systemd unit"

# ── Start ──────────────────────────────────────────────────────

systemctl enable --now teleproxy
info "Teleproxy is running"

# ── Print connection links ─────────────────────────────────────

# Detect external IP
EXT_IP=""
if command -v curl >/dev/null 2>&1; then
    EXT_IP=$(curl -s -4 --connect-timeout 5 --max-time 10 https://icanhazip.com 2>/dev/null || \
             curl -s -4 --connect-timeout 5 --max-time 10 https://ifconfig.me 2>/dev/null || true)
fi
EXT_IP=$(echo "$EXT_IP" | tr -d '[:space:]')
EXT_IP="${EXT_IP:-<YOUR_SERVER_IP>}"

echo ""
echo "===== Connection Links ====="
while IFS= read -r _line; do
    _key=$(printf '%s' "$_line" | cut -d: -f1)
    _label=$(printf '%s' "$_line" | cut -d: -f2 -s)
    if [ -n "$EE_DOMAIN" ]; then
        _domain_only=$(printf '%s' "$EE_DOMAIN" | cut -d: -f1)
        _domain_hex=$(printf '%s' "$_domain_only" | od -An -tx1 | tr -d ' \n')
        _full="ee${_key}${_domain_hex}"
    else
        _full="$_key"
    fi
    _label_arg=""
    [ -n "$_label" ] && _label_arg="--label $_label"
    teleproxy link --server "$EXT_IP" --port "$PORT" --secret "$_full" $_label_arg
done < "$SEC_FILE"
echo ""
echo "QR codes also at: http://${EXT_IP}:${STATS_PORT}/link"
echo "============================="
echo ""
echo "Manage:"
echo "  systemctl status teleproxy    # check status"
echo "  systemctl reload teleproxy    # reload config (SIGHUP)"
echo "  journalctl -u teleproxy -f    # view logs"
echo "  nano $CONFIG_FILE             # edit config"
echo ""
echo "Upgrade: re-run this script"
echo "Uninstall: curl -sSL ... | sh -s -- --uninstall"
