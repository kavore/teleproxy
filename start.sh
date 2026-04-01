#!/bin/sh
set -e

# Save original arguments before positional parameters are repurposed for secrets
ORIG_ARGS="$*"

# Backward-compat: accept old MTPROXY_* env vars with deprecation warning
# Uses indirection via a temp file to avoid eval on user-controlled values
for _old_var in SECRET SECRET_1 SECRET_2 SECRET_3 SECRET_4 SECRET_5 SECRET_6 \
  SECRET_7 SECRET_8 SECRET_9 SECRET_10 SECRET_11 SECRET_12 SECRET_13 SECRET_14 \
  SECRET_15 SECRET_16; do
    _new_val=""
    _old_val=""
    # Safe indirection using printenv (no eval on user values)
    _new_val=$(printenv "TELEPROXY_${_old_var}" 2>/dev/null || true)
    _old_val=$(printenv "MTPROXY_${_old_var}" 2>/dev/null || true)
    if [ -z "$_new_val" ] && [ -n "$_old_val" ]; then
        echo "WARNING: MTPROXY_${_old_var} is deprecated, use TELEPROXY_${_old_var} instead" >&2
        export "TELEPROXY_${_old_var}=${_old_val}"
    fi
done

# Direct mode: connect to Telegram DCs without ME relay.
# Must be explicitly enabled. Incompatible with PROXY_TAG.
DIRECT_MODE=${DIRECT_MODE:-false}

# proxy-secret is baked into the image at build time (only needed for ME relay mode)
if [ "$DIRECT_MODE" != "true" ] && [ ! -f proxy-secret ]; then
    echo "ERROR: proxy-secret not found. The Docker image may be corrupted." >&2
    exit 1
fi

# Download/refresh proxy config to data/ (only in ME relay mode)
if [ "$DIRECT_MODE" != "true" ]; then
    CONFIG_PATH="data/proxy-multi.conf"
    NEEDS_DOWNLOAD=0

    if [ ! -f "$CONFIG_PATH" ]; then
        NEEDS_DOWNLOAD=1
    elif [ $(find "$CONFIG_PATH" -mtime +1 2>/dev/null | wc -l) -gt 0 ]; then
        NEEDS_DOWNLOAD=1
    fi

    PROXY_CONFIG_URL=${PROXY_CONFIG_URL:-https://core.telegram.org/getProxyConfig}
    if [ "$NEEDS_DOWNLOAD" -eq 1 ]; then
        echo "Downloading proxy config from $PROXY_CONFIG_URL..."
        if curl --connect-timeout 10 --max-time 30 --retry 3 --retry-delay 2 -fsSL "$PROXY_CONFIG_URL" -o "$CONFIG_PATH.tmp"; then
            mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
            echo "Proxy config downloaded successfully."
        else
            rm -f "$CONFIG_PATH.tmp"
            if [ -f "$CONFIG_PATH" ]; then
                echo "WARNING: Failed to refresh proxy config, using cached copy." >&2
            else
                echo "ERROR: Failed to download proxy config and no cached copy exists." >&2
                echo "Ensure core.telegram.org is reachable, or provide proxy-multi.conf in the data/ volume." >&2
                exit 1
            fi
        fi
    fi
fi

# --- Input validation helpers ---
validate_port () {
    case "$1" in
        ''|*[!0-9]*) echo "ERROR: Invalid port number: $1" >&2; exit 1 ;;
    esac
    if [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
        echo "ERROR: Port out of range (1-65535): $1" >&2; exit 1
    fi
}

validate_positive_int () {
    case "$1" in
        ''|*[!0-9]*) echo "ERROR: Invalid number for $2: $1" >&2; exit 1 ;;
    esac
}

# Validate a hex secret (32 hex chars, optionally with :label:limit suffix)
validate_secret () {
    _hex=$(printf '%s' "$1" | cut -d: -f1)
    case "$_hex" in
        *[!0-9a-fA-F]*) echo "ERROR: Secret contains non-hex characters: $_hex" >&2; exit 1 ;;
    esac
    if [ "${#_hex}" -ne 32 ]; then
        echo "ERROR: Secret must be exactly 32 hex characters, got ${#_hex}" >&2; exit 1
    fi
}

# Validate domain name (alphanumeric, dots, hyphens, optional :port)
validate_domain () {
    _d=$(printf '%s' "$1" | cut -d: -f1)
    case "$_d" in
        *[!a-zA-Z0-9.-]*) echo "ERROR: Invalid domain: $1" >&2; exit 1 ;;
    esac
}

# Validate file path (no shell metacharacters)
validate_filepath () {
    case "$1" in
        *['$`\;|&()']*) echo "ERROR: Invalid file path: $1" >&2; exit 1 ;;
    esac
}

# Validate a CIDR notation string (IPv4 or IPv6, with optional /prefix)
validate_cidr () {
    case "$1" in
        *[!0-9a-fA-F.:/-]*) echo "ERROR: Invalid CIDR: $1" >&2; exit 1 ;;
    esac
    if [ -z "$1" ]; then
        echo "ERROR: Empty CIDR" >&2; exit 1
    fi
}

validate_dc_override () {
    _entry=$1
    _dc=$(printf '%s' "$_entry" | cut -d: -f1)
    case "$_dc" in
        ''|*[!0-9]*) echo "ERROR: Invalid DC id in DC_OVERRIDE: $_entry" >&2; exit 1 ;;
    esac

    _rest=$(printf '%s' "$_entry" | cut -d: -f2-)
    case "$_rest" in
        \[*\]:*)
            _host=${_rest%:*}
            _host=${_host#\[}
            _host=${_host%\]}
            _port=${_rest##*:}
            ;;
        *:*:*)
            echo "ERROR: IPv6 DC_OVERRIDE entries must use [addr]:port: $_entry" >&2
            exit 1
            ;;
        *:*)
            _host=${_rest%:*}
            _port=${_rest##*:}
            ;;
        *)
            echo "ERROR: Invalid DC_OVERRIDE entry: $_entry" >&2
            exit 1
            ;;
    esac

    if [ -z "$_host" ]; then
        echo "ERROR: Missing host in DC_OVERRIDE entry: $_entry" >&2
        exit 1
    fi

    validate_port "$_port"
}

# --- End validation helpers ---

# Collect secrets from comma-separated SECRET and/or numbered SECRET_N vars.
# Uses positional parameters as a portable array (POSIX sh).
set --

if [ -n "$SECRET" ]; then
    _save_ifs="$IFS"
    IFS=','
    for _s in $SECRET; do
        IFS="$_save_ifs"
        _s=$(printf '%s' "$_s" | tr -d '[:space:]')
        [ -n "$_s" ] && set -- "$@" "$_s"
    done
    IFS="$_save_ifs"
fi

_i=1
while [ "$_i" -le 16 ]; do
    _val=$(printenv "SECRET_${_i}" 2>/dev/null || true)
    _val=$(printf '%s' "$_val" | tr -d '[:space:]')
    if [ -n "$_val" ]; then
        _lbl=$(printenv "SECRET_LABEL_${_i}" 2>/dev/null || true)
        _lbl=$(printf '%s' "$_lbl" | tr -d '[:space:]')
        _lim=$(printenv "SECRET_LIMIT_${_i}" 2>/dev/null || true)
        _lim=$(printf '%s' "$_lim" | tr -d '[:space:]')
        _suffix=""
        if [ -n "$_lbl" ] || [ -n "$_lim" ]; then
            _suffix=":${_lbl}"
        fi
        if [ -n "$_lim" ]; then
            _suffix="${_suffix}:${_lim}"
        fi
        set -- "$@" "${_val}${_suffix}"
    fi
    _i=$((_i + 1))
done

if [ "$#" -eq 0 ]; then
    echo "No SECRET provided, generating one..."
    _gen=$(openssl rand -hex 16)
    set -- "$_gen"
    echo "Generated secret: $_gen"
fi

if [ "$#" -gt 16 ]; then
    echo "ERROR: Maximum 16 secrets supported, got $#" >&2
    exit 1
fi

echo "Configured $# secret(s)"

# Set default values and validate
PORT=${PORT:-443}
STATS_PORT=${STATS_PORT:-8888}
WORKERS=${WORKERS:-1}
PROXY_TAG=${PROXY_TAG:-}
RANDOM_PADDING=${RANDOM_PADDING:-}
# Domain or host:port for TLS-transport mode (e.g. google.com or 127.0.0.1:8443)
EE_DOMAIN=${EE_DOMAIN:-}
# Max connections - lower value avoids rlimit issues in containers
MAX_CONNECTIONS=${MAX_CONNECTIONS:-60000}

validate_port "$PORT"
validate_port "$STATS_PORT"
validate_positive_int "$WORKERS" "WORKERS"
validate_positive_int "$MAX_CONNECTIONS" "MAX_CONNECTIONS"
if [ -n "$EE_DOMAIN" ]; then validate_domain "$EE_DOMAIN"; fi
if [ -n "$IP_BLOCKLIST" ]; then validate_filepath "$IP_BLOCKLIST"; fi
if [ -n "$IP_ALLOWLIST" ]; then validate_filepath "$IP_ALLOWLIST"; fi
if [ -n "$REPLAY_CACHE_SIZE" ]; then validate_positive_int "$REPLAY_CACHE_SIZE" "REPLAY_CACHE_SIZE"; fi

# Validate all secrets
for _s in "$@"; do
    validate_secret "$_s"
done

# Detect container-local IPv4 for NAT.
LOCAL_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP=$(grep -vE '(local|ip6|^fd|^$)' /etc/hosts 2>/dev/null | awk 'NR==1 {print $1}')
fi

# Public IPv4 address to advertise to Telegram DCs.
# Auto-detected if not provided — required for Docker NAT to work.
EXTERNAL_IP=${EXTERNAL_IP:-}
if [ -z "$EXTERNAL_IP" ]; then
    EXTERNAL_IP=$(curl -s -4 --connect-timeout 5 --max-time 10 https://icanhazip.com 2>/dev/null || curl -s -4 --connect-timeout 5 --max-time 10 https://ifconfig.me 2>/dev/null || true)
    if [ -n "$EXTERNAL_IP" ]; then
        echo "Auto-detected external IP: $EXTERNAL_IP"
    fi
fi

NAT_INFO_ARGS=""
if [ -n "$EXTERNAL_IP" ] && [ -n "$LOCAL_IP" ]; then
    NAT_INFO_ARGS="--nat-info ${LOCAL_IP}:${EXTERNAL_IP}"
elif [ -z "$EXTERNAL_IP" ]; then
    echo "WARNING: Could not detect external IP. Set EXTERNAL_IP env var for Docker NAT support." >&2
fi

# Print ready-to-share connection links
echo ""
echo "===== Connection Links ====="
_host="${EXTERNAL_IP:-<YOUR_SERVER_IP>}"
for _s in "$@"; do
    # Strip :LABEL:LIMIT suffix for URLs (labels/limits are for the proxy, not for clients)
    _secret_hex=$(printf '%s' "$_s" | cut -d: -f1)
    _label=$(printf '%s' "$_s" | cut -d: -f2 -s)
    if [ -n "$EE_DOMAIN" ]; then
        _domain_only=$(printf '%s' "$EE_DOMAIN" | cut -d: -f1)
        _domain_hex=$(printf '%s' "$_domain_only" | od -An -tx1 | tr -d ' \n')
        _full="ee${_secret_hex}${_domain_hex}"
    elif [ "$RANDOM_PADDING" = "true" ]; then
        _full="dd${_secret_hex}"
    else
        _full="$_secret_hex"
    fi
    _label_display=""
    [ -n "$_label" ] && _label_display=" [$_label]"
    echo "https://t.me/proxy?server=${_host}&port=${PORT}&secret=${_full}${_label_display}"
done
if [ "$_host" = "<YOUR_SERVER_IP>" ]; then
    echo "(Set EXTERNAL_IP to show your server's IP)"
fi
echo "============================="
echo ""

# Build --stats-allow-net arguments from comma-separated STATS_ALLOW_NET
STATS_ALLOW_NET_ARGS=""
if [ -n "$STATS_ALLOW_NET" ]; then
    _save_ifs="$IFS"
    IFS=','
    for _net in $STATS_ALLOW_NET; do
        IFS="$_save_ifs"
        _net=$(printf '%s' "$_net" | tr -d '[:space:]')
        if [ -n "$_net" ]; then
            validate_cidr "$_net"
            STATS_ALLOW_NET_ARGS="$STATS_ALLOW_NET_ARGS --stats-allow-net $_net"
        fi
    done
    IFS="$_save_ifs"
fi

DC_OVERRIDE_ARGS=""
if [ "$DIRECT_MODE" = "true" ] && [ -n "$DC_OVERRIDE" ]; then
    _save_ifs="$IFS"
    IFS=','
    for _dc_entry in $DC_OVERRIDE; do
        IFS="$_save_ifs"
        _dc_entry=$(printf '%s' "$_dc_entry" | tr -d '[:space:]')
        if [ -n "$_dc_entry" ]; then
            validate_dc_override "$_dc_entry"
            DC_OVERRIDE_ARGS="$DC_OVERRIDE_ARGS --dc-override $_dc_entry"
        fi
    done
    IFS="$_save_ifs"
fi

# Start cron daemon for config refresh (only in ME relay mode)
if [ "$DIRECT_MODE" != "true" ]; then
    crond
fi

# Execute teleproxy with proper argument quoting (no eval)
# shellcheck disable=SC2086
exec ./teleproxy \
    -p "$STATS_PORT" \
    -H "$PORT" \
    $(for _s in "$@"; do printf -- '-S %s ' "$_s"; done) \
    -c "$MAX_CONNECTIONS" \
    --http-stats \
    $NAT_INFO_ARGS \
    ${PREFER_IPV6:+$([ "$PREFER_IPV6" = "true" ] && printf -- '-6')} \
    ${PROXY_TAG:+-P "$PROXY_TAG"} \
    ${RANDOM_PADDING:+$([ "$RANDOM_PADDING" = "true" ] && printf -- '-R')} \
    ${EE_DOMAIN:+-D "$EE_DOMAIN"} \
    ${IP_BLOCKLIST:+--ip-blocklist "$IP_BLOCKLIST"} \
    ${IP_ALLOWLIST:+--ip-allowlist "$IP_ALLOWLIST"} \
    ${REPLAY_CACHE_SIZE:+--replay-cache-size "$REPLAY_CACHE_SIZE"} \
    $STATS_ALLOW_NET_ARGS \
    $DC_OVERRIDE_ARGS \
    $(if [ "$DIRECT_MODE" = "true" ]; then
        printf -- '--direct -M %s -u teleproxy' "$WORKERS"
    else
        printf -- '--aes-pwd proxy-secret data/proxy-multi.conf -M %s -u teleproxy' "$WORKERS"
    fi) \
    $ORIG_ARGS
