#!/bin/bash
#
# SMTP Tunnel Proxy - production installer / upgrader
#
# Preferred remote install:
#   curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- --role server --repo OWNER/REPO --ref main
#
# Explicit roles:
#   sudo bash ./install.sh --role server
#   sudo bash ./install.sh --role client --server-host example.com --username alice --secret-file /root/alice.secret
#
# Version: 1.4.0

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

GITHUB_RAW="${GITHUB_RAW:-https://raw.githubusercontent.com/x011/smtp-tunnel-proxy/main}"

INSTALL_DIR="${INSTALL_DIR:-/opt/smtp-tunnel}"
CONFIG_DIR="${CONFIG_DIR:-/etc/smtp-tunnel}"
CERT_DIR="${CERT_DIR:-/etc/smtp-tunnel/certs}"
REVERSE_CERT_DIR="${REVERSE_CERT_DIR:-/etc/smtp-tunnel/reverse-certs}"
LOG_DIR="${LOG_DIR:-/var/log/smtp-tunnel}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/smtp-tunnel}"
SERVICE_DIR="/etc/systemd/system"
VENV_DIR="$INSTALL_DIR/venv"
PYTHON_BIN="$VENV_DIR/bin/python"

PYTHON_FILES="server.py client.py common.py generate_certs.py"
SCRIPTS="smtp-tunnel-adduser smtp-tunnel-deluser smtp-tunnel-listusers smtp-tunnel-update"
TEMPLATE_FILES="config.yaml users.yaml requirements.txt smtp-tunnel.service"
EXTRA_FILES="install.sh README.md TECHNICAL.md LICENSE"

ROLE="server"
MODE="normal"
ROLE_SET=0
NON_INTERACTIVE=0
ASSUME_YES=0
DRY_RUN=0
MIGRATE_CONFIG=0
RESET_CONFIG=0
SKIP_START=0
ALLOW_INSECURE_NO_CA=0
GENERATE_CERTS=1
EXPORT_CLIENT_PACKAGE=0

SERVICE_NAME="smtp-tunnel"
LISTEN_HOST="0.0.0.0"
LISTEN_PORT="587"
SERVER_PORT="587"
REVERSE_PORT_SET=0
SOCKS_HOST="127.0.0.1"
SOCKS_PORT="1080"
CONNECTIONS="1"
CONNECTIONS_SET=0
ADAPTIVE_CONNECTIONS=0
ADAPTIVE_CONNECTIONS_SET=0
MIN_CONNECTIONS="8"
MIN_CONNECTIONS_SET=0
MAX_CONNECTIONS="20"
MAX_CONNECTIONS_SET=0
SCALE_DOWN_IDLE_SECONDS="300"
SCALE_DOWN_IDLE_SECONDS_SET=0
IDLE_SESSION_RECYCLE=0
IDLE_SESSION_RECYCLE_SET=0
PERFORMANCE_PROFILE="balanced"
PERFORMANCE_PROFILE_SET=0
PRODUCTION_REVERSE_TUNING=0
HOSTNAME_VALUE=""
SERVER_HOST=""
USERNAME_VALUE=""
SECRET_VALUE=""
SECRET_FILE=""
SECRET_ENV=""
CA_CERT_SOURCE=""
EHLO_NAME=""
FROM_PACKAGE=""
FROM_REVERSE_PACKAGE=""
REVERSE_CERT_MODE="existing"
REVERSE_DOMAIN=""
REVERSE_CERT_FILE=""
REVERSE_KEY_FILE=""
LETSENCRYPT_EMAIL=""
LETSENCRYPT_CHALLENGE="http-01"
REVERSE_ALLOWED_DIALER_IPS=""
TLS_VERIFY_MODE="system-ca"
REVERSE_CA_CERT_SOURCE=""
REVERSE_FINGERPRINT=""
EXPORT_REVERSE_PACKAGE=0
INCLUDE_REVERSE_SECRET=0

BACKUP_DIR=""
EXISTING_INSTALL=0
SCRIPT_DIR=""

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
print_ask() { echo -e "${CYAN}[?]${NC} $1"; }

usage() {
    cat << EOF
Usage:
  sudo bash ./install.sh [--role server|client] [options]

Server options:
  --role server
  --mode normal|reverse-dial  Server mode (default: normal)
  --listen-host HOST           Server listen host (default: 0.0.0.0)
  --hostname NAME              SMTP hostname and certificate hostname
  --listen-port PORT           Server listen port (default: 587)
  --service-name NAME          systemd service name (default: smtp-tunnel)
  --ehlo-name NAME             EHLO name placed in generated client configs
  --no-generate-certs          Do not generate private CA/server certificate
  --export-client-package      Offer/export first user's client package under /root

Client options:
  --role client
  --mode normal|reverse-listen Client mode (default: normal)
  --from-package PATH          Install client config/CA from server-generated tar.gz bundle
  --server-host HOST           Tunnel server hostname
  --server-port PORT           Tunnel server port (default: 587)
  --socks-host HOST            Local SOCKS bind host (default: 127.0.0.1)
  --socks-port PORT            Local SOCKS port (default: 1080)
  --username USER              Tunnel username
  --secret SECRET              Tunnel secret
  --secret-file PATH           Read tunnel secret from a root-readable file
  --secret-env NAME            Read tunnel secret from an environment variable
  --ca-cert PATH               CA cert to copy to /etc/smtp-tunnel/certs/ca.crt
  --allow-insecure-no-ca       Allow client install without ca_cert

Reverse mode options:
  --reverse-host HOST          Access Node host/domain for reverse-dial
  --reverse-port PORT          Reverse listener/dial port (default: 587)
  --reverse-domain DOMAIN      TLS domain for reverse-listen
  --reverse-cert-mode MODE     existing|letsencrypt|letsencrypt-http|letsencrypt-dns|private-ca
  --reverse-cert-file PATH     Existing reverse listener certificate/fullchain
  --reverse-key-file PATH      Existing reverse listener private key
  --letsencrypt-email EMAIL    Let's Encrypt account email
  --allowed-dialer-ip IP/CIDR  Restrict Access Node listener to VPS public IP/CIDR
  --tls-verify-mode MODE       system-ca|private-ca|fingerprint for reverse-dial
  --reverse-ca-cert PATH       CA cert for reverse-dial private-ca verification
  --reverse-fingerprint HEX    SHA-256 cert fingerprint for reverse-dial
  --from-reverse-package PATH  Install VPS reverse-dial config from bundle
  --export-reverse-package     Export VPS reverse-dial bundle from Access Node
  --include-reverse-secret     Include reverse.secret in exported bundle
  --connections N             Reverse tunnel sessions for reverse-dial (fresh reverse default: 4)
  --adaptive-connections      Start min reverse sessions and scale up to max under load
  --no-adaptive-connections   Fixed reverse sessions using tunnel.connections
  --fixed-connections         Alias for --no-adaptive-connections
  --min-connections N         Adaptive minimum sessions (default: 8)
  --max-connections N         Adaptive maximum sessions (default: 20)
  --scale-down-idle-seconds N Adaptive idle time before scaling down (default: 300)
  --idle-session-recycle      Recycle only idle sessions, disabled by default
  --no-idle-session-recycle   Disable idle session recycle
  --performance-profile MODE  compatibility|balanced|throughput (default: balanced)
  --production-reverse-tuning Apply tested reverse defaults: throughput profile and 20 reverse-dial sessions

Upgrade / automation:
  --non-interactive            Do not prompt; fail if required values are missing
  --yes                        Answer yes to confirmations
  --migrate-config             Write fresh optimized config after backing up existing config
  --reset-config               Replace active config after backing up existing config
  --skip-start                 Install but do not enable/start service
  --dry-run                    Parse and preflight only; do not change files
  -h, --help

Examples:
  sudo bash ./install.sh --role server
  sudo bash ./install.sh --role server --hostname mail.example.com --listen-port 587 --service-name smtp-tunnel --non-interactive
  sudo bash ./install.sh --role client --server-host mail.example.com --server-port 587 --username alice --secret-file /root/alice.secret --ca-cert ./ca.crt --non-interactive
  sudo bash ./install.sh --role server --mode reverse-dial --reverse-host access.example.com --reverse-port 8443 --connections 20 --performance-profile throughput --non-interactive
EOF
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --role)
                ROLE="${2:-}"
                ROLE_SET=1
                shift 2
                ;;
            --mode)
                MODE="${2:-}"
                shift 2
                ;;
            --hostname)
                HOSTNAME_VALUE="${2:-}"
                shift 2
                ;;
            --listen-host)
                LISTEN_HOST="${2:-}"
                shift 2
                ;;
            --listen-port)
                LISTEN_PORT="${2:-}"
                shift 2
                ;;
            --server-host)
                SERVER_HOST="${2:-}"
                shift 2
                ;;
            --server-port)
                SERVER_PORT="${2:-}"
                shift 2
                ;;
            --socks-host)
                SOCKS_HOST="${2:-}"
                shift 2
                ;;
            --socks-port)
                SOCKS_PORT="${2:-}"
                shift 2
                ;;
            --connections)
                CONNECTIONS="${2:-}"
                CONNECTIONS_SET=1
                shift 2
                ;;
            --adaptive-connections)
                ADAPTIVE_CONNECTIONS=1
                ADAPTIVE_CONNECTIONS_SET=1
                shift
                ;;
            --no-adaptive-connections|--fixed-connections)
                ADAPTIVE_CONNECTIONS=0
                ADAPTIVE_CONNECTIONS_SET=1
                shift
                ;;
            --min-connections)
                MIN_CONNECTIONS="${2:-}"
                MIN_CONNECTIONS_SET=1
                shift 2
                ;;
            --max-connections)
                MAX_CONNECTIONS="${2:-}"
                MAX_CONNECTIONS_SET=1
                shift 2
                ;;
            --scale-down-idle-seconds)
                SCALE_DOWN_IDLE_SECONDS="${2:-}"
                SCALE_DOWN_IDLE_SECONDS_SET=1
                shift 2
                ;;
            --idle-session-recycle)
                IDLE_SESSION_RECYCLE=1
                IDLE_SESSION_RECYCLE_SET=1
                shift
                ;;
            --no-idle-session-recycle)
                IDLE_SESSION_RECYCLE=0
                IDLE_SESSION_RECYCLE_SET=1
                shift
                ;;
            --performance-profile)
                PERFORMANCE_PROFILE="${2:-}"
                PERFORMANCE_PROFILE_SET=1
                shift 2
                ;;
            --production-reverse-tuning)
                PRODUCTION_REVERSE_TUNING=1
                shift
                ;;
            --username)
                USERNAME_VALUE="${2:-}"
                shift 2
                ;;
            --secret)
                SECRET_VALUE="${2:-}"
                print_warn "Using --secret can expose the secret in shell history or process listings. Prefer interactive input, --secret-file, --secret-env, or --from-package."
                shift 2
                ;;
            --secret-file)
                SECRET_FILE="${2:-}"
                shift 2
                ;;
            --secret-env)
                SECRET_ENV="${2:-}"
                shift 2
                ;;
            --ca-cert)
                CA_CERT_SOURCE="${2:-}"
                shift 2
                ;;
            --from-package)
                FROM_PACKAGE="${2:-}"
                shift 2
                ;;
            --from-reverse-package)
                FROM_REVERSE_PACKAGE="${2:-}"
                shift 2
                ;;
            --reverse-host|--reverse-client-host)
                SERVER_HOST="${2:-}"
                shift 2
                ;;
            --reverse-port|--reverse-listen-port|--reverse-client-port)
                SERVER_PORT="${2:-}"
                LISTEN_PORT="${2:-}"
                REVERSE_PORT_SET=1
                shift 2
                ;;
            --reverse-domain)
                REVERSE_DOMAIN="${2:-}"
                shift 2
                ;;
            --reverse-cert-mode)
                REVERSE_CERT_MODE="${2:-}"
                shift 2
                ;;
            --reverse-cert-file)
                REVERSE_CERT_FILE="${2:-}"
                shift 2
                ;;
            --reverse-key-file)
                REVERSE_KEY_FILE="${2:-}"
                shift 2
                ;;
            --letsencrypt-email)
                LETSENCRYPT_EMAIL="${2:-}"
                shift 2
                ;;
            --letsencrypt-challenge)
                LETSENCRYPT_CHALLENGE="${2:-}"
                shift 2
                ;;
            --allowed-dialer-ip|--reverse-allowed-dialer-ip)
                if [ -n "$REVERSE_ALLOWED_DIALER_IPS" ]; then
                    REVERSE_ALLOWED_DIALER_IPS="$REVERSE_ALLOWED_DIALER_IPS ${2:-}"
                else
                    REVERSE_ALLOWED_DIALER_IPS="${2:-}"
                fi
                shift 2
                ;;
            --tls-verify-mode)
                TLS_VERIFY_MODE="${2:-}"
                shift 2
                ;;
            --reverse-ca-cert)
                REVERSE_CA_CERT_SOURCE="${2:-}"
                shift 2
                ;;
            --reverse-fingerprint)
                REVERSE_FINGERPRINT="${2:-}"
                shift 2
                ;;
            --export-reverse-package)
                EXPORT_REVERSE_PACKAGE=1
                shift
                ;;
            --include-reverse-secret)
                INCLUDE_REVERSE_SECRET=1
                shift
                ;;
            --ehlo-name)
                EHLO_NAME="${2:-}"
                shift 2
                ;;
            --service-name)
                SERVICE_NAME="${2:-}"
                shift 2
                ;;
            --non-interactive)
                NON_INTERACTIVE=1
                shift
                ;;
            --yes|-y)
                ASSUME_YES=1
                shift
                ;;
            --migrate-config)
                MIGRATE_CONFIG=1
                shift
                ;;
            --reset-config)
                RESET_CONFIG=1
                shift
                ;;
            --no-generate-certs)
                GENERATE_CERTS=0
                shift
                ;;
            --export-client-package)
                EXPORT_CLIENT_PACKAGE=1
                shift
                ;;
            --skip-start)
                SKIP_START=1
                shift
                ;;
            --allow-insecure-no-ca)
                ALLOW_INSECURE_NO_CA=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    validate_role
    validate_mode
    apply_production_reverse_tuning
}

validate_role() {
    if [ "$ROLE" != "server" ] && [ "$ROLE" != "client" ]; then
        print_error "--role must be either server or client"
        exit 1
    fi
}

validate_mode() {
    case "$MODE" in
        normal) ;;
        reverse-listen)
            [ "$ROLE" = "client" ] || { print_error "--mode reverse-listen requires --role client"; exit 1; }
            ;;
        reverse-dial)
            [ "$ROLE" = "server" ] || { print_error "--mode reverse-dial requires --role server"; exit 1; }
            ;;
        *)
            print_error "--mode must be normal, reverse-listen, or reverse-dial"
            exit 1
            ;;
    esac
}

apply_production_reverse_tuning() {
    if [ "$PRODUCTION_REVERSE_TUNING" -ne 1 ]; then
        return
    fi
    if [ "$MODE" != "reverse-listen" ] && [ "$MODE" != "reverse-dial" ]; then
        print_warn "--production-reverse-tuning applies only to reverse-listen or reverse-dial mode; leaving normal-mode defaults unchanged"
        return
    fi

    PERFORMANCE_PROFILE="throughput"
    PERFORMANCE_PROFILE_SET=1

    if [ "$MODE" = "reverse-dial" ] && [ "$CONNECTIONS_SET" -eq 0 ]; then
        CONNECTIONS="20"
        CONNECTIONS_SET=1
    fi
    if [ "$MODE" = "reverse-dial" ] && [ "$ADAPTIVE_CONNECTIONS_SET" -eq 0 ]; then
        ADAPTIVE_CONNECTIONS=1
        ADAPTIVE_CONNECTIONS_SET=1
    fi
    if [ "$MODE" = "reverse-dial" ] && [ "$MIN_CONNECTIONS_SET" -eq 0 ]; then
        MIN_CONNECTIONS="8"
    fi
    if [ "$MODE" = "reverse-dial" ] && [ "$MAX_CONNECTIONS_SET" -eq 0 ]; then
        MAX_CONNECTIONS="20"
    fi
}

check_root() {
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: root privileges are not required"
        return
    fi
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run as root (use sudo)"
        exit 1
    fi
}

detect_script_dir() {
    if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    else
        SCRIPT_DIR=""
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        OS="unknown"
        OS_VERSION="unknown"
    fi
    print_info "Detected OS: $OS $OS_VERSION"
}

confirm() {
    local prompt="$1"
    if [ "$ASSUME_YES" -eq 1 ]; then
        return 0
    fi
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        return 1
    fi
    read -r -p "$prompt [y/N]: " response < /dev/tty
    case "$response" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

read_from_tty() {
    local var_name="$1"
    local prompt="$2"
    if [ ! -r /dev/tty ]; then
        print_error "Interactive input requires a TTY. Re-run with --non-interactive and explicit options."
        exit 1
    fi
    read -r -p "$prompt" "$var_name" < /dev/tty
}

require_value() {
    local value="$1"
    local name="$2"
    if [ -z "$value" ]; then
        print_error "$name is required in non-interactive mode"
        exit 1
    fi
}

prompt_if_empty() {
    local var_name="$1"
    local prompt="$2"
    local current_value="${!var_name}"
    if [ -n "$current_value" ]; then
        return
    fi
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        require_value "$current_value" "$var_name"
    fi
    print_ask "$prompt"
    read_from_tty current_value "    "
    printf -v "$var_name" '%s' "$current_value"
}

prompt_with_default() {
    local var_name="$1"
    local prompt="$2"
    local default_value="$3"
    local current_value="${!var_name}"
    local shown="${current_value:-$default_value}"
    local response=""

    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        if [ -z "$current_value" ]; then
            printf -v "$var_name" '%s' "$default_value"
        fi
        return
    fi

    print_ask "$prompt [$shown]:"
    read_from_tty response "    "
    if [ -n "$response" ]; then
        printf -v "$var_name" '%s' "$response"
    elif [ -z "$current_value" ]; then
        printf -v "$var_name" '%s' "$default_value"
    fi
}

prompt_secret_if_empty() {
    local var_name="$1"
    local prompt="$2"
    local current_value="${!var_name}"
    load_secret_from_safe_source
    current_value="${!var_name}"
    if [ -n "$current_value" ]; then
        return
    fi
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        require_value "$current_value" "$var_name"
    fi
    print_ask "$prompt"
    local stty_state
    stty_state="$(stty -g < /dev/tty)"
    stty -echo < /dev/tty
    read_from_tty current_value "    "
    stty "$stty_state" < /dev/tty
    echo ""
    printf -v "$var_name" '%s' "$current_value"
}

load_secret_from_safe_source() {
    if [ -n "$SECRET_FILE" ]; then
        if [ ! -f "$SECRET_FILE" ]; then
            print_error "Secret file not found: $SECRET_FILE"
            exit 1
        fi
        SECRET_VALUE="$(head -n 1 "$SECRET_FILE")"
        if [ -z "$SECRET_VALUE" ]; then
            print_error "Secret file is empty: $SECRET_FILE"
            exit 1
        fi
        chmod 600 "$SECRET_FILE" 2>/dev/null || true
    fi
    if [ -n "$SECRET_ENV" ]; then
        SECRET_VALUE="${!SECRET_ENV:-}"
        if [ -z "$SECRET_VALUE" ]; then
            print_error "Environment variable is empty or missing: $SECRET_ENV"
            exit 1
        fi
    fi
}

default_ehlo_name() {
    local base=""
    if command -v hostname >/dev/null 2>&1; then
        base="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
    fi
    if [ -z "$base" ]; then
        base="client.local"
    fi
    echo "$base" | tr -cd 'A-Za-z0-9.-'
}

validate_port_value() {
    local port="$1"
    local name="$2"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        print_error "$name must be an integer between 1 and 65535"
        exit 1
    fi
}

validate_connections_value() {
    local value="$1"
    local name="${2:---connections}"
    if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -lt 1 ]; then
        print_error "$name must be an integer >= 1"
        exit 1
    fi
    if [ "$value" -gt 24 ]; then
        print_warn "$name $value is above the recommended tested range. Values above 24 can increase noise and may hurt upload or reliability."
        if [ "$ASSUME_YES" -ne 1 ] && ! confirm "Continue with $name $value?"; then
            print_error "Install cancelled because $name $value was not confirmed"
            exit 1
        fi
    fi
}

validate_adaptive_connection_values() {
    validate_connections_value "$CONNECTIONS" "--connections"
    validate_connections_value "$MIN_CONNECTIONS" "--min-connections"
    validate_connections_value "$MAX_CONNECTIONS" "--max-connections"
    if [ "$MAX_CONNECTIONS" -lt "$MIN_CONNECTIONS" ]; then
        print_error "--max-connections must be >= --min-connections"
        exit 1
    fi
    if ! [[ "$SCALE_DOWN_IDLE_SECONDS" =~ ^[0-9]+$ ]] || [ "$SCALE_DOWN_IDLE_SECONDS" -lt 1 ]; then
        print_error "--scale-down-idle-seconds must be an integer >= 1"
        exit 1
    fi
}

validate_performance_profile() {
    case "$PERFORMANCE_PROFILE" in
        compatibility|balanced|throughput) ;;
        *)
            print_error "--performance-profile must be compatibility, balanced, or throughput"
            exit 1
            ;;
    esac
}

check_python_version() {
    if ! command -v python3 >/dev/null 2>&1; then
        print_error "Python 3 not found"
        exit 1
    fi
    if ! python3 - << 'PY'
import sys
if sys.version_info < (3, 8):
    print("Python 3.8+ is required", file=sys.stderr)
    sys.exit(1)
print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
PY
    then
        exit 1
    fi
}

check_systemd_available() {
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would check for systemctl"
        return
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        print_error "systemctl not found. This installer currently creates a systemd service."
        exit 1
    fi
}

prompt_install_options() {
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        return
    fi

    if [ "$ROLE_SET" -eq 0 ]; then
        local role_response=""
        print_ask "Install role [server/client] [server]:"
        read_from_tty role_response "    "
        ROLE="${role_response:-server}"
        validate_role
    fi
    validate_mode

    prompt_with_default SERVICE_NAME "Enter systemd service name" "$SERVICE_NAME"

    if [ -f "$CONFIG_DIR/config.yaml" ] && [ "$MIGRATE_CONFIG" -ne 1 ] && [ "$RESET_CONFIG" -ne 1 ]; then
        print_info "Existing config found; role-specific config values will be preserved unless --migrate-config or --reset-config is used."
        return
    fi

    if [ "$MODE" = "reverse-listen" ]; then
        load_secret_from_safe_source
        prompt_with_default SOCKS_HOST "Enter local SOCKS bind host" "127.0.0.1"
        prompt_with_default SOCKS_PORT "Enter local SOCKS port" "1080"
        prompt_with_default LISTEN_HOST "Enter reverse listen host" "0.0.0.0"
        prompt_with_default LISTEN_PORT "Enter reverse listen port" "587"
        prompt_if_empty REVERSE_DOMAIN "Enter public domain for reverse listener TLS certificate:"
        prompt_with_default REVERSE_CERT_MODE "Certificate mode (existing, letsencrypt, letsencrypt-http, letsencrypt-dns, private-ca)" "$REVERSE_CERT_MODE"
        case "$REVERSE_CERT_MODE" in
            existing)
                prompt_if_empty REVERSE_CERT_FILE "Enter existing reverse certificate/fullchain path:"
                prompt_if_empty REVERSE_KEY_FILE "Enter existing reverse private key path:"
                ;;
            letsencrypt|letsencrypt-http|letsencrypt-dns)
                prompt_if_empty LETSENCRYPT_EMAIL "Enter Let's Encrypt email:"
                ;;
        esac
        prompt_if_empty USERNAME_VALUE "Enter reverse auth username:"
        prompt_secret_if_empty SECRET_VALUE "Enter reverse auth secret (input hidden):"
        prompt_if_empty REVERSE_ALLOWED_DIALER_IPS "Enter VPS public IP/CIDR allowed to dial reverse listener:"
        if confirm "Export a VPS reverse-dial bundle after install?"; then
            EXPORT_REVERSE_PACKAGE=1
            if confirm "Include reverse auth secret in VPS bundle?"; then
                INCLUDE_REVERSE_SECRET=1
            fi
        fi
    elif [ "$MODE" = "reverse-dial" ]; then
        load_secret_from_safe_source
        if [ -z "$FROM_REVERSE_PACKAGE" ]; then
            if [ "$CONNECTIONS_SET" -eq 0 ]; then
                CONNECTIONS="4"
            fi
            prompt_if_empty SERVER_HOST "Enter Access Node reverse host/domain:"
            prompt_with_default SERVER_PORT "Enter Access Node reverse port" "587"
            if [ -z "$REVERSE_DOMAIN" ]; then
                REVERSE_DOMAIN="$SERVER_HOST"
            fi
            prompt_with_default REVERSE_DOMAIN "Enter TLS server name/SNI" "$REVERSE_DOMAIN"
            prompt_with_default TLS_VERIFY_MODE "TLS verification mode (system-ca, private-ca, fingerprint)" "$TLS_VERIFY_MODE"
            if [ "$TLS_VERIFY_MODE" = "private-ca" ]; then
                prompt_if_empty REVERSE_CA_CERT_SOURCE "Enter reverse CA cert path:"
            elif [ "$TLS_VERIFY_MODE" = "fingerprint" ]; then
                prompt_if_empty REVERSE_FINGERPRINT "Enter reverse certificate SHA-256 fingerprint:"
            fi
            prompt_if_empty USERNAME_VALUE "Enter reverse auth username:"
            prompt_secret_if_empty SECRET_VALUE "Enter reverse auth secret (input hidden):"
            prompt_with_default CONNECTIONS "Enter reverse tunnel session count" "$CONNECTIONS"
        fi
    elif [ "$ROLE" = "server" ]; then
        prompt_with_default LISTEN_HOST "Enter server listen host" "0.0.0.0"
        prompt_with_default LISTEN_PORT "Enter server listen port" "587"
        prompt_if_empty HOSTNAME_VALUE "Enter public hostname/domain for certificate and SMTP greeting:"
        if [ -z "$EHLO_NAME" ]; then
            EHLO_NAME="$HOSTNAME_VALUE"
        fi
        prompt_with_default EHLO_NAME "Enter EHLO name for generated client configs" "$EHLO_NAME"
    elif [ -z "$FROM_PACKAGE" ]; then
        prompt_if_empty SERVER_HOST "Enter tunnel server hostname:"
        prompt_with_default SERVER_PORT "Enter tunnel server port" "587"
        prompt_with_default SOCKS_HOST "Enter local SOCKS bind host" "127.0.0.1"
        prompt_with_default SOCKS_PORT "Enter local SOCKS port" "1080"
        prompt_if_empty USERNAME_VALUE "Enter tunnel username:"
        if [ -z "$EHLO_NAME" ]; then
            EHLO_NAME="$(default_ehlo_name)"
        fi
        prompt_with_default EHLO_NAME "Enter EHLO name sent by this client" "$EHLO_NAME"
    fi
}

install_system_dependencies() {
    print_step "Installing system dependencies"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would install python3, pip, venv, openssl, curl/wget, and tar"
        return
    fi

    case "${OS:-unknown}" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq python3 python3-pip python3-venv openssl curl tar
            ;;
        centos|rhel|rocky|alma)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y python3 python3-pip openssl curl tar
            else
                yum install -y python3 python3-pip openssl curl tar
            fi
            ;;
        fedora)
            dnf install -y python3 python3-pip openssl curl tar
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm python python-pip openssl curl tar
            ;;
        *)
            print_warn "Unknown OS; assuming Python 3 and curl are already installed"
            ;;
    esac
}

install_certbot_if_needed() {
    case "$REVERSE_CERT_MODE" in
        letsencrypt|letsencrypt-http|letsencrypt-dns) ;;
        *) return ;;
    esac
    if command -v certbot >/dev/null 2>&1; then
        return
    fi
    print_step "Installing certbot for Let's Encrypt"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would install certbot"
        return
    fi
    case "${OS:-unknown}" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq certbot
            ;;
        centos|rhel|rocky|alma)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y certbot
            else
                yum install -y certbot
            fi
            ;;
        fedora)
            dnf install -y certbot
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm certbot
            ;;
        *)
            print_error "certbot is required for Let's Encrypt mode; install certbot or use existing/private-ca mode"
            exit 1
            ;;
    esac
}

detect_existing_install() {
    if [ -d "$INSTALL_DIR" ] || [ -d "$CONFIG_DIR" ] || [ -f "$SERVICE_DIR/${SERVICE_NAME}.service" ]; then
        EXISTING_INSTALL=1
    else
        EXISTING_INSTALL=0
    fi
}

backup_existing_install() {
    if [ "$EXISTING_INSTALL" -ne 1 ]; then
        return
    fi

    BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
    print_step "Backing up existing installation"
    print_info "Backup path: $BACKUP_DIR"

    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would create backup at $BACKUP_DIR"
        return
    fi

    mkdir -p "$BACKUP_DIR/config" "$BACKUP_DIR/install" "$BACKUP_DIR/systemd"

    if [ -d "$INSTALL_DIR" ]; then
        cp -a "$INSTALL_DIR" "$BACKUP_DIR/opt-smtp-tunnel"
    fi

    for file in config.yaml users.yaml server.crt server.key ca.crt ca.key; do
        if [ -f "$CONFIG_DIR/$file" ]; then
            cp -a "$CONFIG_DIR/$file" "$BACKUP_DIR/config/"
        fi
    done

    if [ -d "$CERT_DIR" ]; then
        cp -a "$CERT_DIR" "$BACKUP_DIR/config/certs"
    fi
    if [ -d "$REVERSE_CERT_DIR" ]; then
        cp -a "$REVERSE_CERT_DIR" "$BACKUP_DIR/config/reverse-certs"
    fi

    if [ -d "$INSTALL_DIR" ]; then
        for file in $PYTHON_FILES $SCRIPTS requirements.txt config.yaml.template users.yaml.template; do
            if [ -e "$INSTALL_DIR/$file" ]; then
                cp -a "$INSTALL_DIR/$file" "$BACKUP_DIR/install/"
            fi
        done
    fi

    if [ -f "$SERVICE_DIR/${SERVICE_NAME}.service" ]; then
        cp -a "$SERVICE_DIR/${SERVICE_NAME}.service" "$BACKUP_DIR/systemd/"
    fi

    cat > "$BACKUP_DIR/rollback.sh" << EOF
#!/bin/bash
set -e
SERVICE_NAME="$SERVICE_NAME"
INSTALL_DIR="$INSTALL_DIR"
CONFIG_DIR="$CONFIG_DIR"
SERVICE_DIR="$SERVICE_DIR"
BACKUP_DIR="$BACKUP_DIR"

echo "Stopping service..."
systemctl stop "\$SERVICE_NAME" 2>/dev/null || true

echo "Restoring config/certs..."
mkdir -p "\$CONFIG_DIR"
if [ -d "\$BACKUP_DIR/config" ]; then
  cp -a "\$BACKUP_DIR/config/." "\$CONFIG_DIR/"
fi

echo "Restoring application files..."
rm -rf "\$INSTALL_DIR"
if [ -d "\$BACKUP_DIR/opt-smtp-tunnel" ]; then
  cp -a "\$BACKUP_DIR/opt-smtp-tunnel" "\$INSTALL_DIR"
else
  mkdir -p "\$INSTALL_DIR"
  cp -a "\$BACKUP_DIR/install/." "\$INSTALL_DIR/" 2>/dev/null || true
fi

echo "Restoring systemd service..."
if [ -f "\$BACKUP_DIR/systemd/\${SERVICE_NAME}.service" ]; then
  cp -a "\$BACKUP_DIR/systemd/\${SERVICE_NAME}.service" "\$SERVICE_DIR/\${SERVICE_NAME}.service"
fi

systemctl daemon-reload
systemctl restart "\$SERVICE_NAME"
echo "Rollback complete."
EOF
    chmod +x "$BACKUP_DIR/rollback.sh"
}

create_directories() {
    print_step "Creating directories"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would create $INSTALL_DIR, $CONFIG_DIR, $CERT_DIR, and $LOG_DIR"
        return
    fi
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$CERT_DIR" "$REVERSE_CERT_DIR" "$LOG_DIR" "$BIN_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 700 "$CERT_DIR"
    chmod 700 "$REVERSE_CERT_DIR"
    chmod 755 "$LOG_DIR"
}

copy_or_download_file() {
    local filename="$1"
    local destination="$2"
    local source_path=""

    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$filename" ]; then
        source_path="$SCRIPT_DIR/$filename"
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        if [ -n "$source_path" ]; then
            print_info "Dry-run: would copy $source_path -> $destination"
        else
            print_info "Dry-run: would download $GITHUB_RAW/$filename -> $destination"
        fi
        return 0
    fi

    if [ -n "$source_path" ]; then
        cp -a "$source_path" "$destination"
        print_info "  Copied: $filename"
        return 0
    fi

    if curl -sSL -f "$GITHUB_RAW/$filename" -o "$destination" 2>/dev/null; then
        print_info "  Downloaded: $filename"
        return 0
    fi

    print_error "  Failed to install: $filename"
    return 1
}

install_application_files() {
    print_step "Installing application files"

    for file in $PYTHON_FILES; do
        copy_or_download_file "$file" "$INSTALL_DIR/$file" || exit 1
    done

    for script in $SCRIPTS; do
        copy_or_download_file "$script" "$INSTALL_DIR/$script" || exit 1
        if [ "$DRY_RUN" -ne 1 ]; then
            chmod +x "$INSTALL_DIR/$script"
            ln -sf "$INSTALL_DIR/$script" "$BIN_DIR/$script"
        fi
    done

    copy_or_download_file "requirements.txt" "$INSTALL_DIR/requirements.txt" || exit 1
    copy_or_download_file "config.yaml" "$INSTALL_DIR/config.yaml.template" || true
    copy_or_download_file "users.yaml" "$INSTALL_DIR/users.yaml.template" || true

    for file in $EXTRA_FILES; do
        copy_or_download_file "$file" "$INSTALL_DIR/$file" || true
    done

    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would install scripts/bootstrap.sh"
    else
        mkdir -p "$INSTALL_DIR/scripts"
        copy_or_download_file "scripts/bootstrap.sh" "$INSTALL_DIR/scripts/bootstrap.sh" || true
        [ -f "$INSTALL_DIR/scripts/bootstrap.sh" ] && chmod +x "$INSTALL_DIR/scripts/bootstrap.sh"
    fi
}

install_python_packages() {
    print_step "Installing Python packages"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would create venv at $VENV_DIR and install $INSTALL_DIR/requirements.txt"
        return
    fi
    python3 -m venv "$VENV_DIR"
    "$PYTHON_BIN" -m pip install --upgrade pip >/dev/null
    "$PYTHON_BIN" -m pip install -q -r "$INSTALL_DIR/requirements.txt"

    if ! "$PYTHON_BIN" -c "import yaml, cryptography" >/dev/null 2>&1; then
        print_error "Required Python packages are not importable after installation"
        exit 1
    fi
}

port_available() {
    local host="$1"
    local port="$2"
    python3 - "$host" "$port" << 'PY' >/dev/null 2>&1
import socket
import sys
host = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind((host, port))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
}

warn_if_process_running() {
    if pgrep -f "smtp-tunnel|server.py -c $CONFIG_DIR|client.py -c $CONFIG_DIR" >/dev/null 2>&1; then
        print_warn "A matching smtp-tunnel/python process may already be running"
    fi
}

preflight_role_values() {
    validate_port_value "$LISTEN_PORT" "--listen-port"
    validate_port_value "$SERVER_PORT" "--server-port"
    validate_port_value "$SOCKS_PORT" "--socks-port"
    validate_adaptive_connection_values
    validate_performance_profile
    if [ "$PRODUCTION_REVERSE_TUNING" -eq 1 ] && { [ "$MODE" = "reverse-listen" ] || [ "$MODE" = "reverse-dial" ]; }; then
        print_info "Production reverse tuning: enabled"
    fi
    print_info "Performance profile: $PERFORMANCE_PROFILE"
    if [ "$MODE" = "reverse-dial" ]; then
        print_info "Reverse tunnel sessions: $CONNECTIONS"
        print_info "Adaptive reverse sessions: $([ "$ADAPTIVE_CONNECTIONS" -eq 1 ] && echo enabled || echo disabled)"
        if [ "$ADAPTIVE_CONNECTIONS" -eq 1 ]; then
            print_info "Adaptive session range: min=$MIN_CONNECTIONS max=$MAX_CONNECTIONS"
        fi
    fi

    if [ "$MODE" = "reverse-listen" ]; then
        load_secret_from_safe_source
        if [ "$NON_INTERACTIVE" -eq 1 ] && { [ ! -f "$CONFIG_DIR/config.yaml" ] || [ "$RESET_CONFIG" -eq 1 ]; }; then
            require_value "$REVERSE_DOMAIN" "--reverse-domain"
            require_value "$USERNAME_VALUE" "--username"
            [ -n "$SECRET_VALUE" ] || { print_error "reverse-listen needs --secret-file, --secret-env, or interactive secret"; exit 1; }
            case "$REVERSE_CERT_MODE" in
                existing)
                    require_value "$REVERSE_CERT_FILE" "--reverse-cert-file"
                    require_value "$REVERSE_KEY_FILE" "--reverse-key-file"
                    ;;
                letsencrypt|letsencrypt-http|letsencrypt-dns)
                    require_value "$LETSENCRYPT_EMAIL" "--letsencrypt-email"
                    ;;
                private-ca) ;;
                *) print_error "--reverse-cert-mode must be existing, letsencrypt, letsencrypt-http, letsencrypt-dns, or private-ca"; exit 1 ;;
            esac
        fi
    elif [ "$MODE" = "reverse-dial" ]; then
        load_secret_from_safe_source
        if [ "$NON_INTERACTIVE" -eq 1 ] && { [ ! -f "$CONFIG_DIR/config.yaml" ] || [ "$RESET_CONFIG" -eq 1 ]; }; then
            if [ -n "$FROM_REVERSE_PACKAGE" ]; then
                [ -f "$FROM_REVERSE_PACKAGE" ] || { print_error "--from-reverse-package not found: $FROM_REVERSE_PACKAGE"; exit 1; }
                return
            fi
            require_value "$SERVER_HOST" "--reverse-host"
            require_value "$REVERSE_DOMAIN" "--reverse-domain"
            require_value "$USERNAME_VALUE" "--username"
            [ -n "$SECRET_VALUE" ] || { print_error "reverse-dial needs --secret-file, --secret-env, --from-reverse-package, or interactive secret"; exit 1; }
            case "$TLS_VERIFY_MODE" in
                system-ca) ;;
                private-ca) require_value "$REVERSE_CA_CERT_SOURCE" "--reverse-ca-cert" ;;
                fingerprint) require_value "$REVERSE_FINGERPRINT" "--reverse-fingerprint" ;;
                *) print_error "--tls-verify-mode must be system-ca, private-ca, or fingerprint"; exit 1 ;;
            esac
        fi
    elif [ "$ROLE" = "server" ]; then
        if [ "$NON_INTERACTIVE" -eq 1 ] && [ -z "$HOSTNAME_VALUE" ] && { [ ! -f "$CONFIG_DIR/config.yaml" ] || [ "$MIGRATE_CONFIG" -eq 1 ]; }; then
            require_value "$HOSTNAME_VALUE" "--hostname"
        fi
    else
        load_secret_from_safe_source
        if [ "$NON_INTERACTIVE" -eq 1 ] && { [ ! -f "$CONFIG_DIR/config.yaml" ] || [ "$MIGRATE_CONFIG" -eq 1 ] || [ "$RESET_CONFIG" -eq 1 ]; }; then
            if [ -n "$FROM_PACKAGE" ]; then
                [ -f "$FROM_PACKAGE" ] || { print_error "--from-package not found: $FROM_PACKAGE"; exit 1; }
                return
            fi
            require_value "$SERVER_HOST" "--server-host"
            require_value "$USERNAME_VALUE" "--username"
            if [ -z "$SECRET_VALUE" ]; then
                print_error "Non-interactive client install needs --secret-file, --secret-env, --from-package, existing config, or explicit --secret"
                exit 1
            fi
            if [ -z "$CA_CERT_SOURCE" ] && [ "$ALLOW_INSECURE_NO_CA" -ne 1 ]; then
                print_error "--ca-cert is required for non-interactive client install unless --allow-insecure-no-ca is set"
                exit 1
            fi
        fi
    fi
}

write_reverse_secret_file() {
    if [ -z "$SECRET_VALUE" ]; then
        return
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would write /etc/smtp-tunnel/reverse.secret"
        return
    fi
    printf '%s\n' "$SECRET_VALUE" > "$CONFIG_DIR/reverse.secret"
    chmod 600 "$CONFIG_DIR/reverse.secret"
}

update_existing_reverse_connections() {
    local config_path="$1"
    if [ "$CONNECTIONS_SET" -ne 1 ]; then
        return 1
    fi
    validate_connections_value "$CONNECTIONS"
    print_step "Updating reverse tunnel sessions in existing config"
    print_info "Reverse tunnel sessions: $CONNECTIONS"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would set tunnel.connections=$CONNECTIONS in $config_path"
        return 0
    fi
    "$PYTHON_BIN" - "$config_path" "$CONNECTIONS" << 'PY'
import sys
import yaml

config_path, connections = sys.argv[1], int(sys.argv[2])
with open(config_path, 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f) or {}
data.setdefault('tunnel', {})['connections'] = connections
with open(config_path, 'w', encoding='utf-8') as f:
    yaml.safe_dump(data, f, sort_keys=False)
PY
    chmod 600 "$config_path"
    return 0
}

update_existing_performance_profile() {
    local config_path="$1"
    if [ "$PERFORMANCE_PROFILE_SET" -ne 1 ]; then
        return 1
    fi
    validate_performance_profile
    print_step "Updating performance profile in existing config"
    print_info "Performance profile: $PERFORMANCE_PROFILE"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would set performance.profile=$PERFORMANCE_PROFILE in $config_path"
        return 0
    fi
    "$PYTHON_BIN" - "$config_path" "$PERFORMANCE_PROFILE" "$CONNECTIONS" "$CONNECTIONS_SET" "$ADAPTIVE_CONNECTIONS" "$ADAPTIVE_CONNECTIONS_SET" "$MIN_CONNECTIONS" "$MIN_CONNECTIONS_SET" "$MAX_CONNECTIONS" "$MAX_CONNECTIONS_SET" "$SCALE_DOWN_IDLE_SECONDS" "$SCALE_DOWN_IDLE_SECONDS_SET" "$IDLE_SESSION_RECYCLE" "$IDLE_SESSION_RECYCLE_SET" << 'PY'
import sys
import yaml

(
    config_path, profile, connections, connections_set,
    adaptive, adaptive_set, min_connections, min_set,
    max_connections, max_set, scale_down_idle, scale_down_set,
    idle_recycle, idle_recycle_set,
) = sys.argv[1:15]
with open(config_path, 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f) or {}

data.setdefault('performance', {})['profile'] = profile

tunnel = data.setdefault('tunnel', {})
tunnel.setdefault('connect_timeout', 10)
tunnel.setdefault('adaptive_connections', False)
tunnel.setdefault('min_connections', 8)
tunnel.setdefault('max_connections', 20)
tunnel.setdefault('scale_up_active_channels', 6)
tunnel.setdefault('scale_up_bytes_per_second', 524288)
tunnel.setdefault('scale_down_idle_seconds', 300)
tunnel.setdefault('session_start_interval_seconds', 2)
tunnel.setdefault('session_start_jitter_seconds', 5)
tunnel.setdefault('reconnect_global_backoff', True)
tunnel.setdefault('reconnect_circuit_breaker_failures', 10)
tunnel.setdefault('reconnect_circuit_breaker_window_seconds', 120)
tunnel.setdefault('reconnect_circuit_breaker_cooldown', 300)
tunnel.setdefault('idle_session_recycle', False)
tunnel.setdefault('idle_session_recycle_min_age_seconds', 3600)
tunnel.setdefault('idle_session_recycle_jitter_seconds', 900)
tunnel.setdefault('idle_session_recycle_max_per_cycle', 1)
if connections_set == '1':
    tunnel['connections'] = int(connections)
if adaptive_set == '1':
    tunnel['adaptive_connections'] = adaptive == '1'
if min_set == '1':
    tunnel['min_connections'] = int(min_connections)
if max_set == '1':
    tunnel['max_connections'] = int(max_connections)
if scale_down_set == '1':
    tunnel['scale_down_idle_seconds'] = int(scale_down_idle)
if idle_recycle_set == '1':
    tunnel['idle_session_recycle'] = idle_recycle == '1'
tunnel.setdefault('adaptive_connections', False)
tunnel.setdefault('min_connections', 8)
tunnel.setdefault('max_connections', 20)
tunnel.setdefault('scale_up_active_channels', 6)
tunnel.setdefault('scale_up_bytes_per_second', 524288)
tunnel.setdefault('scale_down_idle_seconds', 300)
tunnel.setdefault('session_start_interval_seconds', 2)
tunnel.setdefault('session_start_jitter_seconds', 5)
tunnel.setdefault('reconnect_global_backoff', True)
tunnel.setdefault('reconnect_circuit_breaker_failures', 10)
tunnel.setdefault('reconnect_circuit_breaker_window_seconds', 120)
tunnel.setdefault('reconnect_circuit_breaker_cooldown', 300)
tunnel.setdefault('idle_session_recycle', False)
tunnel.setdefault('idle_session_recycle_min_age_seconds', 3600)
tunnel.setdefault('idle_session_recycle_jitter_seconds', 900)
tunnel.setdefault('idle_session_recycle_max_per_cycle', 1)

metrics = data.setdefault('metrics', {})
metrics.setdefault('enabled', True)
metrics.setdefault('log_interval', 30)
metrics.setdefault('verbose', False)

logging_conf = data.setdefault('logging', {})
logging_conf.setdefault('log_destinations', False)
logging_conf.setdefault('log_session_events', True)
logging_conf.setdefault('log_metrics', True)

transport = data.setdefault('transport', {})
transport.setdefault('read_chunk_size', 65535)
transport.setdefault('drain_bytes', 262144)
transport.setdefault('drain_interval_ms', 10)
transport.setdefault('socket_send_buffer', 0)
transport.setdefault('socket_recv_buffer', 0)
transport.setdefault('tcp_nodelay', True)
transport.setdefault('tcp_keepalive', True)
transport.setdefault('pending_buffer_limit', 1048576)

with open(config_path, 'w', encoding='utf-8') as f:
    yaml.safe_dump(data, f, sort_keys=False)
PY
    chmod 600 "$config_path"
    return 0
}

update_existing_adaptive_settings() {
    local config_path="$1"
    if [ "$ADAPTIVE_CONNECTIONS_SET" -ne 1 ] && [ "$MIN_CONNECTIONS_SET" -ne 1 ] && [ "$MAX_CONNECTIONS_SET" -ne 1 ] && [ "$SCALE_DOWN_IDLE_SECONDS_SET" -ne 1 ] && [ "$IDLE_SESSION_RECYCLE_SET" -ne 1 ]; then
        return 1
    fi
    print_step "Updating adaptive reverse session settings in existing config"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would update adaptive reverse settings in $config_path"
        return 0
    fi
    "$PYTHON_BIN" - "$config_path" "$ADAPTIVE_CONNECTIONS" "$ADAPTIVE_CONNECTIONS_SET" "$MIN_CONNECTIONS" "$MIN_CONNECTIONS_SET" "$MAX_CONNECTIONS" "$MAX_CONNECTIONS_SET" "$SCALE_DOWN_IDLE_SECONDS" "$SCALE_DOWN_IDLE_SECONDS_SET" "$IDLE_SESSION_RECYCLE" "$IDLE_SESSION_RECYCLE_SET" << 'PY'
import sys
import yaml

(
    config_path, adaptive, adaptive_set, min_connections, min_set,
    max_connections, max_set, scale_down_idle, scale_down_set,
    idle_recycle, idle_recycle_set,
) = sys.argv[1:12]

with open(config_path, 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f) or {}

tunnel = data.setdefault('tunnel', {})
if adaptive_set == '1':
    tunnel['adaptive_connections'] = adaptive == '1'
if min_set == '1':
    tunnel['min_connections'] = int(min_connections)
if max_set == '1':
    tunnel['max_connections'] = int(max_connections)
if scale_down_set == '1':
    tunnel['scale_down_idle_seconds'] = int(scale_down_idle)
if idle_recycle_set == '1':
    tunnel['idle_session_recycle'] = idle_recycle == '1'

with open(config_path, 'w', encoding='utf-8') as f:
    yaml.safe_dump(data, f, sort_keys=False)
PY
    chmod 600 "$config_path"
    return 0
}

update_existing_reverse_listen_migration() {
    local config_path="$1"
    print_step "Migrating reverse-listen config without replacing secrets or TLS settings"
    if [ "$REVERSE_PORT_SET" -eq 1 ]; then
        print_info "Reverse listen port: $LISTEN_PORT"
    fi
    if [ "$PERFORMANCE_PROFILE_SET" -eq 1 ]; then
        print_info "Performance profile: $PERFORMANCE_PROFILE"
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would update reverse-listen runtime defaults in $config_path"
        return 0
    fi
    "$PYTHON_BIN" - "$config_path" "$LISTEN_PORT" "$REVERSE_PORT_SET" "$PERFORMANCE_PROFILE" "$PERFORMANCE_PROFILE_SET" << 'PY'
import sys
import yaml

config_path, reverse_port, reverse_port_set, profile, profile_set = sys.argv[1:6]
with open(config_path, 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f) or {}

client = data.setdefault('client', {})
if reverse_port_set == '1':
    reverse = client.setdefault('reverse', {})
    reverse['listen_port'] = int(reverse_port)

if profile_set == '1':
    data.setdefault('performance', {})['profile'] = profile

tunnel = data.setdefault('tunnel', {})
tunnel.setdefault('connect_timeout', 10)

metrics = data.setdefault('metrics', {})
metrics.setdefault('enabled', True)
metrics.setdefault('log_interval', 30)
metrics.setdefault('verbose', False)

logging_conf = data.setdefault('logging', {})
logging_conf.setdefault('log_destinations', False)
logging_conf.setdefault('log_session_events', True)
logging_conf.setdefault('log_metrics', True)

transport = data.setdefault('transport', {})
transport.setdefault('read_chunk_size', 65535)
transport.setdefault('drain_bytes', 262144)
transport.setdefault('drain_interval_ms', 10)
transport.setdefault('socket_send_buffer', 0)
transport.setdefault('socket_recv_buffer', 0)
transport.setdefault('tcp_nodelay', True)
transport.setdefault('tcp_keepalive', True)
transport.setdefault('pending_buffer_limit', 1048576)

with open(config_path, 'w', encoding='utf-8') as f:
    yaml.safe_dump(data, f, sort_keys=False)
PY
    chmod 600 "$config_path"
    return 0
}

update_existing_reverse_dial_migration() {
    local config_path="$1"
    print_step "Migrating reverse-dial config without replacing secrets or TLS settings"
    if [ "$REVERSE_PORT_SET" -eq 1 ]; then
        print_info "Reverse access port: $SERVER_PORT"
    fi
    if [ "$CONNECTIONS_SET" -eq 1 ]; then
        print_info "Reverse tunnel sessions: $CONNECTIONS"
    fi
    if [ "$PERFORMANCE_PROFILE_SET" -eq 1 ]; then
        print_info "Performance profile: $PERFORMANCE_PROFILE"
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would update reverse-dial runtime defaults in $config_path"
        return 0
    fi
    "$PYTHON_BIN" - "$config_path" "$SERVER_PORT" "$REVERSE_PORT_SET" "$CONNECTIONS" "$CONNECTIONS_SET" "$PERFORMANCE_PROFILE" "$PERFORMANCE_PROFILE_SET" "$ADAPTIVE_CONNECTIONS" "$ADAPTIVE_CONNECTIONS_SET" "$MIN_CONNECTIONS" "$MIN_CONNECTIONS_SET" "$MAX_CONNECTIONS" "$MAX_CONNECTIONS_SET" "$SCALE_DOWN_IDLE_SECONDS" "$SCALE_DOWN_IDLE_SECONDS_SET" "$IDLE_SESSION_RECYCLE" "$IDLE_SESSION_RECYCLE_SET" << 'PY'
import sys
import yaml

(
    config_path, reverse_port, reverse_port_set, connections, connections_set,
    profile, profile_set, adaptive, adaptive_set, min_connections, min_set,
    max_connections, max_set, scale_down_idle, scale_down_set,
    idle_recycle, idle_recycle_set,
) = sys.argv[1:18]
with open(config_path, 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f) or {}

server = data.setdefault('server', {})
if reverse_port_set == '1':
    reverse = server.setdefault('reverse', {})
    reverse['access_port'] = int(reverse_port)

tunnel = data.setdefault('tunnel', {})
tunnel.setdefault('connect_timeout', 10)
if connections_set == '1':
    tunnel['connections'] = int(connections)
if adaptive_set == '1':
    tunnel['adaptive_connections'] = adaptive == '1'
if min_set == '1':
    tunnel['min_connections'] = int(min_connections)
if max_set == '1':
    tunnel['max_connections'] = int(max_connections)
if scale_down_set == '1':
    tunnel['scale_down_idle_seconds'] = int(scale_down_idle)
if idle_recycle_set == '1':
    tunnel['idle_session_recycle'] = idle_recycle == '1'
tunnel.setdefault('adaptive_connections', False)
tunnel.setdefault('min_connections', 8)
tunnel.setdefault('max_connections', 20)
tunnel.setdefault('scale_up_active_channels', 6)
tunnel.setdefault('scale_up_bytes_per_second', 524288)
tunnel.setdefault('scale_down_idle_seconds', 300)
tunnel.setdefault('session_start_interval_seconds', 2)
tunnel.setdefault('session_start_jitter_seconds', 5)
tunnel.setdefault('reconnect_global_backoff', True)
tunnel.setdefault('reconnect_circuit_breaker_failures', 10)
tunnel.setdefault('reconnect_circuit_breaker_window_seconds', 120)
tunnel.setdefault('reconnect_circuit_breaker_cooldown', 300)
tunnel.setdefault('idle_session_recycle', False)
tunnel.setdefault('idle_session_recycle_min_age_seconds', 3600)
tunnel.setdefault('idle_session_recycle_jitter_seconds', 900)
tunnel.setdefault('idle_session_recycle_max_per_cycle', 1)

if profile_set == '1':
    data.setdefault('performance', {})['profile'] = profile

metrics = data.setdefault('metrics', {})
metrics.setdefault('enabled', True)
metrics.setdefault('log_interval', 30)
metrics.setdefault('verbose', False)

logging_conf = data.setdefault('logging', {})
logging_conf.setdefault('log_destinations', False)
logging_conf.setdefault('log_session_events', True)
logging_conf.setdefault('log_metrics', True)

transport = data.setdefault('transport', {})
transport.setdefault('read_chunk_size', 65535)
transport.setdefault('drain_bytes', 262144)
transport.setdefault('drain_interval_ms', 10)
transport.setdefault('socket_send_buffer', 0)
transport.setdefault('socket_recv_buffer', 0)
transport.setdefault('tcp_nodelay', True)
transport.setdefault('tcp_keepalive', True)
transport.setdefault('pending_buffer_limit', 1048576)

with open(config_path, 'w', encoding='utf-8') as f:
    yaml.safe_dump(data, f, sort_keys=False)
PY
    chmod 600 "$config_path"
    return 0
}

install_letsencrypt_renew_hook() {
    if [ "$REVERSE_CERT_MODE" != "letsencrypt" ] && [ "$REVERSE_CERT_MODE" != "letsencrypt-http" ] && [ "$REVERSE_CERT_MODE" != "letsencrypt-dns" ]; then
        return
    fi
    print_step "Installing Let's Encrypt renewal deploy hook"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would install certbot deploy hook to restart $SERVICE_NAME"
        return
    fi
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/smtp-tunnel-restart.sh << EOF
#!/bin/bash
systemctl try-restart "$SERVICE_NAME" >/dev/null 2>&1 || true
EOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/smtp-tunnel-restart.sh
}

provision_reverse_certificate() {
    if [ "$MODE" != "reverse-listen" ]; then
        return
    fi

    prompt_if_empty REVERSE_DOMAIN "Enter public domain for reverse listener certificate:"
    if [ "$REVERSE_CERT_MODE" = "letsencrypt" ]; then
        if [ "$LETSENCRYPT_CHALLENGE" = "dns-01" ] || [ "$LETSENCRYPT_CHALLENGE" = "manual" ]; then
            REVERSE_CERT_MODE="letsencrypt-dns"
        else
            REVERSE_CERT_MODE="letsencrypt-http"
        fi
    fi

    case "$REVERSE_CERT_MODE" in
        existing)
            prompt_if_empty REVERSE_CERT_FILE "Enter existing reverse certificate/fullchain path:"
            prompt_if_empty REVERSE_KEY_FILE "Enter existing reverse private key path:"
            [ -f "$REVERSE_CERT_FILE" ] || { print_error "Reverse cert file not found: $REVERSE_CERT_FILE"; exit 1; }
            [ -f "$REVERSE_KEY_FILE" ] || { print_error "Reverse key file not found: $REVERSE_KEY_FILE"; exit 1; }
            ;;
        letsencrypt|letsencrypt-http)
            prompt_if_empty LETSENCRYPT_EMAIL "Enter Let's Encrypt email:"
            print_warn "HTTP-01 requires $REVERSE_DOMAIN to point to this Access Node, public TCP/80 reachable, and no service occupying port 80 during issuance."
            if ! confirm "Continue with Let's Encrypt HTTP-01 issuance?"; then
                print_error "Let's Encrypt HTTP-01 cancelled"
                exit 1
            fi
            install_certbot_if_needed
            if [ "$DRY_RUN" -eq 1 ]; then
                print_info "Dry-run: would run certbot certonly --standalone for $REVERSE_DOMAIN"
            else
                certbot certonly --standalone -d "$REVERSE_DOMAIN" --email "$LETSENCRYPT_EMAIL" --agree-tos --non-interactive
            fi
            REVERSE_CERT_FILE="/etc/letsencrypt/live/$REVERSE_DOMAIN/fullchain.pem"
            REVERSE_KEY_FILE="/etc/letsencrypt/live/$REVERSE_DOMAIN/privkey.pem"
            install_letsencrypt_renew_hook
            ;;
        letsencrypt-dns)
            prompt_if_empty LETSENCRYPT_EMAIL "Enter Let's Encrypt email:"
            print_warn "DNS-01/manual requires control of DNS for $REVERSE_DOMAIN. Certbot will ask you to create TXT records."
            install_certbot_if_needed
            if [ "$NON_INTERACTIVE" -eq 1 ]; then
                print_error "Let's Encrypt DNS-01 manual mode is interactive. Use existing/private-ca mode or run without --non-interactive."
                exit 1
            fi
            if [ "$DRY_RUN" -eq 1 ]; then
                print_info "Dry-run: would run certbot certonly --manual --preferred-challenges dns for $REVERSE_DOMAIN"
            else
                certbot certonly --manual --preferred-challenges dns -d "$REVERSE_DOMAIN" --email "$LETSENCRYPT_EMAIL" --agree-tos
            fi
            REVERSE_CERT_FILE="/etc/letsencrypt/live/$REVERSE_DOMAIN/fullchain.pem"
            REVERSE_KEY_FILE="/etc/letsencrypt/live/$REVERSE_DOMAIN/privkey.pem"
            install_letsencrypt_renew_hook
            ;;
        private-ca)
            REVERSE_CERT_FILE="$REVERSE_CERT_DIR/server.crt"
            REVERSE_KEY_FILE="$REVERSE_CERT_DIR/server.key"
            if [ -f "$REVERSE_CERT_FILE" ] && [ -f "$REVERSE_KEY_FILE" ] && [ -f "$REVERSE_CERT_DIR/ca.crt" ]; then
                print_info "Existing reverse private CA certificate preserved"
                return
            fi
            print_step "Generating reverse private CA certificate"
            if [ "$DRY_RUN" -eq 1 ]; then
                print_info "Dry-run: would generate reverse private CA certs in $REVERSE_CERT_DIR"
            else
                (cd "$INSTALL_DIR" && "$PYTHON_BIN" generate_certs.py --hostname "$REVERSE_DOMAIN" --output-dir "$REVERSE_CERT_DIR")
            fi
            ;;
        *)
            print_error "--reverse-cert-mode must be existing, letsencrypt, letsencrypt-http, letsencrypt-dns, or private-ca"
            exit 1
            ;;
    esac
}

write_yaml_list_from_words() {
    local words="$1"
    if [ -z "$words" ]; then
        echo "      []"
        return
    fi
    for item in $words; do
        echo "      - $item"
    done
}

write_reverse_listen_config() {
    local config_path="$CONFIG_DIR/config.yaml"
    if [ -f "$config_path" ] && [ "$MIGRATE_CONFIG" -eq 1 ] && [ "$RESET_CONFIG" -ne 1 ]; then
        update_existing_reverse_listen_migration "$config_path"
        return
    fi
    if [ -f "$config_path" ] && [ "$MIGRATE_CONFIG" -ne 1 ] && [ "$RESET_CONFIG" -ne 1 ]; then
        if update_existing_performance_profile "$config_path"; then
            return
        fi
        if update_existing_adaptive_settings "$config_path"; then
            return
        fi
        print_info "Existing config preserved: $config_path"
        return
    fi
    if [ -f "$config_path" ] && { [ "$MIGRATE_CONFIG" -eq 1 ] || [ "$RESET_CONFIG" -eq 1 ]; }; then
        if ! confirm "Overwrite $config_path with reverse-listen config? Backup already exists."; then
            print_info "Existing config preserved"
            return
        fi
    fi

    prompt_secret_if_empty SECRET_VALUE "Enter reverse auth secret (input hidden):"
    write_reverse_secret_file
    provision_reverse_certificate

    print_step "Writing reverse-listen config"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would write $config_path"
        return
    fi

    cat > "$config_path" << EOF
# SMTP Tunnel Proxy Configuration
# Generated by install.sh for Access Node reverse-listen mode

client:
  mode: reverse-listen
  socks_host: "$SOCKS_HOST"
  socks_port: $SOCKS_PORT
  reverse:
    listen_host: "$LISTEN_HOST"
    listen_port: $LISTEN_PORT
    auth_username: "$USERNAME_VALUE"
    auth_secret_file: "$CONFIG_DIR/reverse.secret"
    allowed_dialer_ips:
EOF
    write_yaml_list_from_words "$REVERSE_ALLOWED_DIALER_IPS" >> "$config_path"
    cat >> "$config_path" << EOF
    tls:
      cert_mode: "$([ "$REVERSE_CERT_MODE" = "letsencrypt" ] || [ "$REVERSE_CERT_MODE" = "letsencrypt-http" ] || [ "$REVERSE_CERT_MODE" = "letsencrypt-dns" ] && echo "letsencrypt" || echo "$REVERSE_CERT_MODE")"
      domain: "$REVERSE_DOMAIN"
      cert_file: "$REVERSE_CERT_FILE"
      key_file: "$REVERSE_KEY_FILE"
      letsencrypt_email: "$LETSENCRYPT_EMAIL"
      letsencrypt_challenge: "$LETSENCRYPT_CHALLENGE"
      auto_renew: true
    mtls:
      enabled: false

tunnel:
  connections: 1
  adaptive_connections: $([ "$ADAPTIVE_CONNECTIONS" -eq 1 ] && echo true || echo false)
  min_connections: $MIN_CONNECTIONS
  max_connections: $MAX_CONNECTIONS
  scale_up_active_channels: 6
  scale_up_bytes_per_second: 524288
  scale_down_idle_seconds: $SCALE_DOWN_IDLE_SECONDS
  session_start_interval_seconds: 2
  session_start_jitter_seconds: 5
  reconnect_global_backoff: true
  reconnect_circuit_breaker_failures: 10
  reconnect_circuit_breaker_window_seconds: 120
  reconnect_circuit_breaker_cooldown: 300
  idle_session_recycle: $([ "$IDLE_SESSION_RECYCLE" -eq 1 ] && echo true || echo false)
  idle_session_recycle_min_age_seconds: 3600
  idle_session_recycle_jitter_seconds: 900
  idle_session_recycle_max_per_cycle: 1
  keepalive_interval: 45
  keepalive_timeout: 120
  reconnect_initial_delay: 2
  reconnect_max_delay: 60
  reconnect_jitter: 0.35
  connect_timeout: 10

performance:
  profile: $PERFORMANCE_PROFILE

metrics:
  enabled: true
  log_interval: 30
  verbose: false

transport:
  read_chunk_size: 65535
  drain_bytes: 262144
  drain_interval_ms: 10
  socket_send_buffer: 0
  socket_recv_buffer: 0
  tcp_nodelay: true
  tcp_keepalive: true
  pending_buffer_limit: 1048576

logging:
  log_destinations: false
  log_session_events: true
  log_metrics: true

smtp:
  ehlo_name: "${EHLO_NAME:-$REVERSE_DOMAIN}"
EOF
    chmod 600 "$config_path"
}

import_reverse_package() {
    local package_path="$1"
    local config_path="$CONFIG_DIR/config.yaml"
    local tmpdir package_config package_secret package_ca
    [ -f "$package_path" ] || { print_error "Reverse package not found: $package_path"; exit 1; }
    if ! tar -tzf "$package_path" >/dev/null 2>&1; then
        print_error "Reverse package is not a readable tar.gz archive: $package_path"
        exit 1
    fi
    tmpdir="$(mktemp -d /tmp/smtp-tunnel-reverse-package.XXXXXX)"
    tar -xzf "$package_path" -C "$tmpdir"
    package_config="$(find "$tmpdir" -type f -name config.yaml | head -n 1)"
    package_secret="$(find "$tmpdir" -type f -name reverse.secret | head -n 1)"
    package_ca="$(find "$tmpdir" -type f -name ca.crt | head -n 1)"
    [ -n "$package_config" ] || { rm -rf "$tmpdir"; print_error "Reverse package missing config.yaml"; exit 1; }
    cp -a "$package_config" "$config_path"
    chmod 600 "$config_path"
    if [ -n "$package_secret" ]; then
        cp -a "$package_secret" "$CONFIG_DIR/reverse.secret"
        chmod 600 "$CONFIG_DIR/reverse.secret"
    else
        prompt_secret_if_empty SECRET_VALUE "Enter reverse auth secret (input hidden):"
        write_reverse_secret_file
        "$PYTHON_BIN" - "$config_path" "$CONFIG_DIR/reverse.secret" << 'PY'
import sys
import yaml
config_path, secret_path = sys.argv[1:3]
with open(config_path, 'r') as f:
    data = yaml.safe_load(f) or {}
data.setdefault('server', {}).setdefault('reverse', {})['auth_secret_file'] = secret_path
with open(config_path, 'w') as f:
    yaml.safe_dump(data, f, sort_keys=False)
PY
    fi
    if [ -n "$package_ca" ]; then
        cp -a "$package_ca" "$CERT_DIR/reverse-ca.crt"
        chmod 644 "$CERT_DIR/reverse-ca.crt"
    fi
    rm -rf "$tmpdir"
    print_info "Reverse-dial config installed from package"
}

write_reverse_dial_config() {
    local config_path="$CONFIG_DIR/config.yaml"
    local ca_path=""
    if [ "$CONNECTIONS_SET" -eq 0 ]; then
        CONNECTIONS="4"
    fi
    if [ -f "$config_path" ] && [ "$MIGRATE_CONFIG" -eq 1 ] && [ "$RESET_CONFIG" -ne 1 ]; then
        update_existing_reverse_dial_migration "$config_path"
        return
    fi
    if [ -f "$config_path" ] && [ "$MIGRATE_CONFIG" -ne 1 ] && [ "$RESET_CONFIG" -ne 1 ]; then
        if update_existing_performance_profile "$config_path"; then
            return
        fi
        if update_existing_adaptive_settings "$config_path"; then
            return
        fi
        if update_existing_reverse_connections "$config_path"; then
            return
        fi
        print_info "Existing config preserved: $config_path"
        return
    fi
    if [ -f "$config_path" ] && { [ "$MIGRATE_CONFIG" -eq 1 ] || [ "$RESET_CONFIG" -eq 1 ]; }; then
        if ! confirm "Overwrite $config_path with reverse-dial config? Backup already exists."; then
            print_info "Existing config preserved"
            return
        fi
    fi
    if [ -n "$FROM_REVERSE_PACKAGE" ]; then
        import_reverse_package "$FROM_REVERSE_PACKAGE"
        update_existing_performance_profile "$config_path" || true
        return
    fi

    prompt_secret_if_empty SECRET_VALUE "Enter reverse auth secret (input hidden):"
    write_reverse_secret_file
    print_info "Reverse tunnel sessions: $CONNECTIONS"
    if [ "$TLS_VERIFY_MODE" = "private-ca" ]; then
        [ -f "$REVERSE_CA_CERT_SOURCE" ] || { print_error "Reverse CA cert not found: $REVERSE_CA_CERT_SOURCE"; exit 1; }
        ca_path="$CERT_DIR/reverse-ca.crt"
        if [ "$DRY_RUN" -eq 1 ]; then
            print_info "Dry-run: would copy $REVERSE_CA_CERT_SOURCE -> $ca_path"
        else
            cp -a "$REVERSE_CA_CERT_SOURCE" "$ca_path"
            chmod 644 "$ca_path"
        fi
    fi

    print_step "Writing reverse-dial config"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would write $config_path"
        return
    fi
    cat > "$config_path" << EOF
# SMTP Tunnel Proxy Configuration
# Generated by install.sh for Exit Node reverse-dial mode

server:
  mode: reverse-dial
  reverse:
    access_host: "$SERVER_HOST"
    access_port: $SERVER_PORT
    tls_server_name: "${REVERSE_DOMAIN:-$SERVER_HOST}"
    auth_username: "$USERNAME_VALUE"
    auth_secret_file: "$CONFIG_DIR/reverse.secret"
    tls:
      verify_mode: "$TLS_VERIFY_MODE"
      ca_cert: "${ca_path:-$REVERSE_CA_CERT_SOURCE}"
      cert_fingerprint_sha256: "$REVERSE_FINGERPRINT"
    mtls:
      enabled: false

tunnel:
  connections: $CONNECTIONS
  adaptive_connections: $([ "$ADAPTIVE_CONNECTIONS" -eq 1 ] && echo true || echo false)
  min_connections: $MIN_CONNECTIONS
  max_connections: $MAX_CONNECTIONS
  scale_up_active_channels: 6
  scale_up_bytes_per_second: 524288
  scale_down_idle_seconds: $SCALE_DOWN_IDLE_SECONDS
  session_start_interval_seconds: 2
  session_start_jitter_seconds: 5
  reconnect_global_backoff: true
  reconnect_circuit_breaker_failures: 10
  reconnect_circuit_breaker_window_seconds: 120
  reconnect_circuit_breaker_cooldown: 300
  idle_session_recycle: $([ "$IDLE_SESSION_RECYCLE" -eq 1 ] && echo true || echo false)
  idle_session_recycle_min_age_seconds: 3600
  idle_session_recycle_jitter_seconds: 900
  idle_session_recycle_max_per_cycle: 1
  keepalive_interval: 45
  keepalive_timeout: 120
  reconnect_initial_delay: 2
  reconnect_max_delay: 60
  reconnect_jitter: 0.35
  connect_timeout: 10

performance:
  profile: $PERFORMANCE_PROFILE

metrics:
  enabled: true
  log_interval: 30
  verbose: false

transport:
  read_chunk_size: 65535
  drain_bytes: 262144
  drain_interval_ms: 10
  socket_send_buffer: 0
  socket_recv_buffer: 0
  tcp_nodelay: true
  tcp_keepalive: true
  pending_buffer_limit: 1048576

logging:
  log_destinations: false
  log_session_events: true
  log_metrics: true

smtp:
  ehlo_name: "${EHLO_NAME:-$SERVER_HOST}"
EOF
    chmod 600 "$config_path"
}

export_reverse_dial_bundle() {
    if [ "$MODE" != "reverse-listen" ] || [ "$EXPORT_REVERSE_PACKAGE" -ne 1 ]; then
        return
    fi
    local bundle_dir bundle_path ca_line secret_line bundle_connections
    bundle_dir="$(mktemp -d /tmp/smtp-tunnel-reverse-bundle.XXXXXX)"
    bundle_path="/root/smtp-tunnel-reverse-dial-${USERNAME_VALUE:-vps}.tar.gz"
    bundle_connections="$CONNECTIONS"
    if [ "$CONNECTIONS_SET" -eq 0 ]; then
        bundle_connections="20"
    fi
    ca_line=""
    secret_line='    # auth_secret_file: "/etc/smtp-tunnel/reverse.secret"'
    if [ "$REVERSE_CERT_MODE" = "private-ca" ] && [ -f "$REVERSE_CERT_DIR/ca.crt" ]; then
        cp -a "$REVERSE_CERT_DIR/ca.crt" "$bundle_dir/ca.crt"
        ca_line='      ca_cert: "/etc/smtp-tunnel/certs/reverse-ca.crt"'
    elif [ "$REVERSE_CERT_MODE" = "private-ca" ] && [ "$DRY_RUN" -eq 1 ]; then
        ca_line='      ca_cert: "/etc/smtp-tunnel/certs/reverse-ca.crt"'
    fi
    if [ "$INCLUDE_REVERSE_SECRET" -eq 1 ] && [ -f "$CONFIG_DIR/reverse.secret" ]; then
        cp -a "$CONFIG_DIR/reverse.secret" "$bundle_dir/reverse.secret"
        secret_line='    auth_secret_file: "/etc/smtp-tunnel/reverse.secret"'
    elif [ "$INCLUDE_REVERSE_SECRET" -eq 1 ] && [ "$DRY_RUN" -eq 1 ]; then
        secret_line='    auth_secret_file: "/etc/smtp-tunnel/reverse.secret"'
    fi
    cat > "$bundle_dir/config.yaml" << EOF
server:
  mode: reverse-dial
  reverse:
    access_host: "$REVERSE_DOMAIN"
    access_port: $LISTEN_PORT
    tls_server_name: "$REVERSE_DOMAIN"
    auth_username: "$USERNAME_VALUE"
$secret_line
    tls:
      verify_mode: "$([ "$REVERSE_CERT_MODE" = "private-ca" ] && echo "private-ca" || echo "system-ca")"
$ca_line
      cert_fingerprint_sha256: ""
    mtls:
      enabled: false

tunnel:
  connections: $bundle_connections
  adaptive_connections: true
  min_connections: 8
  max_connections: 20
  scale_up_active_channels: 6
  scale_up_bytes_per_second: 524288
  scale_down_idle_seconds: 300
  session_start_interval_seconds: 2
  session_start_jitter_seconds: 5
  reconnect_global_backoff: true
  reconnect_circuit_breaker_failures: 10
  reconnect_circuit_breaker_window_seconds: 120
  reconnect_circuit_breaker_cooldown: 300
  idle_session_recycle: false
  idle_session_recycle_min_age_seconds: 3600
  idle_session_recycle_jitter_seconds: 900
  idle_session_recycle_max_per_cycle: 1
  keepalive_interval: 45
  keepalive_timeout: 120
  reconnect_initial_delay: 2
  reconnect_max_delay: 60
  reconnect_jitter: 0.35
  connect_timeout: 10

performance:
  profile: $PERFORMANCE_PROFILE

metrics:
  enabled: true
  log_interval: 30
  verbose: false

transport:
  read_chunk_size: 65535
  drain_bytes: 262144
  drain_interval_ms: 10
  socket_send_buffer: 0
  socket_recv_buffer: 0
  tcp_nodelay: true
  tcp_keepalive: true
  pending_buffer_limit: 1048576

logging:
  log_destinations: false
  log_session_events: true
  log_metrics: true
EOF
    cat > "$bundle_dir/INSTALL-REVERSE-DIAL.txt" << EOF
Install on the VPS Exit Node:

sudo bash ./install.sh --role server --mode reverse-dial --from-reverse-package /path/to/$(basename "$bundle_path")

If reverse.secret is not included, enter the reverse auth secret during install.
EOF
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would create reverse-dial bundle at $bundle_path"
    else
        tar -czf "$bundle_path" -C "$bundle_dir" .
        chmod 600 "$bundle_path"
        print_info "Reverse-dial VPS bundle created: $bundle_path"
    fi
    rm -rf "$bundle_dir"
}

write_server_config() {
    local config_path="$CONFIG_DIR/config.yaml"

    if [ -f "$config_path" ] && [ "$MIGRATE_CONFIG" -ne 1 ] && [ "$RESET_CONFIG" -ne 1 ]; then
        if update_existing_performance_profile "$config_path"; then
            return
        fi
        print_info "Existing config preserved: $config_path"
        return
    fi

    if [ -f "$config_path" ] && { [ "$MIGRATE_CONFIG" -eq 1 ] || [ "$RESET_CONFIG" -eq 1 ]; }; then
        if ! confirm "Overwrite $config_path with optimized defaults? Backup already exists."; then
            print_info "Existing config preserved"
            return
        fi
    fi

    prompt_if_empty LISTEN_HOST "Enter server listen host [0.0.0.0]:"
    LISTEN_HOST="${LISTEN_HOST:-0.0.0.0}"
    prompt_if_empty HOSTNAME_VALUE "Enter server domain/hostname for SMTP greeting and certificate:"
    if [ -z "$EHLO_NAME" ]; then
        EHLO_NAME="$HOSTNAME_VALUE"
    fi

    print_step "Writing server config"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would write $config_path"
        return
    fi

    cat > "$config_path" << EOF
# SMTP Tunnel Proxy Configuration
# Generated by install.sh for server role

server:
  host: "$LISTEN_HOST"
  port: $LISTEN_PORT
  hostname: "$HOSTNAME_VALUE"
  cert_file: "$CERT_DIR/server.crt"
  key_file: "$CERT_DIR/server.key"
  users_file: "$CONFIG_DIR/users.yaml"
  log_users: true

client:
  server_host: "$HOSTNAME_VALUE"
  server_port: $LISTEN_PORT
  socks_port: 1080
  socks_host: "127.0.0.1"
  ca_cert: "ca.crt"

tunnel:
  keepalive_interval: 45
  keepalive_timeout: 120
  reconnect_initial_delay: 2
  reconnect_max_delay: 60
  reconnect_jitter: 0.35
  connect_timeout: 10

performance:
  profile: $PERFORMANCE_PROFILE

metrics:
  enabled: true
  log_interval: 30
  verbose: false

transport:
  read_chunk_size: 65535
  drain_bytes: 262144
  drain_interval_ms: 10
  socket_send_buffer: 0
  socket_recv_buffer: 0
  tcp_nodelay: true
  tcp_keepalive: true
  pending_buffer_limit: 1048576

logging:
  log_destinations: false
  log_session_events: true
  log_metrics: true

smtp:
  ehlo_name: "$EHLO_NAME"
EOF
    chmod 600 "$config_path"
}

import_client_package() {
    local package_path="$1"
    local config_path="$CONFIG_DIR/config.yaml"
    local tmpdir=""
    local package_config=""
    local package_ca=""

    if [ ! -f "$package_path" ]; then
        print_error "Client package not found: $package_path"
        exit 1
    fi
    if ! tar -tzf "$package_path" >/dev/null 2>&1; then
        print_error "Client package is not a readable tar.gz archive: $package_path"
        exit 1
    fi
    while IFS= read -r member; do
        case "$member" in
            /*|../*|*/../*|*/..)
                print_error "Unsafe path in client package: $member"
                exit 1
                ;;
        esac
    done < <(tar -tzf "$package_path")

    print_step "Importing client package"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would extract $package_path and install config/CA"
        return
    fi

    tmpdir="$(mktemp -d /tmp/smtp-tunnel-client-package.XXXXXX)"
    tar -xzf "$package_path" -C "$tmpdir"

    package_config="$(find "$tmpdir" -type f -name config.yaml | head -n 1)"
    package_ca="$(find "$tmpdir" -type f -name ca.crt | head -n 1)"

    if [ -z "$package_config" ]; then
        rm -rf "$tmpdir"
        print_error "Client package does not contain config.yaml"
        exit 1
    fi

    cp -a "$package_config" "$config_path"
    chmod 600 "$config_path"

    if [ -n "$package_ca" ]; then
        mkdir -p "$CERT_DIR"
        cp -a "$package_ca" "$CERT_DIR/ca.crt"
        chmod 644 "$CERT_DIR/ca.crt"
        "$PYTHON_BIN" - "$config_path" "$CERT_DIR/ca.crt" << 'PY'
import sys
import yaml
config_path, ca_path = sys.argv[1:3]
with open(config_path, 'r') as f:
    data = yaml.safe_load(f) or {}
data.setdefault('client', {})['ca_cert'] = ca_path
with open(config_path, 'w') as f:
    yaml.safe_dump(data, f, sort_keys=False)
PY
    else
        print_warn "Client package does not contain ca.crt"
    fi

    rm -rf "$tmpdir"
    print_info "Client config installed from package"
}

write_client_config() {
    local config_path="$CONFIG_DIR/config.yaml"
    local ca_path="$CERT_DIR/ca.crt"
    local ca_will_be_installed=0

    if [ -f "$config_path" ] && [ "$MIGRATE_CONFIG" -ne 1 ] && [ "$RESET_CONFIG" -ne 1 ]; then
        if update_existing_performance_profile "$config_path"; then
            return
        fi
        print_info "Existing config preserved: $config_path"
        return
    fi

    if [ -f "$config_path" ] && { [ "$MIGRATE_CONFIG" -eq 1 ] || [ "$RESET_CONFIG" -eq 1 ]; }; then
        if ! confirm "Overwrite $config_path with optimized client defaults? Backup already exists."; then
            print_info "Existing config preserved"
            return
        fi
    fi

    if [ -n "$FROM_PACKAGE" ]; then
        import_client_package "$FROM_PACKAGE"
        update_existing_performance_profile "$config_path" || true
        return
    fi

    prompt_if_empty SERVER_HOST "Enter tunnel server hostname:"
    prompt_if_empty USERNAME_VALUE "Enter tunnel username:"
    prompt_secret_if_empty SECRET_VALUE "Enter tunnel secret (input hidden):"
    if [ -z "$EHLO_NAME" ]; then
        EHLO_NAME="$(default_ehlo_name)"
    fi

    if [ -n "$CA_CERT_SOURCE" ]; then
        if [ ! -f "$CA_CERT_SOURCE" ]; then
            print_error "CA certificate not found: $CA_CERT_SOURCE"
            exit 1
        fi
        if [ "$DRY_RUN" -eq 1 ]; then
            print_info "Dry-run: would copy $CA_CERT_SOURCE -> $ca_path"
        else
            cp -a "$CA_CERT_SOURCE" "$ca_path"
            chmod 644 "$ca_path"
        fi
        ca_will_be_installed=1
    else
        if [ "$NON_INTERACTIVE" -ne 1 ] && [ "$ALLOW_INSECURE_NO_CA" -ne 1 ]; then
            print_ask "Enter CA certificate path, or leave empty to paste PEM / skip:"
            read -r -p "    " ca_prompt < /dev/tty
            if [ -n "$ca_prompt" ]; then
                if [ ! -f "$ca_prompt" ]; then
                    print_error "CA certificate not found: $ca_prompt"
                    exit 1
                fi
                if [ "$DRY_RUN" -eq 1 ]; then
                    print_info "Dry-run: would copy $ca_prompt -> $ca_path"
                else
                    cp -a "$ca_prompt" "$ca_path"
                    chmod 644 "$ca_path"
                fi
                ca_will_be_installed=1
                CA_CERT_SOURCE="$ca_prompt"
            else
                if confirm "Paste CA certificate PEM now?"; then
                    if [ "$DRY_RUN" -eq 1 ]; then
                        print_info "Dry-run: would read pasted CA certificate"
                    else
                        echo "Paste PEM, ending with a line containing only END:"
                        : > "$ca_path"
                        while IFS= read -r line < /dev/tty; do
                            [ "$line" = "END" ] && break
                            printf '%s\n' "$line" >> "$ca_path"
                        done
                        chmod 644 "$ca_path"
                    fi
                    ca_will_be_installed=1
                    CA_CERT_SOURCE="$ca_path"
                fi
            fi
        fi
    fi

    if [ "$ca_will_be_installed" -eq 1 ] || [ -f "$ca_path" ]; then
        CA_CERT_SOURCE="$ca_path"
    elif [ "$ALLOW_INSECURE_NO_CA" -ne 1 ]; then
        print_warn "No CA certificate provided. TLS verification is strongly recommended."
        if ! confirm "Continue with TLS certificate verification disabled?"; then
            print_error "Client install cancelled because ca_cert is missing"
            exit 1
        fi
    fi

    print_step "Writing client config"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would write $config_path"
        return
    fi

    cat > "$config_path" << EOF
# SMTP Tunnel Proxy Configuration
# Generated by install.sh for client role

client:
  server_host: "$SERVER_HOST"
  server_port: $SERVER_PORT
  socks_port: $SOCKS_PORT
  socks_host: "$SOCKS_HOST"
  username: "$USERNAME_VALUE"
  secret: "$SECRET_VALUE"
EOF

    if [ "$ca_will_be_installed" -eq 1 ] || [ -f "$ca_path" ]; then
        cat >> "$config_path" << EOF
  ca_cert: "$ca_path"
EOF
    else
        cat >> "$config_path" << EOF
  # ca_cert: "$ca_path"
EOF
    fi

    cat >> "$config_path" << EOF

tunnel:
  keepalive_interval: 45
  keepalive_timeout: 120
  reconnect_initial_delay: 2
  reconnect_max_delay: 60
  reconnect_jitter: 0.35
  connect_timeout: 10

performance:
  profile: $PERFORMANCE_PROFILE

metrics:
  enabled: true
  log_interval: 30
  verbose: false

transport:
  read_chunk_size: 65535
  drain_bytes: 262144
  drain_interval_ms: 10
  socket_send_buffer: 0
  socket_recv_buffer: 0
  tcp_nodelay: true
  tcp_keepalive: true
  pending_buffer_limit: 1048576

logging:
  log_destinations: false
  log_session_events: true
  log_metrics: true

smtp:
  ehlo_name: "$EHLO_NAME"
EOF
    chmod 600 "$config_path"
}

ensure_users_file() {
    local users_path="$CONFIG_DIR/users.yaml"
    if [ -f "$users_path" ]; then
        return
    fi
    print_step "Creating users file"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would create $users_path"
        return
    fi
    cat > "$users_path" << 'EOF'
# SMTP Tunnel Users
# Managed by smtp-tunnel-adduser

users: {}
EOF
    chmod 600 "$users_path"
}

generate_server_certs() {
    if [ "$GENERATE_CERTS" -ne 1 ]; then
        print_warn "Certificate generation disabled. Ensure config points to valid cert/key files before starting."
        return
    fi

    if [ "$NON_INTERACTIVE" -ne 1 ] && [ ! -f "$CERT_DIR/server.crt" ]; then
        if ! confirm "Generate private CA and server certificate now?"; then
            print_warn "Skipping certificate generation"
            return
        fi
    fi

    if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ] && [ -f "$CERT_DIR/ca.crt" ]; then
        print_info "Existing certificates preserved"
        if [ "$DRY_RUN" -ne 1 ]; then
            ln -sf "$CERT_DIR/ca.crt" "$INSTALL_DIR/ca.crt"
        fi
        return
    fi

    prompt_if_empty HOSTNAME_VALUE "Enter server domain/hostname for certificates:"
    print_step "Generating private CA and server certificate"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would generate certificates in $CONFIG_DIR"
        return
    fi
    (cd "$INSTALL_DIR" && "$PYTHON_BIN" generate_certs.py --hostname "$HOSTNAME_VALUE" --output-dir "$CERT_DIR")
    ln -sf "$CERT_DIR/ca.crt" "$INSTALL_DIR/ca.crt"
}

create_first_user_if_requested() {
    if [ "$ROLE" != "server" ]; then
        return
    fi
    if [ -n "$USERNAME_VALUE" ]; then
        print_step "Creating configured user '$USERNAME_VALUE'"
        if [ "$DRY_RUN" -eq 1 ]; then
            print_info "Dry-run: would run smtp-tunnel-adduser $USERNAME_VALUE"
            return
        fi
        local package_args=("--output-dir" "/root")
        if [ "$EXPORT_CLIENT_PACKAGE" -ne 1 ] && [ "$NON_INTERACTIVE" -eq 1 ]; then
            package_args=("--no-package")
        fi
        if [ -n "$SECRET_VALUE" ]; then
            printf '%s\n' "$SECRET_VALUE" | "$PYTHON_BIN" "$INSTALL_DIR/smtp-tunnel-adduser" "$USERNAME_VALUE" --secret-stdin "${package_args[@]}" || true
        else
            "$PYTHON_BIN" "$INSTALL_DIR/smtp-tunnel-adduser" "$USERNAME_VALUE" "${package_args[@]}" || true
        fi
        return
    fi

    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        print_warn "No initial user requested. Add one later with smtp-tunnel-adduser and restart the service."
        return
    fi

    if confirm "Create the first user now?"; then
        print_ask "Enter username:"
        read -r -p "    " first_user < /dev/tty
        if [ -n "$first_user" ]; then
            local first_secret=""
            local package_args=("--no-package")
            print_ask "Enter user secret (input hidden, leave empty to auto-generate):"
            local stty_state
            stty_state="$(stty -g < /dev/tty)"
            stty -echo < /dev/tty
            read_from_tty first_secret "    "
            stty "$stty_state" < /dev/tty
            echo ""
            if confirm "Export a client bundle to /root for this user?"; then
                package_args=("--output-dir" "/root")
            fi
            if [ "$DRY_RUN" -eq 1 ]; then
                print_info "Dry-run: would create user $first_user"
            elif [ -n "$first_secret" ]; then
                printf '%s\n' "$first_secret" | "$PYTHON_BIN" "$INSTALL_DIR/smtp-tunnel-adduser" "$first_user" --secret-stdin "${package_args[@]}" || true
            else
                "$PYTHON_BIN" "$INSTALL_DIR/smtp-tunnel-adduser" "$first_user" "${package_args[@]}" || true
            fi
        fi
    else
        print_warn "No users configured yet. Add one later with smtp-tunnel-adduser and restart the service."
    fi
}

write_systemd_service() {
    local service_path="$SERVICE_DIR/${SERVICE_NAME}.service"
    local exec_line=""
    local description=""

    if [ "$MODE" = "reverse-dial" ]; then
        description="SMTP Tunnel Reverse Dialer"
        exec_line="$PYTHON_BIN $INSTALL_DIR/server.py -c $CONFIG_DIR/config.yaml"
    elif [ "$MODE" = "reverse-listen" ]; then
        description="SMTP Tunnel Reverse Access Node"
        exec_line="$PYTHON_BIN $INSTALL_DIR/client.py -c $CONFIG_DIR/config.yaml"
    elif [ "$ROLE" = "server" ]; then
        description="SMTP Tunnel Server"
        exec_line="$PYTHON_BIN $INSTALL_DIR/server.py -c $CONFIG_DIR/config.yaml"
    else
        description="SMTP Tunnel Client"
        exec_line="$PYTHON_BIN $INSTALL_DIR/client.py -c $CONFIG_DIR/config.yaml"
    fi

    print_step "Installing systemd service: ${SERVICE_NAME}.service"
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would write $service_path"
        return
    fi

    cat > "$service_path" << EOF
[Unit]
Description=$description
Documentation=https://github.com/x011/smtp-tunnel-proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$exec_line
Restart=always
RestartSec=5
UMask=0077
StandardOutput=journal
StandardError=journal

# Conservative hardening that should not break normal networking or /etc reads.
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

create_uninstall_script() {
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would create $INSTALL_DIR/uninstall.sh"
        return
    fi
    cat > "$INSTALL_DIR/uninstall.sh" << EOF
#!/bin/bash
set -e
SERVICE_NAME="$SERVICE_NAME"
INSTALL_DIR="$INSTALL_DIR"

echo "Stopping service..."
systemctl stop "\$SERVICE_NAME" 2>/dev/null || true
systemctl disable "\$SERVICE_NAME" 2>/dev/null || true

echo "Removing service and application files..."
rm -f "$SERVICE_DIR/\${SERVICE_NAME}.service"
rm -f "$BIN_DIR/smtp-tunnel-adduser" "$BIN_DIR/smtp-tunnel-deluser" "$BIN_DIR/smtp-tunnel-listusers" "$BIN_DIR/smtp-tunnel-update"
rm -rf "\$INSTALL_DIR"
systemctl daemon-reload

echo "Configuration in $CONFIG_DIR was not removed."
EOF
    chmod +x "$INSTALL_DIR/uninstall.sh"
}

run_config_check() {
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would run config check"
        return
    fi
    print_step "Running config validation"
    if [ "$ROLE" = "server" ]; then
        "$PYTHON_BIN" "$INSTALL_DIR/server.py" -c "$CONFIG_DIR/config.yaml" --check || exit 1
    else
        "$PYTHON_BIN" "$INSTALL_DIR/client.py" -c "$CONFIG_DIR/config.yaml" --check || exit 1
    fi
}

role_preflight_after_config() {
    if [ "$DRY_RUN" -eq 1 ]; then
        return
    fi

    warn_if_process_running

    if [ "$MODE" = "reverse-listen" ]; then
        if ! port_available "0.0.0.0" "$LISTEN_PORT"; then
            print_warn "Reverse listen port $LISTEN_PORT appears to be in use"
        fi
        if [ -z "$REVERSE_ALLOWED_DIALER_IPS" ]; then
            print_warn "No reverse allowed dialer IP configured; restrict the listener with firewall rules"
        fi
    elif [ "$MODE" = "reverse-dial" ]; then
        :
    elif [ "$ROLE" = "server" ]; then
        if ! port_available "0.0.0.0" "$LISTEN_PORT"; then
            print_warn "Server listen port $LISTEN_PORT appears to be in use. This is expected during some upgrades if the current service is still running."
        fi
        for file in "$CERT_DIR/server.crt" "$CERT_DIR/server.key" "$CONFIG_DIR/users.yaml"; do
            [ -e "$file" ] || print_warn "Expected file missing: $file"
        done
    else
        if ! port_available "$SOCKS_HOST" "$SOCKS_PORT"; then
            print_warn "Client SOCKS port $SOCKS_HOST:$SOCKS_PORT appears to be in use"
        fi
        if [ ! -f "$CERT_DIR/ca.crt" ]; then
            print_warn "No CA certificate installed at $CERT_DIR/ca.crt. Client will only verify TLS if config points elsewhere."
        fi
    fi
}

open_firewall_server() {
    if [ "$DRY_RUN" -eq 1 ]; then
        return
    fi
    if [ "$ROLE" != "server" ] && [ "$MODE" != "reverse-listen" ]; then
        return
    fi
    print_step "Checking firewall helper"
    if command -v ufw >/dev/null 2>&1; then
        if [ "$MODE" = "reverse-listen" ] && [ -n "$REVERSE_ALLOWED_DIALER_IPS" ]; then
            for ip in $REVERSE_ALLOWED_DIALER_IPS; do
                ufw allow from "$ip" to any port "$LISTEN_PORT" proto tcp >/dev/null 2>&1 || print_warn "Could not configure ufw for $ip"
            done
        else
            ufw allow "$LISTEN_PORT/tcp" >/dev/null 2>&1 || print_warn "Could not configure ufw"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="$LISTEN_PORT/tcp" >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 || print_warn "Could not configure firewalld"
    else
        print_warn "No supported firewall helper detected. Make sure TCP port $LISTEN_PORT is open."
    fi
}

start_service() {
    if [ "$SKIP_START" -eq 1 ]; then
        print_info "Skipping service start by request"
        return
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Dry-run: would enable and restart $SERVICE_NAME"
        return
    fi
    print_step "Enabling and restarting service"
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    systemctl restart "$SERVICE_NAME"
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_info "Service is active: $SERVICE_NAME"
    else
        print_warn "Service is not active. Check: systemctl status $SERVICE_NAME"
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Installation Complete${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Role: $ROLE"
    echo "Mode: $MODE"
    echo "Service: $SERVICE_NAME"
    echo "Install dir: $INSTALL_DIR"
    echo "Config dir: $CONFIG_DIR"
    if [ -n "$BACKUP_DIR" ]; then
        echo "Backup: $BACKUP_DIR"
        echo "Rollback: sudo $BACKUP_DIR/rollback.sh"
    fi
    echo ""
    echo "Useful commands:"
    echo "  sudo systemctl daemon-reload"
    echo "  sudo systemctl enable $SERVICE_NAME"
    echo "  sudo systemctl restart $SERVICE_NAME"
    echo "  sudo journalctl -u $SERVICE_NAME -f"
    if [ "$MODE" = "reverse-listen" ]; then
        echo "  curl -x socks5h://$SOCKS_HOST:$SOCKS_PORT https://ifconfig.me"
        echo "  sudo journalctl -u $SERVICE_NAME -f"
        if [ -n "$REVERSE_ALLOWED_DIALER_IPS" ]; then
            echo "  sudo ufw allow from $REVERSE_ALLOWED_DIALER_IPS to any port $LISTEN_PORT proto tcp"
        fi
        if [ "$REVERSE_CERT_MODE" = "letsencrypt-http" ] || [ "$REVERSE_CERT_MODE" = "letsencrypt-dns" ]; then
            echo "  sudo certbot renew --dry-run"
        fi
    elif [ "$MODE" = "reverse-dial" ]; then
        echo "  sudo journalctl -u $SERVICE_NAME -f"
    elif [ "$ROLE" = "server" ]; then
        echo "  sudo smtp-tunnel-adduser alice"
        echo "  sudo systemctl restart $SERVICE_NAME"
    else
        echo "  curl -x socks5h://$SOCKS_HOST:$SOCKS_PORT https://ifconfig.me"
    fi
    echo ""
    echo "No tunnel can guarantee avoidance of DPI/firewall detection. Test on staging before production."
}

main() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  SMTP Tunnel Proxy Installer${NC}"
    echo -e "${GREEN}  Version 1.4.0${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""

    parse_args "$@"
    check_root
    detect_script_dir
    detect_os
    prompt_install_options
    preflight_role_values
    check_systemd_available
    detect_existing_install

    if [ "$EXISTING_INSTALL" -eq 1 ]; then
        print_warn "Existing installation detected"
    fi

    install_system_dependencies
    if [ "$DRY_RUN" -ne 1 ]; then
        check_python_version
    fi
    backup_existing_install
    create_directories
    install_application_files
    install_python_packages

    if [ "$MODE" = "reverse-listen" ]; then
        write_reverse_listen_config
        export_reverse_dial_bundle
    elif [ "$MODE" = "reverse-dial" ]; then
        write_reverse_dial_config
    elif [ "$ROLE" = "server" ]; then
        write_server_config
        ensure_users_file
        generate_server_certs
        create_first_user_if_requested
    else
        write_client_config
    fi

    write_systemd_service
    create_uninstall_script
    role_preflight_after_config
    run_config_check
    open_firewall_server
    start_service
    print_summary
}

main "$@"
