#!/bin/bash
#
# Remote bootstrap installer for SMTP Tunnel Proxy.
#
# Example:
#   curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- --role server --repo OWNER/REPO --ref main

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

REPO=""
REF="main"
DOWNLOAD_METHOD="auto"
KEEP_SOURCE=0
INSTALL_ARGS=()
BOOTSTRAP_WORKDIR=""

print_info() { echo -e "${GREEN}[INFO]${NC} $1" >&2; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
print_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
print_step() { echo -e "${BLUE}[STEP]${NC} $1" >&2; }

cleanup_bootstrap() {
    if [ "$KEEP_SOURCE" -eq 1 ]; then
        return 0
    fi
    if [ -n "${BOOTSTRAP_WORKDIR:-}" ] && [ -d "${BOOTSTRAP_WORKDIR:-}" ]; then
        rm -rf "$BOOTSTRAP_WORKDIR"
    fi
}


usage() {
    cat << EOF
Usage:
  sudo bash bootstrap.sh --role server|client --repo OWNER/REPO [--ref main] [install options]

Bootstrap options:
  --repo OWNER/REPO          GitHub repository to install from
  --ref REF                  Branch, tag, or commit-ish (default: main)
  --download-method auto|git|tar
  --keep-source             Keep downloaded source directory for inspection
  -h, --help

All other options are passed through to install.sh, for example:
  --role server --hostname mail.example.com
  --role client --server-host mail.example.com --from-package /root/client.tar.gz
  --role server --mode reverse-dial --performance-profile throughput
  --role server --mode reverse-dial --production-reverse-tuning
  --role server --mode reverse-dial --adaptive-connections --min-connections 8 --max-connections 20
EOF
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --repo)
                REPO="${2:-}"
                shift 2
                ;;
            --ref)
                REF="${2:-}"
                shift 2
                ;;
            --download-method)
                DOWNLOAD_METHOD="${2:-}"
                shift 2
                ;;
            --keep-source)
                KEEP_SOURCE=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                INSTALL_ARGS+=("$1")
                shift
                ;;
        esac
    done

    case "$DOWNLOAD_METHOD" in
        auto|git|tar) ;;
        *)
            print_error "--download-method must be auto, git, or tar"
            exit 1
            ;;
    esac
}

has_install_arg() {
    local wanted="$1"
    local arg
    for arg in "${INSTALL_ARGS[@]}"; do
        [ "$arg" = "$wanted" ] && return 0
    done
    return 1
}

install_arg_value() {
    local wanted="$1"
    local i
    for ((i = 0; i < ${#INSTALL_ARGS[@]}; i++)); do
        if [ "${INSTALL_ARGS[$i]}" = "$wanted" ] && [ $((i + 1)) -lt ${#INSTALL_ARGS[@]} ]; then
            echo "${INSTALL_ARGS[$((i + 1))]}"
            return 0
        fi
    done
    return 1
}

redacted_install_args() {
    local output=()
    local redact_next=0
    local arg
    for arg in "${INSTALL_ARGS[@]}"; do
        if [ "$redact_next" -eq 1 ]; then
            output+=("[redacted]")
            redact_next=0
            continue
        fi
        case "$arg" in
            --secret)
                output+=("$arg")
                redact_next=1
                ;;
            --secret=*)
                output+=("--secret=[redacted]")
                ;;
            *)
                output+=("$arg")
                ;;
        esac
    done
    echo "${output[*]:-(none)}"
}

is_non_interactive() {
    has_install_arg "--non-interactive"
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

prompt_missing_bootstrap_options() {
    if [ -z "$REPO" ]; then
        if is_non_interactive; then
            print_error "--repo OWNER/REPO is required in non-interactive mode"
            usage
            exit 1
        fi
        print_info "GitHub repository is required, for example OWNER/REPO"
        read_from_tty REPO "Repository: "
        if [ -z "$REPO" ]; then
            print_error "--repo OWNER/REPO is required"
            exit 1
        fi
    fi

    if ! has_install_arg "--role"; then
        if is_non_interactive; then
            print_error "--role server|client is required in non-interactive bootstrap mode"
            exit 1
        fi
        local role_response=""
        read_from_tty role_response "Install role [server/client] [server]: "
        role_response="${role_response:-server}"
        if [ "$role_response" != "server" ] && [ "$role_response" != "client" ]; then
            print_error "Role must be server or client"
            exit 1
        fi
        INSTALL_ARGS+=("--role" "$role_response")
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run as root (use sudo)"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        OS="unknown"
    fi
}

install_packages() {
    local packages="$*"
    if [ -z "$packages" ]; then
        return
    fi

    print_step "Installing bootstrap prerequisites: $packages"
    case "$OS" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq $packages
            ;;
        centos|rhel|rocky|alma)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y $packages
            else
                yum install -y $packages
            fi
            ;;
        fedora)
            dnf install -y $packages
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm $packages
            ;;
        *)
            print_warn "Unknown OS; please ensure these packages are installed: $packages"
            ;;
    esac
}

ensure_prerequisites() {
    local missing=""
    command -v tar >/dev/null 2>&1 || missing="$missing tar"
    command -v python3 >/dev/null 2>&1 || missing="$missing python3"
    command -v openssl >/dev/null 2>&1 || missing="$missing openssl"
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        missing="$missing curl"
    fi
    install_packages $missing
}

download_with_http() {
    local url="$1"
    local output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
    else
        wget -qO "$output" "$url"
    fi
}

download_tarball() {
    local workdir="$1"
    local archive="$workdir/source.tar.gz"
    local urls=(
        "https://github.com/$REPO/archive/refs/heads/$REF.tar.gz"
        "https://github.com/$REPO/archive/refs/tags/$REF.tar.gz"
        "https://github.com/$REPO/archive/$REF.tar.gz"
    )

    for url in "${urls[@]}"; do
        print_info "Trying $url"
        if download_with_http "$url" "$archive"; then
            mkdir -p "$workdir/source"
            tar -xzf "$archive" -C "$workdir/source" --strip-components=1
            echo "$workdir/source"
            return 0
        fi
    done

    return 1
}

download_git() {
    local workdir="$1"
    local source="$workdir/source"
    git clone --depth 1 --branch "$REF" "https://github.com/$REPO.git" "$source"
    echo "$source"
}

download_source() {
    local workdir="$1"
    local source=""

    if [ "$DOWNLOAD_METHOD" = "git" ]; then
        command -v git >/dev/null 2>&1 || install_packages git
        source="$(download_git "$workdir")"
    elif [ "$DOWNLOAD_METHOD" = "tar" ]; then
        source="$(download_tarball "$workdir")"
    else
        if command -v git >/dev/null 2>&1; then
            if source="$(download_git "$workdir" 2>/dev/null)"; then
                :
            else
                print_warn "git clone failed; falling back to GitHub tarball"
                source="$(download_tarball "$workdir")"
            fi
        else
            source="$(download_tarball "$workdir")"
        fi
    fi

    if [ ! -f "$source/install.sh" ]; then
        print_error "Downloaded source does not contain install.sh"
        exit 1
    fi

    echo "$source"
}

main() {
    parse_args "$@"
    prompt_missing_bootstrap_options
    check_root
    detect_os
    ensure_prerequisites

    BOOTSTRAP_WORKDIR="$(mktemp -d /tmp/smtp-tunnel-bootstrap.XXXXXX)"
    local workdir="$BOOTSTRAP_WORKDIR"
    if [ "$KEEP_SOURCE" -ne 1 ]; then
        trap cleanup_bootstrap EXIT
    fi

    print_step "Downloading $REPO at ref $REF"
    local source
    source="$(download_source "$workdir")"

    print_step "Running project installer"
    print_info "Source: $source"
    print_info "Forwarded install args: $(redacted_install_args)"
    bash "$source/install.sh" "${INSTALL_ARGS[@]}"

    print_info "Bootstrap complete"
    if [ "$KEEP_SOURCE" -eq 1 ]; then
        print_info "Source kept at: $source"
    fi
    local service_name
    service_name="$(install_arg_value "--service-name" || true)"
    service_name="${service_name:-smtp-tunnel}"
    print_info "Next steps: sudo systemctl status $service_name && sudo journalctl -u $service_name -f"
}

main "$@"
