#!/bin/bash
#
# SNIFF Auto-Installer
# One-line install: curl -sSL https://raw.githubusercontent.com/ntu168108/realtime-packet-sniff/main/install.sh | sudo bash
#
# This script will:
# - Detect Python 3.8+ (with proper fallback to python3.11/3.10/3.9/3.8/3.x)
# - Check libpcap presence (warn if missing, scapy works without but is slow)
# - Check available disk space (warn if < 200MB free)
# - Install pip3 if needed
# - Install scapy
# - Install SNIFF (idempotent: skip if already installed and up to date)
# - Optionally setup systemd service (skippable with --skip-systemd)
#

set -e

# ----------------------------- Constants & flags -----------------------------

VERSION="0.2.0"
GITHUB_REPO="ntu168108/realtime-packet-sniff"
MIN_PY_MAJOR=3
MIN_PY_MINOR=8
MIN_DISK_MB=200
MIN_DISK_BYTES=$((MIN_DISK_MB * 1024 * 1024))

INSTALL_MARKER="/var/lib/sniff/.installed"
SKIP_SYSTEMD=0
VERBOSE=0
FORCE_REINSTALL=0
NO_COLOR=0
SKIP_LIBPCAP_CHECK=0

# ----------------------------- Argument parsing -----------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-systemd)   SKIP_SYSTEMD=1; shift ;;
        --force)          FORCE_REINSTALL=1; shift ;;
        --verbose|-v)     VERBOSE=1; shift ;;
        --no-color)       NO_COLOR=1; shift ;;
        --skip-libpcap-check) SKIP_LIBPCAP_CHECK=1; shift ;;
        --help|-h)
            cat <<EOF
SNIFF Auto-Installer v${VERSION}

Usage: install.sh [OPTIONS]

Options:
  --skip-systemd         Do not prompt for systemd service setup
  --force                Reinstall even if already installed
  --verbose, -v          Verbose output
  --no-color             Disable colored output
  --skip-libpcap-check   Skip libpcap presence check
  --help, -h             Show this help

Environment:
  SNIFF_NO_COLOR=1       Same as --no-color
  SNIFF_SKIP_SYSTEMD=1   Same as --skip-systemd
EOF
            exit 0
            ;;
        *) echo "Unknown option: $1 (use --help)"; exit 1 ;;
    esac
done

[[ -n "$SNIFF_NO_COLOR" ]] && NO_COLOR=1
[[ -n "$SNIFF_SKIP_SYSTEMD" ]] && SKIP_SYSTEMD=1

# ----------------------------- Colors / tput detection -----------------------------

setup_colors() {
    if [[ $NO_COLOR -eq 1 ]] || ! command -v tput >/dev/null 2>&1; then
        RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
        return
    fi
    if ! tput colors >/dev/null 2>&1; then
        RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
        return
    fi
    local ncolors
    ncolors=$(tput colors 2>/dev/null || echo 0)
    if [[ $ncolors -lt 8 ]]; then
        RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
        return
    fi
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
}

# ----------------------------- Logging helpers -----------------------------

log_info()    { echo -e "${BLUE}[*]${NC} $*"; }
log_ok()      { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $*" >&2; }
log_error()   { echo -e "${RED}[-]${NC} $*" >&2; }
log_step()    { echo -e "\n${BOLD}==> $*${NC}"; }
log_verbose() { [[ $VERBOSE -eq 1 ]] && echo -e "    $*"; }

die() {
    log_error "$@"
    exit 1
}

# ----------------------------- Pre-flight checks -----------------------------

setup_colors

# Banner
echo -e "${GREEN}"
echo "╔═══════════════════════════════════════╗"
echo "║   SNIFF Auto-Installer v${VERSION}        ║"
echo "║   Network Packet Capture Tool         ║"
echo "╚═══════════════════════════════════════╝"
echo -e "${NC}"

# Root check (with helpful message)
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    log_info  "Usage: curl -sSL https://.../install.sh | sudo bash"
    exit 1
fi

# OS detection
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
    PRETTY=$PRETTY_NAME
else
    log_warn "Cannot detect OS from /etc/os-release; assuming unknown"
    OS="unknown"
    VER="0"
    PRETTY="Unknown"
fi

# Architecture
ARCH=$(uname -m 2>/dev/null || echo "unknown")
log_info "Detected: $PRETTY ($ARCH)"

# Disk check (require at least MIN_DISK_MB free on /)
if command -v df >/dev/null 2>&1; then
    FREE_KB=$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}')
    if [[ -n "$FREE_KB" ]] && [[ $FREE_KB -lt $((MIN_DISK_MB * 1024)) ]]; then
        log_warn "Low disk space: $((FREE_KB / 1024)) MB free (recommended >= ${MIN_DISK_MB} MB)"
        log_warn "Continuing anyway; install may fail if it runs out of space"
    else
        log_verbose "Disk space OK: $((FREE_KB / 1024)) MB free"
    fi
fi

# ----------------------------- Idempotency check -----------------------------

is_installed() {
    if command -v sniff >/dev/null 2>&1; then
        if [[ $FORCE_REINSTALL -eq 0 ]]; then
            local installed_ver
            installed_ver=$(sniff --version 2>&1 | head -1 | awk '{print $2}' || echo "0")
            log_ok "SNIFF is already installed (version: $installed_ver)"
            log_info  "Use --force to reinstall, or run: sudo sniff --help"
            return 0
        fi
    fi
    return 1
}

if is_installed; then
    exit 0
fi

# ----------------------------- [1/5] Update package list -----------------------------

log_step "[1/5] Updating package list"
case $OS in
    ubuntu|debian)
        apt-get update -qq || log_warn "apt-get update failed; continuing"
        ;;
    centos|rhel|fedora|rocky|almalinux)
        yum check-update -q || true
        ;;
    arch|manjaro)
        pacman -Sy --noconfirm || log_warn "pacman -Sy failed; continuing"
        ;;
    alpine)
        apk update || log_warn "apk update failed; continuing"
        ;;
    *)
        log_warn "Unsupported OS '$OS'; trying generic install"
        ;;
esac
log_ok "Package list updated"

# ----------------------------- [2/5] Detect or install Python -----------------------------

log_step "[2/5] Detecting Python 3.${MIN_PY_MINOR}+"
PYTHON_CMD=""
PY_VERSION=""

# Try candidates in order (newest first)
PY_CANDIDATES=(
    "python3.13" "python3.12" "python3.11" "python3.10"
    "python3.9"   "python3.8"   "python3"
)

for py in "${PY_CANDIDATES[@]}"; do
    if command -v "$py" >/dev/null 2>&1; then
        ver=$("$py" --version 2>&1 | awk '{print $2}')
        py_major=$(echo "$ver" | cut -d. -f1)
        py_minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$py_major" -ge $MIN_PY_MAJOR ]] && [[ "$py_minor" -ge $MIN_PY_MINOR ]]; then
            PYTHON_CMD="$py"
            PY_VERSION="$ver"
            break
        else
            log_verbose "  $py: $ver (too old, need >= $MIN_PY_MAJOR.$MIN_PY_MINOR)"
        fi
    fi
done

if [[ -z "$PYTHON_CMD" ]]; then
    log_warn "Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ not found; attempting install"
    case $OS in
        ubuntu|debian)
            apt-get install -y python3 python3-pip python3-venv 2>&1 | grep -v "^Reading\|^Building\|^Get:" || true
            PYTHON_CMD="python3"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            yum install -y python3 python3-pip 2>&1 | tail -20 || true
            PYTHON_CMD="python3"
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm python python-pip 2>&1 | tail -5 || true
            PYTHON_CMD="python3"
            ;;
        alpine)
            apk add python3 py3-pip 2>&1 | tail -5 || true
            PYTHON_CMD="python3"
            ;;
        *)
            die "Cannot install Python automatically on '$OS'. Please install Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ manually."
            ;;
    esac

    # Re-check after install
    for py in "${PY_CANDIDATES[@]}"; do
        if command -v "$py" >/dev/null 2>&1; then
            ver=$("$py" --version 2>&1 | awk '{print $2}')
            py_major=$(echo "$ver" | cut -d. -f1)
            py_minor=$(echo "$ver" | cut -d. -f2)
            if [[ "$py_major" -ge $MIN_PY_MAJOR ]] && [[ "$py_minor" -ge $MIN_PY_MINOR ]]; then
                PYTHON_CMD="$py"
                PY_VERSION="$ver"
                break
            fi
        fi
    done

    if [[ -z "$PYTHON_CMD" ]]; then
        die "Failed to install a compatible Python (need ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+)"
    fi
fi

log_ok "Using $PYTHON_CMD (Python $PY_VERSION)"

# Verify version explicitly
if ! $PYTHON_CMD -c "import sys; sys.exit(0 if sys.version_info >= ($MIN_PY_MAJOR, $MIN_PY_MINOR) else 1)"; then
    die "Python version check failed for $PYTHON_CMD ($PY_VERSION)"
fi

# ----------------------------- [3/5] Ensure pip + libpcap -----------------------------

log_step "[3/5] Checking pip and libpcap"

# pip
if ! $PYTHON_CMD -m pip --version >/dev/null 2>&1; then
    log_warn "pip not available via $PYTHON_CMD; installing"
    case $OS in
        ubuntu|debian)
            apt-get install -y python3-pip 2>&1 | tail -3 || true
            ;;
        centos|rhel|fedora|rocky|almalinux)
            yum install -y python3-pip 2>&1 | tail -3 || true
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm python-pip 2>&1 | tail -3 || true
            ;;
        alpine)
            apk add py3-pip 2>&1 | tail -3 || true
            ;;
        *)
            log_warn "Cannot install pip automatically; trying ensurepip"
            $PYTHON_CMD -m ensurepip --upgrade 2>&1 || die "pip install failed"
            ;;
    esac
fi

# Verify pip works
if ! $PYTHON_CMD -m pip --version >/dev/null 2>&1; then
    die "pip is not functional; please install pip for $PYTHON_CMD manually"
fi
log_ok "pip OK ($($PYTHON_CMD -m pip --version 2>&1 | head -1))"

# libpcap (optional but recommended for performance)
if [[ $SKIP_LIBPCAP_CHECK -eq 0 ]]; then
    if command -v ldconfig >/dev/null 2>&1; then
        if ldconfig -p 2>/dev/null | grep -q "libpcap\.so"; then
            PCAP_VER=$(ldconfig -p 2>/dev/null | grep "libpcap\.so" | head -1 | awk '{print $NF}' | xargs -I{} basename {} 2>/dev/null)
            log_ok "libpcap found: $PCAP_VER"
        else
            log_warn "libpcap not found - Scapy will use slower Python backend"
            log_warn "  Install with: sudo apt install libpcap-dev   (Debian/Ubuntu)"
            log_warn "             or: sudo yum install libpcap-devel  (RHEL/Fedora)"
            case $OS in
                ubuntu|debian) apt-get install -y libpcap-dev 2>&1 | tail -3 || true ;;
                centos|rhel|fedora|rocky|almalinux) yum install -y libpcap-devel 2>&1 | tail -3 || true ;;
                arch|manjaro) pacman -Sy --noconfirm libpcap 2>&1 | tail -3 || true ;;
                alpine) apk add libpcap-dev 2>&1 | tail -3 || true ;;
            esac
        fi
    fi
fi

# ----------------------------- [4/5] Install Scapy + SNIFF -----------------------------

log_step "[4/5] Installing Scapy and SNIFF"

# Scapy (only if not already present)
if ! $PYTHON_CMD -c "import scapy" >/dev/null 2>&1; then
    log_info "Installing scapy via pip"
    PIP_EXTRA_ARGS=""
    if $PYTHON_CMD -m pip install --help 2>&1 | grep -q "break-system-packages"; then
        if [[ -f /usr/lib/python*/EXTERNALLY-MANAGED ]] || \
           [[ -f /usr/lib/python3.*/EXTERNALLY-MANAGED ]] || \
           compgen -G "/usr/lib/python3.*/EXTERNALLY-MANAGED" > /dev/null; then
            log_verbose "EXTERNALLY-MANAGED detected; using --break-system-packages"
            PIP_EXTRA_ARGS="--break-system-packages"
        fi
    fi
    $PYTHON_CMD -m pip install --quiet $PIP_EXTRA_ARGS "scapy>=2.5.0" \
        || die "Failed to install scapy"
    log_ok "scapy installed"
else
    log_ok "scapy already present"
fi

# SNIFF itself - try local install first (more reliable), then pip from GitHub
SNIFF_INSTALLED=0

# Strategy 1: pip install from GitHub (fast, no clone)
log_info "Installing SNIFF from GitHub ($GITHUB_REPO)"
PIP_EXTRA_ARGS=""
if $PYTHON_CMD -m pip install --help 2>&1 | grep -q "break-system-packages"; then
    if [[ -f /usr/lib/python*/EXTERNALLY-MANAGED ]] || \
       compgen -G "/usr/lib/python3.*/EXTERNALLY-MANAGED" > /dev/null; then
        PIP_EXTRA_ARGS="--break-system-packages"
    fi
fi

if $PYTHON_CMD -m pip install --quiet $PIP_EXTRA_ARGS \
        "git+https://github.com/${GITHUB_REPO}.git" 2>/dev/null; then
    SNIFF_INSTALLED=1
    log_ok "SNIFF installed from GitHub"
else
    log_warn "GitHub pip install failed; trying local clone fallback"
    # Strategy 2: clone and install locally
    TEMP_DIR=$(mktemp -d)
    if command -v git >/dev/null 2>&1; then
        if git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$TEMP_DIR/sniff" >/dev/null 2>&1; then
            (cd "$TEMP_DIR/sniff" && $PYTHON_CMD -m pip install --quiet $PIP_EXTRA_ARGS .) \
                && SNIFF_INSTALLED=1 \
                && log_ok "SNIFF installed from local clone" \
                || log_warn "Local install failed"
        else
            log_warn "git clone failed"
        fi
    else
        log_warn "git not available; cannot clone"
    fi
    rm -rf "$TEMP_DIR"
fi

if [[ $SNIFF_INSTALLED -eq 0 ]]; then
    die "Failed to install SNIFF. Check network connectivity and try again."
fi

# Write install marker
mkdir -p "$(dirname "$INSTALL_MARKER")"
echo "sniff ${VERSION} installed via install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    > "$INSTALL_MARKER" 2>/dev/null || true

# ----------------------------- [5/5] Verify + optional systemd -----------------------------

log_step "[5/5] Verifying installation"

if ! command -v sniff >/dev/null 2>&1; then
    # Some pip installs put sniff in /usr/local/bin which may not be in PATH
    for candidate in /usr/local/bin/sniff /usr/bin/sniff; do
        if [[ -x "$candidate" ]]; then
            log_warn "sniff installed at $candidate but not in PATH"
            log_info "Add to PATH: export PATH=\"$candidate:${PATH}\""
            break
        fi
    done
    die "sniff executable not found after install"
fi

log_ok "sniff installed at: $(command -v sniff)"
log_ok "Version: $(sniff --version 2>&1 | head -1)"

# Self-test (lightweight, no packet capture)
if [[ $VERBOSE -eq 1 ]]; then
    log_info "Running self-test..."
    sniff --list-interfaces 2>&1 | head -10 || log_warn "self-test failed (non-fatal)"
fi

# Success message
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Installation Successful! OK         ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
echo ""
echo "Run SNIFF with:"
echo -e "  ${BOLD}sudo sniff${NC}                      # Interactive mode"
echo -e "  ${BOLD}sudo sniff -i eth0${NC}              # Quick capture"
echo -e "  ${BOLD}sudo sniff -i eth0 --live | jq .${NC} # Live NDJSON to stdout"
echo -e "  ${BOLD}sudo sniff --help${NC}               # Show all options"
echo ""

# ----------------------------- Optional: systemd service -----------------------------

setup_systemd() {
    if [[ $SKIP_SYSTEMD -eq 1 ]]; then
        log_info "Skipping systemd setup (--skip-systemd)"
        return
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        log_info "systemctl not available; skipping service setup"
        return
    fi

    # Default to "no" in non-interactive mode
    local response
    if [[ -t 0 ]]; then
        echo -e "${BLUE}Would you like to setup SNIFF as a systemd service? [y/N]${NC}"
        read -r -n 1 response
        echo ""
    else
        log_info "Non-interactive mode; skipping systemd prompt (use --skip-systemd to silence)"
        return
    fi

    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        return
    fi

    echo ""
    log_info "Available network interfaces:"
    ip -o link show 2>/dev/null | awk -F': ' '{print "  - " $2}' || \
        log_warn "  (cannot list interfaces)"
    echo ""
    echo -e "${BLUE}Enter interface name (e.g., eth0):${NC}"
    read -r INTERFACE

    if [[ -z "$INTERFACE" ]]; then
        log_warn "No interface provided; skipping service setup"
        return
    fi

    SNIFF_BIN=$(command -v sniff)
    cat > /etc/systemd/system/sniff.service <<EOF
[Unit]
Description=SNIFF Packet Capture Service - $INTERFACE
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$SNIFF_BIN -i $INTERFACE -d --log-file /var/log/sniff/sniff.log
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Hardening
NoNewPrivileges=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF

    # Ensure log directory exists
    mkdir -p /var/log/sniff
    chmod 755 /var/log/sniff

    systemctl daemon-reload
    systemctl enable sniff

    echo ""
    echo -e "${BLUE}Start service now? [y/N]${NC}"
    read -r -n 1 START_NOW
    echo ""

    if [[ "$START_NOW" =~ ^[Yy]$ ]]; then
        systemctl start sniff
        log_ok "Service started"
        systemctl status sniff --no-pager || true
    else
        log_info "Service installed but not started"
        log_info "Start with: sudo systemctl start sniff"
    fi

    echo ""
    echo "Service commands:"
    echo "  sudo systemctl start sniff     # Start"
    echo "  sudo systemctl stop sniff      # Stop (sends SIGTERM, waits 15s, then SIGKILL)"
    echo "  sudo systemctl status sniff    # Status"
    echo "  sudo journalctl -u sniff -f    # Logs"
    echo "  sudo systemctl reload sniff    # Re-open log files (SIGHUP)"
}

setup_systemd

echo ""
echo -e "${GREEN}Thank you for using SNIFF!${NC}"
echo ""
