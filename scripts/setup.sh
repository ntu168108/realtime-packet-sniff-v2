#!/bin/bash
#
# SNIFF Auto-Setup Script
# Chạy file này để tự động cài đặt môi trường + dependencies
# Usage: bash setup.sh [interface]
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              SNIFF Auto-Setup (Linux)                        ║${NC}"
echo -e "${GREEN}║         Công cụ bắt gói tin mạng cho Linux                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ===== 1. Check root =====
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}✗ Cần quyền root để setup${NC}"
    echo -e "  Chạy: ${YELLOW}sudo bash setup.sh${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Đang chạy với quyền root${NC}"

# ===== 2. Detect OS =====
echo ""
echo -e "${BLUE}[1/6] Phát hiện hệ điều hành...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    echo -e "  HĐH: ${GREEN}$PRETTY_NAME${NC}"
else
    OS="unknown"
    echo -e "  ${YELLOW}Không nhận diện được OS, sẽ thử cách generic${NC}"
fi

# ===== 3. Update package list =====
echo ""
echo -e "${BLUE}[2/6] Cập nhật package list...${NC}"
case $OS in
    ubuntu|debian)
        apt-get update -qq
        ;;
    centos|rhel|fedora|rocky|almalinux)
        yum check-update -q || true
        ;;
    arch|manjaro)
        pacman -Sy --noconfirm
        ;;
esac
echo -e "  ${GREEN}✓ Done${NC}"

# ===== 4. Install system deps =====
echo ""
echo -e "${BLUE}[3/6] Cài system dependencies...${NC}"
case $OS in
    ubuntu|debian)
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            python3 python3-pip python3-dev \
            tcpdump iproute2 net-tools curl git \
            libpcap-dev 2>&1 | grep -v "^Selecting" || true
        ;;
    centos|rhel|fedora|rocky|almalinux)
        yum install -y -q python3 python3-pip tcpdump iproute net-tools curl git libpcap-devel
        ;;
    arch|manjaro)
        pacman -S --noconfirm python python-pip tcpdump iproute2 net-tools curl git libpcap
        ;;
esac
echo -e "  ${GREEN}✓ System deps OK${NC}"

# ===== 5. Check Python version =====
echo ""
echo -e "${BLUE}[4/6] Kiểm tra Python...${NC}"
PYTHON_CMD=""
for py in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v $py &>/dev/null; then
        PY_VERSION=$($py --version 2>&1 | awk '{print $2}')
        PY_MAJOR=$(echo $PY_VERSION | cut -d. -f1)
        PY_MINOR=$(echo $PY_VERSION | cut -d. -f2)
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 8 ]; then
            PYTHON_CMD=$py
            echo -e "  Python: ${GREEN}$py ($PY_VERSION)${NC}"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo -e "  ${YELLOW}Python 3.8+ chưa có, đang cài...${NC}"
    case $OS in
        ubuntu|debian)
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-pip python3-dev
            ;;
        centos|rhel|fedora)
            yum install -y -q python3 python3-pip
            ;;
        arch)
            pacman -S --noconfirm python python-pip
            ;;
    esac
    PYTHON_CMD=python3
fi
echo -e "  ${GREEN}✓ Python OK${NC}"

# ===== 6. Install Python deps =====
echo ""
echo -e "${BLUE}[5/6] Cài Python dependencies (scapy)...${NC}"
PIP_ARGS=""
if $PYTHON_CMD -m pip install --help 2>&1 | grep -q "break-system-packages"; then
    if [ -f /usr/lib/python3*/EXTERNALLY-MANAGED ] 2>/dev/null; then
        PIP_ARGS="--break-system-packages"
        echo -e "  ${YELLOW}Phát hiện externally-managed Python, dùng --break-system-packages${NC}"
    fi
fi

$PYTHON_CMD -m pip install --quiet $PIP_ARGS --upgrade pip
$PYTHON_CMD -m pip install --quiet $PIP_ARGS "scapy>=2.5.0"
echo -e "  ${GREEN}✓ Scapy installed${NC}"

# ===== 7. Setup SNIFF =====
echo ""
echo -e "${BLUE}[6/6] Cài đặt SNIFF...${NC}"
$PYTHON_CMD -m pip install --quiet $PIP_ARGS -e "$SCRIPT_DIR" 2>&1 | head -5
echo -e "  ${GREEN}✓ SNIFF installed (editable mode)${NC}"

# Verify
if command -v sniff &>/dev/null; then
    echo -e "  ${GREEN}✓ sniff command available: $(which sniff)${NC}"
else
    # Fallback: tạo wrapper
    cat > /usr/local/bin/sniff << EOF
#!/bin/bash
exec $PYTHON_CMD $SCRIPT_DIR/sniff.py "\$@"
EOF
    chmod +x /usr/local/bin/sniff
    echo -e "  ${GREEN}✓ Created /usr/local/bin/sniff wrapper${NC}"
fi

# ===== 8. Test =====
echo ""
echo -e "${BLUE}Kiểm tra cài đặt...${NC}"
if sniff --list-protocols > /dev/null 2>&1 || $PYTHON_CMD sniff.py --list-protocols > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓ sniff --list-protocols OK${NC}"
else
    echo -e "  ${YELLOW}⚠ sniff --list-protocols failed, kiểm tra thủ công${NC}"
fi

# ===== Summary =====
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              SETUP HOÀN TẤT!                                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Sử dụng:"
echo -e "  ${YELLOW}sudo sniff${NC}                              # Menu tương tác"
echo -e "  ${YELLOW}sudo sniff -i eth0${NC}                      # Capture nhanh"
echo -e "  ${YELLOW}sudo sniff -i eth0 --live | jq .${NC}       # Live JSON stream"
echo -e "  ${YELLOW}sudo sniff -i eth0 -d -r 30${NC}            # Daemon mode, giữ 30 ngày"
echo -e "  ${YELLOW}sniff --list-protocols${NC}                 # Xem protocols hỗ trợ"
echo -e "  ${YELLOW}sniff --help${NC}                           # Full help"
echo ""
echo -e "Tài liệu:"
echo -e "  ${YELLOW}cat README.md${NC}                          # Hướng dẫn đầy đủ"
echo ""
echo -e "${GREEN}Để chạy systemd service 24/7:${NC}"
echo -e "  ${YELLOW}sudo cp scripts/sniff.service /etc/systemd/system/${NC}"
echo -e "  ${YELLOW}sudo sed -i 's|INTERFACE|eth0|g' /etc/systemd/system/sniff.service${NC}"
echo -e "  ${YELLOW}sudo systemctl daemon-reload && sudo systemctl enable --now sniff${NC}"
echo ""
