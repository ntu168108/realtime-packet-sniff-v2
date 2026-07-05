#!/bin/bash
# ============================================================
# install_tools.sh - Cài đặt Argus + Zeek trên Ubuntu 24.04 (WSL)
# Chạy trong WSL terminal: bash install_tools.sh
# ============================================================

set -e  # Dừng nếu có lỗi

echo "============================================================"
echo "  CÀI ĐẶT ARGUS + ZEEK CHO PCAP FEATURE EXTRACTOR"
echo "============================================================"
echo ""

# ----------------------------------------------------------
# BƯỚC 1: Cập nhật hệ thống
# ----------------------------------------------------------
echo "[1/5] Đang cập nhật package list..."
sudo apt-get update -y

# ----------------------------------------------------------
# BƯỚC 2: Cài đặt Argus (argus-server + argus-client)
# ----------------------------------------------------------
echo ""
echo "[2/5] Đang cài đặt Argus (server + client)..."
sudo apt-get install -y argus-server argus-client

echo "  → Kiểm tra argus:"
argus -h 2>&1 | head -1 || echo "  (argus đã cài)"
echo "  → Kiểm tra ra:"
ra --version 2>&1 | head -1 || echo "  (ra đã cài)"

# ----------------------------------------------------------
# BƯỚC 3: Cài đặt dependencies cho Zeek
# ----------------------------------------------------------
echo ""
echo "[3/5] Đang cài đặt dependencies cho Zeek..."
sudo apt-get install -y curl gpg

# ----------------------------------------------------------
# BƯỚC 4: Thêm repo Zeek + cài đặt Zeek 8.0
# ----------------------------------------------------------
echo ""
echo "[4/5] Đang thêm Zeek repository và cài đặt Zeek 8.0..."

# Thêm GPG key
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | \
    gpg --dearmor | \
    sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

# Thêm repository
echo 'deb https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | \
    sudo tee /etc/apt/sources.list.d/security:zeek.list

# Cập nhật và cài đặt
sudo apt-get update -y
sudo apt-get install -y zeek-8.0

# ----------------------------------------------------------
# BƯỚC 5: Thêm Zeek vào PATH
# ----------------------------------------------------------
echo ""
echo "[5/5] Đang cấu hình PATH cho Zeek..."

# Thêm vào .bashrc nếu chưa có
if ! grep -q "/opt/zeek/bin" ~/.bashrc 2>/dev/null; then
    echo '' >> ~/.bashrc
    echo '# Zeek - Network Security Monitor' >> ~/.bashrc
    echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc
    echo "  → Đã thêm /opt/zeek/bin vào ~/.bashrc"
else
    echo "  → /opt/zeek/bin đã có trong ~/.bashrc"
fi

# Áp dụng ngay cho session hiện tại
export PATH=$PATH:/opt/zeek/bin

# ----------------------------------------------------------
# KIỂM TRA KẾT QUẢ
# ----------------------------------------------------------
echo ""
echo "============================================================"
echo "  KIỂM TRA KẾT QUẢ CÀI ĐẶT"
echo "============================================================"
echo ""

echo "--- Argus ---"
if command -v argus &> /dev/null; then
    echo "  ✅ argus: $(which argus)"
else
    echo "  ❌ argus: KHÔNG TÌM THẤY"
fi

if command -v ra &> /dev/null; then
    echo "  ✅ ra:    $(which ra)"
else
    echo "  ❌ ra: KHÔNG TÌM THẤY"
fi

echo ""
echo "--- Zeek ---"
if command -v zeek &> /dev/null; then
    echo "  ✅ zeek:     $(zeek --version 2>&1 | head -1)"
    echo "              $(which zeek)"
else
    # Thử đường dẫn trực tiếp
    if [ -f /opt/zeek/bin/zeek ]; then
        echo "  ✅ zeek:     $(/opt/zeek/bin/zeek --version 2>&1 | head -1)"
        echo "              /opt/zeek/bin/zeek"
    else
        echo "  ❌ zeek: KHÔNG TÌM THẤY"
    fi
fi

if command -v zeek-cut &> /dev/null; then
    echo "  ✅ zeek-cut: $(which zeek-cut)"
elif [ -f /opt/zeek/bin/zeek-cut ]; then
    echo "  ✅ zeek-cut: /opt/zeek/bin/zeek-cut"
else
    echo "  ❌ zeek-cut: KHÔNG TÌM THẤY"
fi

echo ""
echo "============================================================"
echo "  CÀI ĐẶT HOÀN TẤT!"
echo "  Hãy chạy 'source ~/.bashrc' hoặc mở terminal mới"
echo "  để Zeek PATH có hiệu lực."
echo "============================================================"
