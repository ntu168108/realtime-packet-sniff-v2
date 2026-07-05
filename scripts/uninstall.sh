#!/bin/bash
#
# SNIFF Uninstaller
# Usage: curl -sSL https://raw.githubusercontent.com/ntu168108/realtime-packet-sniff/main/uninstall.sh | sudo bash
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Uninstalling SNIFF...${NC}"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Stop service if running
if systemctl is-active --quiet sniff; then
    echo "Stopping SNIFF service..."
    systemctl stop sniff
fi

# Disable service
if systemctl is-enabled --quiet sniff 2>/dev/null; then
    echo "Disabling SNIFF service..."
    systemctl disable sniff
fi

# Remove service file
if [ -f /etc/systemd/system/sniff.service ]; then
    echo "Removing service file..."
    rm /etc/systemd/system/sniff.service
    systemctl daemon-reload
fi

# Uninstall pip package
if pip3 show sniff-pcap &> /dev/null; then
    echo "Uninstalling SNIFF package..."
    pip3 uninstall -y sniff-pcap
fi

echo ""
echo -e "${GREEN}SNIFF has been uninstalled.${NC}"
echo ""
echo "Note: Captured data in sniff_data/ was NOT deleted."
echo "Remove manually if needed: rm -rf /path/to/sniff_data"
echo ""
