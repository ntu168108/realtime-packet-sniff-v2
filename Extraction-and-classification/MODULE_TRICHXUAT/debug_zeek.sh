#!/bin/bash
DIR="/mnt/c/Users/USER/Downloads/Source_For_Matching/4-6-DoS/filepcap"
export PATH=$PATH:/opt/zeek/bin

echo "=== CONN.LOG RAW (3 dong dau, bo comment) ==="
grep -v '^#' "$DIR/zeek_logs/conn.log" 2>/dev/null | head -3

echo ""
echo "=== CONN.LOG HEADER ==="
grep '^#fields' "$DIR/zeek_logs/conn.log" 2>/dev/null

echo ""
echo "=== ZEEK-CUT TEST: chi lay id.orig_h, service, conn_state ==="
grep -v '^#' "$DIR/zeek_logs/conn.log" 2>/dev/null | head -5 | zeek-cut id.orig_h id.resp_h id.orig_p id.resp_p proto service conn_state

echo ""
echo "=== ZEEK-CUT TEST: co orig_l2_addr khong? ==="
grep '^#fields' "$DIR/zeek_logs/conn.log" 2>/dev/null | grep -o 'orig_l2_addr' || echo "KHONG CO orig_l2_addr trong conn.log!"

echo ""
echo "=== ZEEK-CUT voi mac ==="
grep -v '^#' "$DIR/zeek_logs/conn.log" 2>/dev/null | head -3 | zeek-cut orig_l2_addr resp_l2_addr id.orig_h id.resp_h id.orig_p id.resp_p proto service conn_state
