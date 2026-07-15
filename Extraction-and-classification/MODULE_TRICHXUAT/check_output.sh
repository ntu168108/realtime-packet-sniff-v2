#!/bin/bash
# Usage: ./check_output.sh <path/to/final_features_nb15_with_mac.csv>
FILE="${1:?Usage: $0 <path/to/final_features_nb15_with_mac.csv>}"

echo "=== FINAL HEADER ==="
head -n 1 "$FILE"

echo ""
echo "=== 5 ROWS ==="
head -n 6 "$FILE" | tail -n 5

echo ""
echo "=== TOTAL ROWS ==="
wc -l < "$FILE"
