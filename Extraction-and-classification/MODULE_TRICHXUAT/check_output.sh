#!/bin/bash
FILE="/mnt/c/Users/USER/Downloads/Source_For_Matching/4-6-DoS/filepcap/final_features_nb15_with_mac.csv"

echo "=== FINAL HEADER ==="
head -n 1 "$FILE"

echo ""
echo "=== 5 ROWS ==="
head -n 6 "$FILE" | tail -n 5

echo ""
echo "=== TOTAL ROWS ==="
wc -l < "$FILE"
