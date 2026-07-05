#!/bin/bash
FILE="/mnt/c/Users/USER/Downloads/Source_For_Matching/4-6-DoS/filepcap/final_features_nb15_with_mac.csv"

echo "=== FILE INFO ==="
ls -lh "$FILE"

echo ""
echo "=== HEADER (18 cot) ==="
head -1 "$FILE"

echo ""
echo "=== 5 DONG DAU ==="
sed -n '2,6p' "$FILE"

echo ""
echo "=== TONG DONG ==="
wc -l "$FILE"

echo ""
echo "=== SO COT ==="
head -1 "$FILE" | tr ',' '\n' | wc -l
