#!/bin/bash
FILE="/mnt/d/1LearnandStudy/Program_Language/Python/TrichXuat/final_features_nb15_with_mac.csv"

echo "=== HEADER ==="
head -1 "$FILE"

echo ""
echo "=== 5 DONG DAU ==="
sed -n '2,6p' "$FILE"

echo ""
echo "=== KIEM TRA SERVICE VA STATE ==="
echo -n "Tong dong: "; wc -l < "$FILE"
echo -n "Dong co state KHONG rong: "; awk -F',' 'NR>1 && $9!=""' "$FILE" | wc -l
echo -n "Dong co service KHONG rong: "; awk -F',' 'NR>1 && $8!=""' "$FILE" | wc -l

echo ""
echo "=== MAU STATE VALUES ==="
awk -F',' 'NR>1 && $9!="" {print $9}' "$FILE" | sort | uniq -c | sort -rn | head -10

echo ""
echo "=== MAU SERVICE VALUES ==="
awk -F',' 'NR>1 && $8!="" {print $8}' "$FILE" | sort | uniq -c | sort -rn | head -10
