#!/bin/bash
DIR="/mnt/c/Users/USER/Downloads/Source_For_Matching/4-6-DoS/filepcap"

echo "=== ARGUS TEMP (5 dong dau) ==="
head -6 "$DIR/argus_temp.csv" 2>/dev/null || echo "File khong ton tai"

echo ""
echo "=== ZEEK TEMP (5 dong dau) ==="
head -6 "$DIR/zeek_temp.csv" 2>/dev/null || echo "File khong ton tai"

echo ""
echo "=== ZEEK: service va state co du lieu khong? ==="
if [ -f "$DIR/zeek_temp.csv" ]; then
    echo "Tong dong:"
    wc -l "$DIR/zeek_temp.csv"
    echo ""
    echo "Mau service va conn_state:"
    awk -F',' 'NR>1 && NR<=10 {print "  service=" $8 " | state=" $9}' "$DIR/zeek_temp.csv"
    echo ""
    echo "Dong co service khong rong:"
    awk -F',' 'NR>1 && $8!=""' "$DIR/zeek_temp.csv" | wc -l
    echo ""
    echo "Dong co state khong rong:"
    awk -F',' 'NR>1 && $9!=""' "$DIR/zeek_temp.csv" | wc -l
fi

echo ""
echo "=== SO SANH MERGE KEYS ==="
echo "--- Argus: 3 dong srcip,dstip,sport,dport,proto ---"
if [ -f "$DIR/argus_temp.csv" ]; then
    awk -F',' 'NR>1 && NR<=4 {print "  " $3 "," $4 "," $5 "," $6 "," $7}' "$DIR/argus_temp.csv"
fi
echo "--- Zeek: 3 dong srcip,dstip,sport,dport,proto ---"
if [ -f "$DIR/zeek_temp.csv" ]; then
    awk -F',' 'NR>1 && NR<=4 {print "  " $3 "," $4 "," $5 "," $6 "," $7}' "$DIR/zeek_temp.csv"
fi
