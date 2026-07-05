#!/bin/bash
echo "=== KẾT QUẢ CÀI ĐẶT ==="
echo ""

export PATH=$PATH:/opt/zeek/bin

echo "[Argus]"
echo -n "  argus:    "; which argus 2>/dev/null && echo "  ✅ OK" || echo "  ❌ NOT FOUND"
echo -n "  ra:       "; which ra 2>/dev/null && echo "  ✅ OK" || echo "  ❌ NOT FOUND"
echo -n "  version:  "; ra --version 2>&1 | head -1

echo ""
echo "[Zeek]"
echo -n "  zeek:     "; which zeek 2>/dev/null && echo "  ✅ OK" || echo "  ❌ NOT FOUND"
echo -n "  zeek-cut: "; which zeek-cut 2>/dev/null && echo "  ✅ OK" || echo "  ❌ NOT FOUND"
echo -n "  version:  "; zeek --version 2>&1 | head -1

echo ""
echo "=== DONE ==="
