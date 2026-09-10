# Báo cáo thực nghiệm: Kiểm định 6/7 họ phân loại (bỏ DoS) — 2026-09-08

> **Ngày:** 2026-09-08, 17:30–18:25 UTC
> **Máy sniff:** `192.168.106.77` (ens19 mirror, pipeline v2.0.0 + patch scan-vs-flood)
> **Attacker #1 (Kali):** `192.168.109.24` — **Attacker #2 (Kali):** `192.168.100.225`
> **Victim:** `192.168.101.135` (open: 21,22,23,80,443,3306 — closed: còn lại; **không có cổng filtered**)
> **Nguồn dữ liệu:** `network_ids.flows_all` (ClickHouse), 35/35 segment `success`, 0 failed
> **Ghi chú đếm:** mỗi flow có thể xuất hiện nhiều dòng trong `flows_all` (1 dòng/family-filter) — mọi số
> liệu dưới đây đã **dedup bằng `uniqExact(tuple(srcip,sport,dport,ltime,sbytes))`**.

---

## 0. Sự cố hạ tầng phát hiện & đã sửa TRƯỚC khi thực nghiệm (quan trọng!)

**Producer "báo published" nhưng Kafka rỗng — mất dữ liệu im lặng.**
- Triệu chứng: producer log `published segment` + warning `Produced messages ... base offset -1`,
  nhưng `kafka-get-offsets` = 0 và console-consumer = 0 messages; partition log 0 byte.
- Nguyên nhân: broker Kafka dùng **mặc định `message.max.bytes` ≈ 1MB** (server.properties không khai
  báo), trong khi segment pcap 60 giây × traffic mirror ≈ vài MB → broker từ chối với
  `MessageSizeTooLargeError` (đã tái tạo bằng test 1MB/3MB). Producer dùng `send()` fire-and-forget,
  không kiểm tra future → mất im lặng.
- **Fix đã áp dụng:** thêm `message.max.bytes=100663296` vào `/opt/kafka/config/server.properties`
  (backup `server.properties.bak.*`), restart kafka, tạo lại topic `raw_pcap_segments` (1P/1R,
  retention 1h/2GB). Test 5MB → OK. Sau fix pipeline chạy 35/35 segment thành công.
- Bài học: đáng thêm assertion future.get() hoặc check offset sau flush trong producer.

## 1. Runlog — đã làm gì, lúc nào, mất bao lâu

| Thời gian (UTC) | Thời lượng | Máy | Hành động |
|---|---|---|---|
| 17:30:42 | — | sniff | start `sniff-producer` + `ec-consumer` |
| 17:31–17:35 | ~4 min | kali1 | *Prep:* scan cổng victim (lấy open/filtered), cài sshpass |
| 17:41–17:44 | ~3 min | sniff | **Sửa sự cố Kafka** (mục 0) |
| **17:52:48 → 17:52:54** | **6s** | kali1 | **P1 Recon:** `nmap -sS -p 1-500 --min-rate 200` + `nmap -sn 192.168.101.0/24` |
| 17:53:24 → 17:54:31 | ~67s | kali2 | **P2 Analysis (lần 1):** `nmap -sV -O -p 1-1000 --version-light` (49.5s, nền) + `nikto -h https://… -maxtime 60s` + 80× `curl -I` (path 46 ký tự) |
| 17:55:49 → 17:56:08 | ~19s | kali1 | **P3 Exploits:** ~120× `curl` SQLi payload ~1.4KB, 6 req/connection |
| 17:56:45 → 17:58:05 | ~80s | kali2 | **P4 Fuzzers (lần 1):** 30× `hping3 --udp --data 8 --rand-source` (30 cổng 1024–1053) |
| 17:58:05 → 17:58:16 | ~11s | kali1+kali2 | **P5:** kali1 = 30× `hping3 -R --ttl 255 --data 600 -c 1` (Shellcode, cổng 1200–1229) **đồng thời** kali2 = 15× `hping3 -R --ttl 255 -c 10 -i u10` (Generic, cổng 1100–1114) |
| 18:09:31 → 18:10:01 | ~30s | kali2+kali1 | **Vòng 2:** Analysis path 90 (80× HEAD) + Fuzzers `--data 0` (30×) + Generic frag `--data 4000 --ttl 255` (10×) |
| 18:12:47 → 18:13:03 | ~16s | kali2 | **Vòng 3 Fuzzers:** 30× **scapy** UDP 28B rand-src (sport 33333+) |
| 18:13:39 → 18:13:41 | 2s | kali2 | **Vòng 3 Analysis:** 80× HEAD path 260, strip headers |
| **18:21:53 → 18:21:55** | **2s** | kali2 | **Vòng 4 Analysis (thành công):** 80× HEAD **path 46 + strip headers** → sbytes ~480–500 |

## 2. Kết quả từng họ (dedup)

| Họ | Đợt tấn công | Kỳ vọng | Thực tế (flow distinct) | Verdict |
|---|---|---|---|---|
| **Reconnaissance** | P1: SYN scan 500 cổng + ping sweep | ~500 Recon | **492 Reconnaissance, 0 DoS** | ✅ **ĐẠT** (8 flow mất do BPF `not port 22` + mép segment) |
| **Analysis** | R4: HTTP HEAD probe (path 46, strip headers) | 80 Analysis | **80 Analysis** | ✅ **ĐẠT** (100% sau khi hiệu chỉnh request, mục 3.1) |
| **Exploits** | P3: SQLi payload 1.4KB, 6 req/conn | ~25 Exploits | **20 Exploits** | ✅ **ĐẠT** |
| **Shellcode** | P5: bare-RST 654B, TTL 255, one-way | 30 Shellcode | **30 Shellcode** | ✅ **ĐẠT 100%** |
| **Fuzzers** | P4: UDP 28–60B rand-src, 30 cổng | ≥30 Fuzzers | **0 Fuzzers** (30 flow → Recon) | ❌ **KHÔNG ĐẠT — giới hạn cấu trúc** (mục 3.2) |
| **Generic** | P5/R2: burst/frag TTL 255 | ≥15 Generic | **0 Generic** (frag 4KB → 4 Shellcode + 6 Normal) | ❌ **KHÔNG ĐẠT — giới hạn cấu trúc** (mục 3.3) |
| **DoS** (đối chứng bị động) | toàn bộ 33 phút tấn công | 0 false-positive | **0 DoS trong toàn bộ thực nghiệm** | ✅ **Bản vá scan-vs-flood hoạt động đúng** (KB1 trước vá: 248 flow sai) |

## 3. Nguyên nhân 3 lần fail & bằng chứng flow

### 3.1 Analysis — fail 3 vòng do `sbytes≤500` tính CẢ handshake TCP
- Argus tính `sbytes` = tổng byte phía nguồn của **toàn bộ connection**, không chỉ request:
  SYN(60) + request + FIN/ACK(120) + overhead ≈ **request + ~440B**.
- Vòng 1 (path 46, headers đầy): sbytes=527 → Analysis 29/30 điểm (thiếu đúng 1 điểm) → Normal.
  Vòng 2 (path 90, headers đầy): 582B → Normal. Vòng 3 (path 260, strip headers): ~709B → Normal.
  **Vòng 4 (path 46 + strip User-Agent/Accept): ~482–500B → 80/80 Analysis.**
- Sọt ngọt thực nghiệm: **tổng sbytes ∈ (200, 500]** — dưới 200 Recon `sbytes≤200` giành,
  trên 500 mất decisive của Analysis.

### 3.2 Fuzzers — `smean≤50` KHÔNG ĐẠT ĐƯỢC VẬT LÝ trên Ethernet
- scapy gửi gói IP/UDP 28B (không payload) → capture vẫn ghi `sbytes=60, smean=60`.
- Nguyên nhân: **Ethernet pad mọi frame nhỏ lên 60 byte** (không tính FCS) — Argus đếm byte
  đã pad. hping3 `--data 0` cũng ra 60B.
- → Decisive `smean≤50` **không thể chạm** với bất kỳ gói Ethernet nào. Fuzzers chỉ còn
  3/4 decisive (30đ) + support ≤9đ = 39đ, thua Recon 42đ trong mọi cấu hình đã thử.

### 3.3 Generic — luôn thua Shellcode ở thế hòa điểm (priority tie-break)
- Bằng chứng flow frag 4122B TTL255 (vòng 2): `sload = 50–156 Mbps ✓ (≥30M)`, `sttl=255 ✓`,
  `rate=6.8k–21k ✗ (<100k)`, `dttl=64 ✗` (victim RST mọi cổng closed — **không còn cổng
  filtered để có one-way**), `ct_state_ttl=0`.
- Điểm: Generic = sttl+sload (2 decisive) + 4 support = **32**; Shellcode = sttl+sbytes
  (2 decisive) + support = **32** → **hòa → `FAMILY_PRIORITY` xếp Shellcode trước → Shellcode
  giành** (4/10 flow; 6/10 rơi Normal do biên support).
- Kết luận: trên victim phản hồi nhanh, **Generic bị Shellcode che phủ hoàn toàn ở tầng
  flow-only** — cần tín hiệu ngoài flow (nhịp thời gian, DPI) để tách 2 họ này.

### 3.4 Phát hiện phụ: nhân bản dòng trong `flows_all`
- Mỗi flow có thể xuất hiện **tối đa 7 dòng** trong `flows_all` (1 dòng mỗi family-filter
  pre-select). Ví dụ: 80 flow HEAD → 560 dòng (80 Analysis + 480 Normal). Dashboard/truy vấn
  tổng hợp **phải dedup** theo định danh flow, nếu không sẽ đếm phóng đại ~7×.

## 4. Xác minh bản vá scan-vs-flood (đạt ngoài dự kiến)
- Toàn bộ 33 phút tấn công (kể cả SYN scan 500 cổng + nmap -sV 1000 cổng + 30 flow UDP dồn
  1 dst): **0 flow nào bị gán nhãn DoS** — so với báo cáo 2026-07-17: KB1 sai 248/377,
  KB2 sai 995/1015. `DOS_MAX_DPORT_SPREAD=8` + `DOS_MIN_PKTS_FOR_RATE=4` hoạt động đúng.
- Lưu ý: đợt này **chưa** chạy flood thật nên chưa kiểm chứng chiều bỏ lọt DoS — theo
  PATCH_SPEC mục 9, cần 1 đợt `hping3 -S --flood --rand-source` đối chứng sau.

## 5. Khuyến nghị
1. **Producer:** assert kết quả gửi Kafka (future.get / kiểm tra end-offset) — sự cố mục 0
   gây mất dữ liệu im lặng nhiều ngày.
2. **Fuzzers:** nâng `smean≤50 → ≤64` (sàn Ethernet) hoặc bỏ luật, thay bằng đặc trưng khác.
3. **Analysis:** nâng `sbytes≤500 → ≤600` hoặc tăng trọng số `trans_depth`/`ct_flw_http_mthd`.
4. **Generic:** ghi nhận "bị Shellcode che phủ trên victim phản hồi"; cân nhắc đảo priority
   hoặc thêm điều kiện dttl/rate đặc hiệu hơn.
5. **Dashboard/truy vấn:** luôn dedup khi đếm flow từ `flows_all`.

## 6. Truy vấn tái lập
```sql
SELECT predicted_class,
       uniqExact(tuple(srcip,sport,dport,ltime,sbytes)) AS flows
FROM network_ids.flows_all
WHERE ts >= '2026-09-08 17:52:00'
  AND srcip IN ('192.168.109.24','192.168.100.225')
  AND predicted_class != 'Normal'
GROUP BY predicted_class;
```

