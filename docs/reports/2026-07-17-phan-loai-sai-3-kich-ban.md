# Báo cáo phân tích: 3 kịch bản tấn công & nguyên nhân phân loại sai trong ClickHouse

> **TRẠNG THÁI KHẮC PHỤC (cập nhật 2026-07-24):** nguyên nhân gốc rễ #1 và #2 ở
> mục 6 **đã được vá** trên branch `fix/scan-vs-flood-misclassification`. Xem
> [mục 8](#8-trạng-thái-khắc-phục-2026-07-24) ở cuối báo cáo để biết đã vá gì,
> đo lại ra sao, và phần nào **vẫn còn tồn đọng**. Nguyên nhân #3 (thiếu DPI/TLS)
> và #4 chưa xử lý.

- **Ngày thực nghiệm:** 2026-07-17
- **Attacker (Kali):** `192.168.106.60`
- **Victim:** `192.168.101.135`
- **Nguồn dữ liệu:** `network_ids.flows_all` (ClickHouse, `http://localhost:8123`)
- **Bộ phân loại:** [`unified_classifier.py`](../../Extraction-and-classification/MODULE_PHANLOAI/unified_classifier.py)

## 1. Tổng quan kết quả theo khung giờ

| Khung giờ | Kịch bản | Reconnaissance | DoS | Analysis | Exploits |
|---|---|---:|---:|---:|---:|
| 07:17 | Exp1 – SYN scan `-p 1-500` + ping sweep subnet | 129 | 248 | 0 | 0 |
| 07:21 | Exp2 – `nmap -sV -O -p 1-1000` | 19 | 995 | 1 | 0 |
| 07:22 | Exp3 – nikto + curl SQLi (HTTPS) | 19 | 3 | 6 | 2 |

Truy vấn dùng để tổng hợp:

```sql
SELECT toStartOfMinute(ts) minute, attack_family, predicted_class, count() c
FROM network_ids.flows_all
WHERE predicted_class != 'Normal'
GROUP BY minute, attack_family, predicted_class
ORDER BY minute;
```

**Nhận xét đầu tiên:** cả 3 kịch bản đều sinh ra rất nhiều nhãn **"DoS"** dù không kịch bản nào là tấn công DoS thật. Đây là lỗi phân loại sai lớn nhất, nghiêm trọng hơn cả việc thiếu nhãn Reconnaissance/Analysis/Exploits.

## 2. Kịch bản 1 — Reconnaissance (SYN scan + ping sweep)

Lệnh chạy:
```bash
sudo nmap -sS -p 1-500 --min-rate 200 192.168.101.135
sudo nmap -sn 192.168.101.0/24
```

Kỳ vọng: toàn bộ flow → `Reconnaissance`.
Thực tế: 129 flow đúng nhãn Reconnaissance, nhưng **248 flow bị gắn nhãn DoS**.

Mẫu flow thật bị phân loại sai (attacker → cổng 111/135/53/23... trên victim):

```
ts=07:17:13.379  dport=111  dur=0        spkts=1 dpkts=0  rate=0      → DoS
ts=07:17:13.380  dport=110  dur=0.000512 spkts=1 dpkts=1  rate=1953   → DoS
ts=07:17:13.380  dport=113  dur=0.000203 spkts=1 dpkts=1  rate=4926   → DoS
ts=07:17:13.380  dport=445  dur=0.000146 spkts=1 dpkts=1  rate=6849   → DoS
ts=07:17:13.380  dport=345  dur=0        spkts=0 dpkts=1  rate=0      → Reconnaissance
```

→ Xem mục 4 để biết nguyên nhân gốc rễ (cơ chế `rate`/`DOS_HIGH_RATE`).

## 3. Kịch bản 2 — Analysis (dò version + OS)

Lệnh chạy:
```bash
sudo nmap -sV -O -p 1-1000 192.168.101.135
```

Kỳ vọng: flow → `Analysis`/`Reconnaissance`.
Thực tế: chỉ 1 flow đúng nhãn Analysis, 19 flow Reconnaissance, còn lại **995 flow bị gắn nhãn DoS** — tỉ lệ sai cao nhất trong 3 kịch bản vì `-sV -O` gửi nhiều probe nhanh tới 1000 cổng trong thời gian ngắn.

Mẫu flow thật (một burst tại 07:21:33.023–07:21:33.024, cùng `sport=51150`, quét lần lượt hàng chục cổng):

```
dport=143  dur=0.000578  spkts=1 dpkts=1  rate=1730   → DoS
dport=844  dur=0.000092  spkts=1 dpkts=1  rate=10869  → DoS
dport=731  dur=0.000072  spkts=1 dpkts=1  rate=13888  → DoS
dport=80   dur=0.000705  spkts=2 dpkts=1  rate=2836   → Reconnaissance
dport=23   dur=0.000705  spkts=2 dpkts=1  rate=2836   → Reconnaissance
```

## 4. Nguyên nhân gốc rễ Exp1 & Exp2: Reconnaissance/Analysis bị "DoS" nuốt nhãn

Trong `_detect_dos()` của `unified_classifier.py`:

```python
DOS_HIGH_RATE = float(os.environ.get("DOS_HIGH_RATE", "5000"))
...
is_dos = flood_like & (dst_pressure | high_rate)
```

- `rate = spkts / dur` là **tỉ số**, không phải tốc độ tuyệt đối đo trên nhiều gói.
- Một probe SYN đơn gói của nmap trong LAN có RTT bắt tay cực ngắn (~70–700 µs) → `dur` rất nhỏ → `rate` bị đội lên hàng nghìn đến hàng chục nghìn "gói/giây" **dù thực chất chỉ có 1–2 gói trao đổi**.
- Ngưỡng `DOS_HIGH_RATE=5000` được thiết kế để bắt flood tốc độ cao thật (nhiều gói dồn dập), nhưng do công thức `rate` không xét đến `spkts` tuyệt đối, nó bị false-trigger bởi chính bản chất của port-scan: nhanh, ngắn, ít gói.
- Ranh giới giữa nhãn `DoS` và `Reconnaissance` chỉ cách nhau vài trăm micro-giây độ trễ mạng (`dur=0.000577` → DoS, `dur=0.000705` → Reconnaissance) — hoàn toàn không ổn định và không phản ánh đúng bản chất tấn công.
- `FAMILY_PRIORITY` xếp `DoS` ưu tiên cao nhất, ghi đè mọi nhãn family khác (`predicted[is_dos] = "DoS"`) nên một khi flow chạm ngưỡng DoS ảo, nhãn Reconnaissance/Analysis đúng bị mất hoàn toàn.

**Đề xuất fix:** thêm điều kiện `spkts` tối thiểu (ví dụ `spkts >= 20`) trước khi áp `high_rate`, để loại các probe 1–2 gói ra khỏi nhánh "flood tốc độ cao" thay vì chỉ dựa vào tỉ số `rate`.

## 5. Kịch bản 3 — Exploits (nikto + SQLi)

Lệnh chạy:
```bash
nikto -h https://192.168.101.135 -maxtime 60s
curl -sk "https://192.168.101.135/?id=1' OR '1'='1" -o /dev/null
curl -sk "https://192.168.101.135/login?u=admin'--" -o /dev/null
```

Kết quả: 6 flow Analysis, chỉ 2 flow Exploits, 19 flow Reconnaissance, 3 flow DoS (dư âm của scan trước).

### 5.1. Vì sao phần lớn traffic nikto rơi vào "Analysis" chứ không phải "Exploits"

Mẫu flow đúng nhãn Analysis:

```
dport=23  service=http  ct_flw_http_mthd=1  trans_depth=1  response_body_len=0   → Analysis (score 39)
dport=80  service=http  ct_flw_http_mthd=1  trans_depth=1  response_body_len=264 → Analysis (score 36)
```

- nikto thử baseline HTTP trên nhiều cổng thay thế (kể cả cổng 23 không phải HTTP chuẩn); Argus gán `service=http` dựa trên **nội dung payload quan sát được**, không dựa theo số hiệu cổng chuẩn.
- Chữ ký `analysis.json` chấm điểm dựa trên `ct_flw_http_mthd` (có method HTTP) và `trans_depth` thấp (transaction nông, 1 request đơn) — đúng đặc trưng của một request dò quét đơn lẻ kiểu nikto. Đây là phân loại **đúng theo thiết kế**, không phải lỗi.

### 5.2. Vì sao chỉ 2/nhiều request SQLi được gắn đúng "Exploits"

Mẫu flow đúng nhãn Exploits:

```
dport=443  sbytes=2628 dbytes=2574  spkts=10 dpkts=9  rate=929  → Exploits (score 39)
dport=443  sbytes=2482 dbytes=2649  spkts=10 dpkts=8  rate=1193 → Exploits (score 39)
```

- Cả 2 request `curl "?id=1' OR '1'='1"` và `curl "login?u=admin'--"` đi qua **HTTPS (443)**, nghĩa là payload SQLi trong URL bị **mã hoá TLS**.
- Bộ phân loại chỉ có đặc trưng flow-level (số gói, số byte, thời gian handshake) — **không có DPI/giải mã payload** — nên hoàn toàn không "nhìn thấy" chuỗi SQL injection thực tế.
- 2 flow trên khớp nhãn Exploits chỉ vì **hình dạng lưu lượng** (số gói/byte của handshake TLS + request) tình cờ trùng với chữ ký `exploits.json`, không phải vì hệ thống hiểu đó là SQL injection.
- Các request HTTPS khác của nikto có hình dạng byte/gói khác (nhẹ hơn/nặng hơn) không chạm ngưỡng Exploits nên rơi về Analysis/Reconnaissance/Normal — giải thích tỉ lệ phát hiện thấp (chỉ 2/nhiều request).

## 6. Tổng kết nguyên nhân gốc rễ

1. **`rate = spkts/dur` là tỉ số, không phải tốc độ tuyệt đối** → probe đơn gói RTT thấp bị hiểu nhầm là "flood tốc độ cao" (`DOS_HIGH_RATE=5000`), khiến Reconnaissance/Analysis bị nhãn DoS ghi đè. Đây là lỗi hệ thống nghiêm trọng nhất (Exp1: 248 flow, Exp2: 995 flow bị ảnh hưởng).
2. **Ưu tiên nhãn cứng `DoS > Exploits > Shellcode > Generic > Analysis > Reconnaissance > Fuzzers`** trong `FAMILY_PRIORITY` khiến bất kỳ flow nào chạm ngưỡng DoS (dù do rate ảo) sẽ ghi đè nhãn family đúng hơn, không có cơ chế "soft label"/đa nhãn để đối chiếu lại.
3. **Không có payload/DPI** — mọi phân loại Exploits/SQLi qua TLS chỉ suy luận gián tiếp từ hình dạng flow (byte/gói/thời gian), nên độ chính xác phụ thuộc hoàn toàn vào việc traffic có giống phân bố huấn luyện UNSW-NB15 hay không → tỉ lệ phát hiện thấp và không ổn định.
4. **`service` field xác định theo nội dung payload, không theo port chuẩn** — hành vi này thực ra có lợi (giúp Analysis match đúng dù nikto dùng cổng lạ), không phải lỗi, nhưng dễ gây hiểu nhầm khi đọc log thô.

## 7. Đề xuất khắc phục

- Thêm điều kiện `spkts` tối thiểu (ví dụ `spkts >= 20`) trước khi áp nhánh `high_rate` trong `_detect_dos()`, để loại các probe 1–2 gói khỏi việc bị tính là "flood tốc độ cao".
- Cân nhắc tách `DOS_HIGH_RATE` theo `proto`/`dport` thay vì một ngưỡng tuyệt đối chung cho mọi loại lưu lượng.
- Ghi thêm cột phụ (ví dụ `dos_reason`) để phân biệt flow bị gắn DoS do `dst_pressure` (volumetric thật) hay do `high_rate` (dễ false-positive hơn) — hỗ trợ debug và tinh chỉnh ngưỡng sau này.

## 8. Trạng thái khắc phục (2026-07-24)

Vá trên branch `fix/scan-vs-flood-misclassification` (base: commit `3266830`),
theo đặc tả `PATCH_SPEC_scan_vs_flood.md`.

### 8.1. Bổ sung so với chẩn đoán ban đầu của báo cáo

Mục 4 của báo cáo này quy nguyên nhân Exp1/Exp2 cho **`high_rate`**. Khi vá đã
phát hiện thêm: chính **`dst_pressure` cũng gây sai độc lập**. Bằng chứng nằm
ngay trong mẫu flow ở mục 2 của báo cáo:

```
ts=07:17:13.379  dport=111  dur=0  spkts=1 dpkts=0  rate=0  → DoS
```

Flow này có `rate=0`, tức **không thể** đi qua cổng `high_rate`. Nó bị gán DoS
vì cổng `dst_pressure`: 248 flow flood-like cùng đổ về 1 victim đã vượt
`DOS_MIN_FLOWS_PER_DST=40`. Nói cách khác, dù sửa `high_rate` như báo cáo đề
xuất thì **port-scan vẫn bị gán nhãn DoS**, vì cổng volumetric cũ chỉ đếm *số
lượng* flow theo `dstip` mà không xét chúng nhắm vào bao nhiêu cổng. Do đó bản
vá xử lý **cả hai** cổng.

### 8.2. Đã vá

1. **Cổng `dst_pressure` — thêm điều kiện độ đa dạng cổng đích**
   (`DOS_MAX_DPORT_SPREAD`, mặc định `8`): một đích chỉ được coi là đang chịu
   flood khi lượng flow flood-like đổ về nó tập trung vào ít cổng. Flood dồn
   vào 1 cổng; scan trải hàng trăm cổng. Đây là đặc trưng **duy nhất** còn phân
   biệt được hai loại ở tầng flow-only.
2. **Cổng `high_rate` — thêm yêu cầu số gói tối thiểu**
   (`DOS_MIN_PKTS_FOR_RATE`, mặc định `4`). Báo cáo đề xuất `spkts >= 20`; bản
   vá chọn `4` — thấp hơn nên **an toàn hơn với false-negative** (không loại oan
   flood thật có ít gói/flow), mà vẫn đủ chặn probe 1–2 gói. Hiệu chỉnh được qua
   biến môi trường.
3. **Nhãn trung tính không ghi đè nhãn họ hợp lệ.** Sau khi (1) loại port-scan
   khỏi DoS, các flow scan rơi vào diện `flood_like_ungated` và **sẽ bị gán
   `Suspicious-Low-Volume`** theo logic cũ — tức chỉ đổi một nhãn sai lấy một
   nhãn sai khác, không giải quyết được vấn đề báo cáo này nêu. Đã siết thành
   `flood_like_ungated & ~has_family`: các flow scan có
   `reconnaissance_score` vượt ngưỡng nên giữ đúng nhãn `Reconnaissance`.

### 8.2b. Một false-negative do chính bản vá gây ra — đã phát hiện và bịt trước khi triển khai

Cài đặt đầu tiên của cổng spread đếm cổng riêng biệt trên giá trị `dport` **thô**.
Điều đó sai khi `dport` là `NaN` — xảy ra thật với flow **ICMP** (không có cổng
đích) và ô CSV rỗng: từ Python 3.10, `hash(NaN)` dựa trên `id()` và `nan != nan`,
nên **mỗi `NaN` là một phần tử set riêng**.

Đo được: flood 500 flow với `dport=NaN` cho `spread=500` > ngưỡng `8` →
`dst_pressure=False` → **500/500 DoS trở thành 0/500, bỏ lọt hoàn toàn**. Đây
đúng là kiểu đánh đổi false-positive lấy false-negative mà quy trình vá yêu cầu
phải revert nếu gặp.

Đã bịt bằng cách chuẩn hoá `dport` về `int64` với sentinel `-1` cho giá trị thiếu
(tách biệt với cổng `0` hợp lệ), để mọi `dport` thiếu đếm là **đúng một** cổng.
Có test hồi quy `test_flood_with_missing_dport_still_dos` phủ cả `NaN`, `""`,
`None`.

### 8.3. Đo lại (cùng một tập dữ liệu, chạy qua classifier cũ và mới)

| Kịch bản | Trước vá | Sau vá | Mong muốn |
|---|---|---|---|
| KB1 port-scan (500 cổng, 1 host) | 500/500 DoS | **0/500 DoS** (493 Reconnaissance, 7 Suspicious-Low-Volume) | Không DoS ✔ |
| Flood thật (dport=80, 500 flow) | 500/500 DoS | **500/500 DoS** | DoS ✔ |
| Flood trải 5 cổng (500 flow) | 500/500 DoS | **500/500 DoS** | DoS ✔ |
| Flood với `dport` thiếu (NaN, 500 flow) | 500/500 DoS | **500/500 DoS** | DoS ✔ (xem 8.2b) |
| Fixture test cũ (60 flow, dport=80) | 60/60 DoS | **60/60 DoS** | DoS ✔ |

Không có false-negative: mọi kịch bản flood thật giữ nguyên 100% phát hiện.
Test suite `MODULE_PHANLOAI`: 40 pass → **46 pass** (+6 test hồi quy), 2 skip.

### 8.3b. Đo lại trên CHÍNH DỮ LIỆU THẬT của báo cáo này (2026-07-24)

Các flow của 3 kịch bản vẫn còn nguyên trong `network_ids.flows_all`. Đã export
lại chúng (de-dup: `flows_all` là Merge của 7 bảng nên mỗi flow vật lý xuất hiện
7 lần) và chạy qua classifier **sau khi vá** với **cùng đầu vào**. Nhãn cũ đọc
trực tiếp từ ClickHouse tái tạo đúng Bảng 3.1 ở mục 1, xác nhận phép so sánh
là hợp lệ:

| Khung giờ | Kịch bản | Nhãn DoS cũ | Nhãn DoS mới | Các flow đó chuyển thành |
|---|---|---:|---:|---|
| 07:15 | phần đầu SYN scan `-p 1-500` | 495 | **0** | 488 Reconnaissance + 7 Suspicious-Low-Volume |
| 07:17 | Exp1 – SYN scan + ping sweep | 248 | **0** | 244 Reconnaissance + 4 Suspicious-Low-Volume |
| 07:21 | Exp2 – `nmap -sV -O -p 1-1000` | 995 | **0** | 986 Reconnaissance + 9 Suspicious-Low-Volume |
| 07:22 | Exp3 – nikto + SQLi | 3 | **0** | 3 Reconnaissance |
| 2026-07-24 | flow đơn lẻ (artifact `high_rate`) | 7 | **0** | 5 Suspicious-Low-Volume + 2 Reconnaissance |
| | **Tổng** | **1748** | **0** | |

**Không một flow nào MỚI trở thành DoS** ở bất kỳ khung nào — bản vá chỉ bỏ nhãn
DoS sai, không tạo nhãn DoS mới.

Phát hiện đi kèm khi phân rã: **toàn bộ 1748 nhãn `DoS` mà hệ thống từng sinh ra
đều là false-positive.** Không có một cuộc flood thật nào trong dữ liệu đã lưu —
mọi khung có nhãn DoS đều mang chữ ký port-scan (1 `srcip`, 1 `dstip`, hàng trăm
`dport` riêng biệt, `spkts=1`) hoặc là flow đơn lẻ 1–2 gói. Con số 495 ở khung
07:15 nằm ngoài Bảng 3.1 của báo cáo gốc nhưng cùng bản chất (phần đầu của cùng
cuộc quét).

### 8.3c. Phần xác minh CHƯA làm được

Kiểm soát false-negative **trên traffic sống** (mục 9 của quy trình vá: phát một
SYN-flood spoofed-source thật bằng `hping3 -S --rand-source` và xác nhận hệ thống
**vẫn** gán nhãn DoS) **chưa chạy được**: `hping3` và `nmap` chưa cài trên máy
sniff, và `sudo` yêu cầu mật khẩu.

Hiện tại kiểm soát false-negative chỉ dựa trên: (a) 4 kịch bản flood tổng hợp ở
mục 8.3 — đều giữ 100% phát hiện; (b) 6 test hồi quy; (c) dữ liệu thật đã lưu
**không chứa** flood thật nào để đối chiếu. **Cần chạy mục 9 trước khi coi bản vá
là đã xác minh đầy đủ trên môi trường sản xuất.**
Test suite gốc `tests/`: 52 pass, 1 fail — fail này **đã có sẵn** ở commit
`3266830` trước khi vá (`test_idempotency.py`, guard chống dữ liệu giả của
`clickhouse_sink` loại fixture 200 dòng của chính test), không liên quan bản vá.

### 8.4. Còn tồn đọng — KHÔNG được coi là đã giải quyết hết

- **Scan hẹp (≤ 8 cổng) vào 1 host với ≥ 40 flow vẫn bị gán DoS.** Vùng chồng
  lấn thật ở tầng flow-only: 60 flow dồn vào 6 cổng của một máy về mặt thống kê
  *đúng là* giống flood. Cần tín hiệu ngoài flow (nhịp thời gian giữa các probe,
  hoặc trạng thái phản hồi RST của victim). **Không** vá bằng cách hạ
  `DOS_MAX_DPORT_SPREAD` — sẽ bỏ lọt flood đa cổng thật.
- **Nguyên nhân gốc rễ #2 (ưu tiên nhãn cứng, không có soft-label/đa nhãn) chưa
  xử lý.** `predicted[is_dos] = "DoS"` vẫn ghi đè mọi nhãn họ. Bản vá chỉ làm
  cổng DoS *chính xác hơn*, không thay đổi cơ chế ưu tiên.
- **Nguyên nhân gốc rễ #3 (thiếu DPI/TLS) chưa xử lý** — Exp3 (nikto/SQLi qua
  HTTPS) vẫn chỉ suy luận từ hình dạng luồng. Hạng mục riêng, lớn hơn một PR.
- **Đề xuất cột `dos_reason` ở mục 7 chưa làm.** Sẽ cần đổi schema ClickHouse +
  tầng hiển thị. Ghi vào backlog.
- **Nhãn `Suspicious-Low-Volume` vẫn chưa có biểu diễn riêng ở dashboard**
  (tồn đọng từ bản vá `fix/dosguard-race-and-classifier-gating-edge-cases`).
