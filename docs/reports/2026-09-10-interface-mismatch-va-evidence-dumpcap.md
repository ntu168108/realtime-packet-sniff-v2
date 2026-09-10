# Báo cáo sự cố & khắc phục: chọn NIC ở Web GUI và ghi PCAP bằng chứng (dumpcap)

- **Ngày:** 2026-09-10
- **Máy:** `tu` (`192.168.1.35`), NIC thật duy nhất `ens33`
- **Phiên bản:** pipeline v2.0.0 (`main`)
- **Commit khắc phục:** `9f108c6`

## TL;DR

Ba sự cố nối tiếp khiến pipeline "chạy nhưng rỗng" và tính năng PCAP bằng chứng
không hoạt động:

1. `config.yaml` trỏ NIC `ens19` — **không tồn tại** trên máy này → producer bắt 0 gói.
2. Web `/capture` bấm Start báo `Interface 'ens19' not found` **dù dropdown hiển thị `ens33`**.
3. Bộ ghi PCAP bằng chứng (`dumpcap`) không khởi động: option `--print` không tồn tại
   ở dumpcap 4.x, cộng thêm quyền thư mục chặn dumpcap ghi file.

Sau khắc phục: Kafka nhận segment, ClickHouse có dữ liệu trở lại, và
`evidence_ens33_*.pcap` được ghi liên tục.

## 1. Sự cố interface mismatch (`ens19` vs `ens33`)

**Triệu chứng:** `sniff-producer` báo `active`, log `Capture started on ens19`,
nhưng `kafka-get-offsets --topic raw_pcap_segments` = `0`, consumer lag = `-`,
toàn bộ 9 bảng `network_ids.*` = 0 dòng.

**Nguyên nhân gốc:** `config.yaml` giữ `capture.interface: ens19` — di sản của máy
thí nghiệm cũ (`192.168.106.77`, NIC mirror `ens19`). Máy hiện tại chỉ có `ens33`.

**Khắc phục:**
```yaml
# config.yaml
capture:
  interface: ens33
```
```bash
systemctl restart sniff-producer
```

## 2. Web `/capture` báo `Interface 'ens19' not found`

**Triệu chứng:** chọn NIC trên dropdown rồi bấm Start vẫn nhận
`400 Interface 'ens19' not found`.

**Nguyên nhân gốc:** `sniff-web/web/src/pages/Capture.tsx` nạp
`/api/capture/last-config` rồi `setIface(lc.interface)` **ghi đè vô điều kiện**,
kể cả khi NIC đó không còn trong danh sách NIC thật (`/api/interfaces` chỉ trả
`ens33`). `<select value="ens19">` không có `<option>` khớp nên trình duyệt hiển
thị như thể đang chọn `ens33`, nhưng state React vẫn là `ens19` → Start gửi
`ens19` lên backend.

**Khắc phục:**
- Chỉ khôi phục NIC đã lưu **nếu nó vẫn tồn tại**; nếu không thì fallback về NIC
  đầu tiên đang có và hiện thông báo.
- Thêm nút **Reload** để quét lại danh sách NIC (hỗ trợ cắm/rút/đổi card).
- Chặn gửi NIC không hợp lệ trước khi Start.
- Backend `/api/capture/start` trả lỗi kèm danh sách NIC khả dụng:
  `Interface 'x' not found. Available: ens33`.

## 3. PCAP bằng chứng (`dumpcap`) không chạy

### 3.1 Option không tồn tại

`core/native_writer.py` (`DumpcapWriter._build_cmd`) sinh lệnh có `--print`. Option
này **không tồn tại** trong Wireshark/dumpcap 4.x → dumpcap in usage rồi thoát
ngay (tiến trình thành zombie), không tạo file pcap.

**Khắc phục:** bỏ `--print`; đổi `-n` (pcapng) → `-P` (pcap) cho khớp mục đích
"pcap ground truth".

### 3.2 Quyền thư mục

`dumpcap` sau khi mở NIC sẽ **hạ bỏ capability `CAP_DAC_OVERRIDE`** (vẫn uid 0
nhưng không còn quyền bỏ qua phân quyền). Vì vậy nó chỉ ghi được vào thư mục do
root sở hữu hoặc world-writable. Thư mục bằng chứng `tu:tu 755` nằm dưới parent
`750` → `Permission denied` dù chạy bằng root.

**Khắc phục:**
```bash
chmod o+x /var/lib/sniff-web                    # parent 750 -> 751 cho dumpcap đi qua
chown root:tu /var/lib/sniff-web/sniff_data     # root sở hữu -> dumpcap ghi được
chmod 775 /var/lib/sniff-web/sniff_data         # nhóm tu vẫn ghi được (web rotator)
```

### 3.3 Giới hạn còn lại

`evidence_drop` trong log DoS chỉ chốt ở dòng tổng kết khi dumpcap **dừng**
(SIGINT). dumpcap 4.2 không ghép được `-S` (thống kê định kỳ) với ring buffer
`-b` (`Ring buffer requested, but a capture isn't being done.`). Muốn thống kê
drop live cần bỏ ring `-b` và dùng `-S`, rồi parse bảng riêng.

## 4. Kiểm chứng

Bắt trên `ens33` (đúng NIC) sau khắc phục:

| Chỉ số | Trước | Sau |
|---|---:|---:|
| Kafka `raw_pcap_segments` offset | 0 | 15 |
| Consumer lag `ec-consumer` | `-` | 0 |
| ClickHouse `flows_all` | 0 | 17409 |
| `evidence_ens33_*.pcap` | không có | có (đang lớn dần) |

## 5. File thay đổi (commit `9f108c6`)

| File | Nội dung |
|---|---|
| `sniff-web/web/src/pages/Capture.tsx` | Chọn NIC linh hoạt, Reload, validate trước Start |
| `sniff-web/web_server.py` | `/api/capture/start` lỗi kèm danh sách NIC khả dụng |
| `core/native_writer.py` | Bỏ `--print`, `-n` → `-P` cho evidence |
| `CHANGELOG.md` | Mục `[Unreleased]` + deployment notes |

## 6. Tồn đọng / khuyến nghị

- `DoS SUSPECTED` vẫn kích hoạt nhầm ở pps rất thấp (~15) do cơ chế backpressure —
  cùng hiện tượng đã ghi nhận trước đây, chưa xử lý.
- `config.yaml` (chứa `jwt_secret`, `password_hash`) và `last_capture.json` không
  nên commit — hiện đang được `.gitignore`/để ngoài git.
- Thống kê drop live của evidence (mục 3.3) nếu cần chính xác theo thời gian thực.
