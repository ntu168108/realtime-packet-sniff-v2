# MODULE_AUTO — Tự động hóa pipeline PCAP → Trích xuất → Phân loại

Tự động hóa toàn bộ luồng: thả file `.pcap` vào thư mục `Filepcap/` → chờ xem các CSV đã lọc xuất hiện ở các thư mục `CSV/Filter_*`. Không cần thao tác thủ công.

## Luồng dữ liệu

```
file.pcap  (thả vào Filepcap/)
   │
   ▼
MODULE_TRICHXUAT
   ├─ extractor.py    →  CSV/CSV_Full_feature/<base>_raw.csv
   └─ add_features.py →  CSV/CSV_Full_feature/<base>_dos_features.csv  (50 cột)
   │
   ▼
MODULE_PHANLOAI  (7 filter, chế độ file đơn lẻ)
   ├─ generic        → CSV/Filter_Generic_feature/
   ├─ dos            → CSV/Filter_DoS_feature/
   ├─ exploits       → CSV/Filter_Exploits_feature/
   ├─ fuzzers        → CSV/Filter_Fuzzers_feature/
   ├─ analysis       → CSV/Filter_Analysis_feature/
   ├─ reconnaissance → CSV/Filter_Reconnaissance_feature/
   └─ shellcode      → CSV/Filter_Shellcode_feature/
   │
   ▼
pcap được move sang  Filepcap/processed/
```

## File trong module

- `auto_pipeline.py` — Orchestrator: nhận 1 pcap, chạy tuần tự extractor → add_features → 7 filter.
- `pcap_watcher.py` — Theo dõi thư mục `Filepcap/`, tự gọi orchestrator khi có pcap mới.

## Yêu cầu

- **WSL + argus + zeek** (cho `extractor.py`) — đã bật.
- **Python có pandas/numpy**. Orchestrator tự dò interpreter có pandas (ưu tiên biến môi trường `AUTO_PIPELINE_PYTHON`, rồi `py -3`, rồi `python`). Trên máy này: `Python314` (pandas 3.0.3).
- **watchdog** (tùy chọn): `pip install watchdog` để watcher phản ứng tức thì. Không cài thì tự fallback sang polling.

## Cách dùng

### 1. Chạy tự động (khuyến nghị)

Khởi động watcher rồi để chạy nền:

```powershell
py -3 pcap_watcher.py
```

Sau đó chỉ cần copy/move file `.pcap` vào `Filepcap/`. Watcher sẽ:
1. Chờ file ổn định kích thước (tránh đọc file đang copy dở).
2. Chạy full pipeline.
3. Move pcap sang `Filepcap/processed/` khi xong (giữ nguyên nếu lỗi).

Tham số:
- `--watch-dir <đường_dẫn>` — thư mục theo dõi (mặc định `Filepcap/`).
- `--poll <giây>` — chu kỳ quét chế độ polling (mặc định 5s).
- `--force-polling` — ép dùng polling kể cả khi có watchdog.
- `--process-existing` — xử lý luôn các pcap đang có sẵn lúc khởi động (mặc định bỏ qua, chỉ bắt file mới).

### 2. Chạy thủ công 1 file

```powershell
py -3 auto_pipeline.py D:\...\Filepcap\synf5k.pcap
```

## Ghi chú

- Watcher mặc định **bỏ qua** các pcap có sẵn lúc khởi động, chỉ xử lý file MỚI đi vào. Dùng `--process-existing` nếu muốn xử lý cả file cũ.
- Nếu một filter lỗi, các filter khác vẫn chạy; pcap sẽ **không** bị move sang `processed/` để bạn biết cần xử lý lại.
- Đặt interpreter cụ thể: `set AUTO_PIPELINE_PYTHON=C:\...\python.exe` trước khi chạy.
