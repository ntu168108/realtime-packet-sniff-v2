# Hệ thống tự động trích xuất & phân loại đặc trưng lưu lượng mạng (UNSW-NB15)

Dự án đọc file **PCAP**, trích xuất bộ đặc trưng chuẩn **UNSW-NB15** (40+ trường),
rồi lọc thành các tập đặc trưng chuyên biệt cho **7 loại tấn công**. Toàn bộ luồng
chạy **tự động**: chỉ cần thả file `.pcap` vào thư mục đầu vào và chờ CSV kết quả.

## 🔄 Luồng dữ liệu

```
file.pcap  (thả vào Filepcap/)
   │
   ▼
MODULE_TRICHXUAT
   ├─ extractor.py     →  CSV/CSV_Full_feature/<base>_raw.csv        (Argus + Zeek, gộp 5-tuple)
   └─ add_features.py  →  CSV/CSV_Full_feature/<base>_dos_features.csv (50 cột: rename + rule-based + sliding window)
   │
   ▼
MODULE_PHANLOAI  (7 filter, chế độ file đơn lẻ)
   ├─ generic_feature_filter.py        →  CSV/Filter_Generic_feature/
   ├─ dos_feature_filter.py            →  CSV/Filter_DoS_feature/
   │    └─ dos_classifier.py           →  Phân loại DoS chi tiết (SYN/UDP/ICMP) và xuất cảnh báo
   ├─ exploits_feature_filter.py       →  CSV/Filter_Exploits_feature/
   ├─ fuzzers_feature_filter.py        →  CSV/Filter_Fuzzers_feature/
   ├─ analysis_feature_filter.py       →  CSV/Filter_Analysis_feature/
   ├─ reconnaissance_feature_filter.py →  CSV/Filter_Reconnaissance_feature/
   └─ shellcode_feature_filter.py      →  CSV/Filter_Shellcode_feature/
   │
   ▼
MODULE_AUTO  (điều phối + theo dõi thư mục)
   ├─ auto_pipeline.py  →  chạy full pipeline cho 1 pcap
   └─ pcap_watcher.py   →  theo dõi Filepcap/, tự kích hoạt khi có pcap mới
```

## 📁 Cấu trúc thư mục

> [!IMPORTANT]
> **Code** nằm trong `EaF/` (workspace), còn **dữ liệu** (`CSV/`, `Filepcap/`) nằm
> ở thư mục cha `Python/`. Các script tự suy ra đường dẫn này, không cần chỉnh tay.

```
Python\
├── EaF\                         ← THƯ MỤC CODE (workspace)
│   ├── README.md                ← file này
│   ├── MODULE_TRICHXUAT\        ← trích xuất đặc trưng từ PCAP
│   │   ├── extractor.py
│   │   ├── add_features.py
│   │   ├── config.py            ← cấu hình đường dẫn + tool WSL
│   │   └── ...
│   ├── MODULE_PHANLOAI\         ← 7 filter phân loại và engine phân loại
│   │   ├── generic_feature_filter.py
│   │   ├── dos_feature_filter.py
│   │   ├── dos_classifier.py    ← Engine phân loại tập dữ liệu DoS
│   │   └── ... (5 filter còn lại)
│   └── MODULE_AUTO\             ← tự động hóa
│       ├── auto_pipeline.py
│       ├── pcap_watcher.py
│       └── README_AUTO.md
│
├── CSV\                         ← THƯ MỤC OUTPUT
│   ├── CSV_Full_feature\        ← CSV đầy đủ đặc trưng (trung gian)
│   ├── Filter_Generic_feature\
│   ├── Filter_DoS_feature\
│   ├── Filter_Exploits_feature\
│   ├── Filter_Fuzzers_feature\
│   ├── Filter_Analysis_feature\
│   ├── Filter_Reconnaissance_feature\
│   └── Filter_Shellcode_feature\
│
└── Filepcap\                    ← THƯ MỤC INPUT (thả .pcap vào đây)
    └── processed\               ← pcap đã xử lý tự move vào đây
```

## 🛠️ Yêu cầu hệ thống

- **Python 3.8+** có `pandas` và `numpy`.
  Trên máy này: `py -3` trỏ tới `Python314` (đã có pandas 3.0.3). `auto_pipeline.py`
  tự dò interpreter có pandas, nên không cần lo chọn nhầm bản Python.
- **WSL** (Windows) với **Argus** (`argus`, `ra`) và **Zeek 8.0+** — chỉ cần cho
  bước trích xuất (`extractor.py`). Đường dẫn tool cấu hình trong
  [config.py](MODULE_TRICHXUAT/config.py).
- (Tùy chọn) `watchdog` để watcher phản ứng tức thì:
  ```powershell
  py -3 -m pip install watchdog
  ```
  Không cài vẫn chạy được — watcher tự fallback sang chế độ polling.

## 🚀 Cách dùng

### Cách 1 — Tự động (khuyên dùng)

Mở 1 terminal, chạy watcher rồi để yên:

```powershell
py -3 D:\1LearnandStudy\Program_Language\Python\EaF\MODULE_AUTO\pcap_watcher.py
```

Sau đó **thả file `.pcap` vào `Python\Filepcap\`** → pipeline tự kích hoạt, sinh CSV
ở các thư mục `CSV\Filter_*`, rồi move pcap sang `Filepcap\processed\`.

Tùy chọn watcher:
- `--process-existing` : xử lý luôn các pcap đã có sẵn trong thư mục khi khởi động.
- `--force-polling`    : ép dùng polling kể cả khi đã cài watchdog.
- `--poll N`           : chu kỳ quét polling (giây, mặc định 5).
- `--watch-dir <path>` : đổi thư mục theo dõi.

### Cách 2 — Chạy thủ công 1 file pcap

```powershell
py -3 D:\1LearnandStudy\Program_Language\Python\EaF\MODULE_AUTO\auto_pipeline.py <đường_dẫn.pcap>
```

### Cách 3 — Chạy lẻ từng bước

```powershell
# Bước 1: trích xuất thô
py -3 EaF\MODULE_TRICHXUAT\extractor.py Filepcap\synf5k.pcap

# Bước 2: bổ sung đặc trưng
py -3 EaF\MODULE_TRICHXUAT\add_features.py CSV\CSV_Full_feature\synf5k_raw.csv

# Bước 3: chạy 1 filter (hoặc cả thư mục)
py -3 EaF\MODULE_PHANLOAI\dos_feature_filter.py CSV\CSV_Full_feature\synf5k_dos_features.csv

# Bước 4: chấm điểm rủi ro & phân loại DoS chuyên sâu (chỉ dành cho luồng DoS)
# Lưu ý: Nếu truyền file CSV thô, dos_classifier.py sẽ tự động chạy dos_feature_filter.py trước.
py -3 EaF\MODULE_PHANLOAI\dos_classifier.py --csv CSV\CSV_Full_feature\synf5k_dos_features.csv
```

## 📝 Ghi chú

> [!NOTE]
> Mỗi filter giữ một tập cột khác nhau theo nghiên cứu cho từng loại tấn công.
> File trung gian `<base>_dos_features.csv` (50 cột) là đầu vào chung cho cả 7 filter.

> [!WARNING]
> Bước trích xuất phụ thuộc WSL + Argus + Zeek. Nếu môi trường chưa sẵn sàng,
> `extractor.py` sẽ lỗi và pipeline dừng ở bước 1 (các pcap khác vẫn xử lý tiếp).

## 📌 Tài liệu tham khảo

- Moustafa, Nour, and Jill Slay. "UNSW-NB15: a comprehensive data set for network
  intrusion detection systems." *MilCIS*, 2015. IEEE.
- Moustafa, Nour, and Jill Slay. "The evaluation of Network Anomaly Detection
  Systems: Statistical analysis of the UNSW-NB15 data set and the comparison with
  the KDD99 data set." *Information Security Journal* 25.1-3 (2016): 18-31.
- Moustafa, Nour Abdelhameed. *Designing an online and reliable statistical anomaly
  detection framework for dealing with large high-speed network traffic*. PhD thesis,
  UNSW, 2017.
