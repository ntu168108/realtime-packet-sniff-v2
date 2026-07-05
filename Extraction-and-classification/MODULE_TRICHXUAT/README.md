## 📌 Tác giả và Tài liệu tham khảo (Authors & References)

* Moustafa, Nour, and Jill Slay. "UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)." *Military Communications and Information Systems Conference (MilCIS)*, 2015. IEEE, 2015.
* Moustafa, Nour, and Jill Slay. "The evaluation of Network Anomaly Detection Systems: Statistical analysis of the UNSW-NB15 data set and the comparison with the KDD99 data set." *Information Security Journal: A Global Perspective* 25.1-3 (2016): 18-31.
* Moustafa, Nour Abdelhameed. *Designing an online and reliable statistical anomaly detection framework for dealing with large high-speed network traffic*. PhD thesis, University of New South Wales, 2017.

# Hướng dẫn chạy dự án trích xuất đặc trưng PCAP (UNSW-NB15 + MAC)
Dự án này gồm 2 công đoạn chính:
1. **Trích xuất và Gộp dữ liệu (Argus + Zeek)**: Đọc file PCAP, trích xuất đặc trưng mạng và gộp lại dựa trên 5-tuple.
2. **Bổ sung đặc trưng nâng cao (Feature Engineering)**: Đổi tên trường, áp dụng các luật logic tĩnh (Rule-based) và tính toán 7 đặc trưng Sliding Window (look-back 100 dòng).

---

## 🛠️ Yêu cầu hệ thống (Prerequisites)
Chương trình yêu cầu chạy trên môi trường Linux (hoặc WSL trên Windows) và đã cài đặt các công cụ sau:
* **Python 3.8+** (cần cài đặt thư viện `pandas` và `numpy`).
* **Argus & Client (ra)**: Để trích xuất thông tin flow.
* **Zeek 8.0+**: Để trích xuất thông tin giao thức HTTP/FTP và địa chỉ MAC.

Kiểm tra sự sẵn sàng của môi trường bằng lệnh:
```bash
bash check_tools.sh
```

---

## 🚀 Cách chạy dự án (End-to-End)

Chạy 2 bước sau theo thứ tự:

### Bước 1: Trích xuất đặc trưng từ file PCAP
Chạy pipeline chính để trích xuất và gộp dữ liệu từ Argus và Zeek:
```bash
python3 extractor.py <đường_dẫn_file_pcap>
```
* **Ví dụ**: `python3 extractor.py synf5k.pcap`
* **Kết quả**:
  * **Tệp CSV thô mặc định**: `<base_name>_raw.csv` (ví dụ: `synf5k_raw.csv`) được sinh ra trong thư mục kết quả mặc định (`D:\1LearnandStudy\Program_Language\Python\CSV\CSV_Full_feature`).
  * **Cơ chế Smart Cleanup (Bảo tồn http.log)**: Khi chạy dọn dẹp mặc định, tệp `http.log` của Zeek nếu tồn tại sẽ tự động được sao chép ra thư mục đích dưới dạng `<base_name>_http.log` (ví dụ: `synf5k_http.log`) để phục vụ truy ngược User-Agent cho module Classifier sau này.
* **Các tham số tùy chọn khác**:
  * `-o <tên_file>`: Chỉ định tên tệp CSV đầu ra cụ thể.
  * `--output-dir <thư_mục>`: Chỉ định thư mục lưu file kết quả.
  * `--no-cleanup`: Giữ lại các tệp log và CSV tạm thời (`zeek_logs/`, `argus_temp.csv`, `zeek_temp.csv`) để kiểm tra thủ công.
  * `-v` hoặc `--verbose`: Bật log chi tiết debug.

### Bước 2: Bổ sung đặc trưng nâng cao (UNSW-NB15 Features)
Sử dụng script xử lý sau trích xuất để thực hiện đổi tên trường, tạo đặc trưng rule-based và cửa sổ trượt:
```bash
python3 add_features.py <đường_dẫn_file_csv_bước_1>
```
* **Ví dụ**:
  ```bash
  python3 add_features.py synf5k_raw.csv
  ```
* **Kết quả**:
  * **Tên file mặc định**: `<base_name>_dos_features.csv` (ví dụ: `synf5k_dos_features.csv`) được lưu tự động tại cùng thư mục chứa tệp CSV đầu vào. Tệp này chứa 49 cột dữ liệu hoàn chỉnh, sẵn sàng làm đầu vào cho việc lọc và phân loại DoS.
* **Các tham số tùy chọn khác**:
  * `-o <đường_dẫn_file>`: Chỉ định đường dẫn tệp đầu ra cụ thể.
