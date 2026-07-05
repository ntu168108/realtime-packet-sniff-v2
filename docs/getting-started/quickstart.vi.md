# Hướng dẫn nhanh — realtime-packet-sniff IDS

> Hướng dẫn từng bước để cài đặt và vận hành toàn bộ hệ thống IDS trên một máy chủ Ubuntu mới,  
> từ việc cài phụ thuộc cho đến khi Grafana hiển thị dữ liệu tấn công mạng thời gian thực.

**Hệ điều hành được kiểm thử:** Ubuntu 22.04 / 24.04 LTS (x86-64)  
**Thời gian cài đặt ước tính:** 45 – 90 phút  
**Phiên bản:** v1.0.0

---

## Tổng quan kiến trúc

Hệ thống gồm **5 thành phần** chạy chuỗi nhau:

```
NIC (ens33)
    │ libpcap / scapy
    ▼
[sniff-producer]          ← Python, chạy dưới systemd (root)
    │ ~60s pcap blob
    ▼
[Kafka topic: raw_pcap_segments]   ← Apache Kafka KRaft
    │
    ▼
[ec-consumer]             ← Python, chạy dưới systemd (user thường)
    │ Argus + Zeek → trích xuất đặc trưng UNSW-NB15
    │ auto_pipeline.py → 7 filter + DoS classifier
    ▼
[ClickHouse]              ← database lưu flows đã phân loại
    │
    ▼
[Grafana]                 ← dashboard trực quan hóa tấn công
```

**Luồng dữ liệu chi tiết:**
1. `sniff-producer` bắt gói tin từ NIC, gom ~60 giây, đóng gói thành blob → đẩy lên Kafka.
2. `ec-consumer` đọc blob từ Kafka, giải nén ra file `.pcap` tạm trong `/dev/shm`.
3. `auto_pipeline.py` xử lý file `.pcap` qua 4 bước:
   - **Bước 1/4:** `extractor.py` (Argus + Zeek) → trích đặc trưng UNSW-NB15 ra CSV thô.
   - **Bước 2/4:** `add_features.py` → bổ sung 49 cột đặc trưng DoS.
   - **Bước 3/4:** 7 filter theo họ tấn công → 7 file CSV phân loại riêng.
   - **Bước 4/4:** `dos_classifier.py` → phân loại chi tiết SYN / UDP / ICMP Flood.
4. `ClickHouseSink` ghi kết quả vào 7 bảng `flows_<family>` + bảng audit `pipeline_runs`.
5. Grafana đọc ClickHouse và hiển thị dashboard.

---

## Cài đặt nhanh (capture tool đơn thuần)

Nếu chỉ muốn dùng công cụ bắt gói tin (TUI/daemon/live stream) **không cần** Kafka/ClickHouse/Grafana:

```bash
# Cài đặt 1 lệnh
curl -fsSL https://raw.githubusercontent.com/ntu168108/realtime-packet-sniff-v2/main/install.sh -o /tmp/install.sh && sudo bash /tmp/install.sh --verbose

# Hoặc cài thủ công
git clone https://github.com/ntu168108/realtime-packet-sniff-v2.git
cd realtime-packet-sniff-v2
pip install --break-system-packages .

# Sử dụng
sudo sniff                          # Menu tương tác
sudo sniff -i ens33                 # Bắt gói tin trên ens33
sudo sniff -i ens33 --live | jq .   # Stream NDJSON ra stdout
sudo sniff -i ens33 -d              # Chạy nền (daemon)
sudo sniff --status                 # Xem trạng thái daemon
sudo sniff --stop                   # Dừng daemon
```

---

## Bước tiếp theo

- **Triển khai pipeline IDS đầy đủ** (Kafka + ClickHouse + Grafana + Argus + Zeek) → xem [Triển khai](../operations/deployment.md)
- **Hiểu luồng dữ liệu** → xem [Kiến trúc](../operations/architecture.md)
- **Gặp vấn đề?** → xem [Xử lý sự cố](../operations/troubleshooting.md)
- **Tài liệu tiếng Anh** → dùng language switcher trên thanh trên cùng.