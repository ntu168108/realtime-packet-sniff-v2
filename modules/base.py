"""
Base Module - Abstract base class cho analysis modules
- BaseModule: batch analysis (post-rotate, xử lý PCAP file)
- LiveModule: streaming analysis (xử lý packet realtime từ capture engine)
- Detection/Summary: thêm priority/category/alerts cho alerting
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional
import time

logger = logging.getLogger(__name__)


# ---------- Enums cho alerting ----------

class Priority(str, Enum):
    """Mức độ ưu tiên của detection"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    """Phân loại hành vi phát hiện"""
    RECON = "recon"        # Quét / trinh sát
    EXPLOIT = "exploit"    # Khai thác lỗ hổng
    C2 = "c2"              # Command & control beaconing
    EXFIL = "exfil"        # Rò rỉ dữ liệu
    ANOMALY = "anomaly"    # Bất thường chung
    INFO = "info"          # Thông tin thuần


# ---------- Core dataclasses ----------

@dataclass
class Detection:
    """
    Một detection/finding từ module.
    Mở rộng: priority, category, alert_id để phục vụ alerting pipeline.
    """
    stt: int                    # Packet sequence number
    ts_sec: int                 # Timestamp seconds
    label: str                  # Nhãn (vd: "port-scan", "beaconing")
    src: str = ""               # Source address
    dst: str = ""               # Destination address
    sport: int = 0              # Source port
    dport: int = 0              # Destination port
    proto: str = ""             # Protocol

    # Mở rộng cho live + alerting
    priority: str = Priority.MEDIUM.value
    category: str = Category.ANOMALY.value
    alert_id: str = ""          # ID duy nhất, sinh tự động nếu trống

    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Sinh alert_id tự động nếu chưa có
        if not self.alert_id:
            self.alert_id = f"{self.label}-{self.ts_sec}-{self.stt}"

    @property
    def is_alert(self) -> bool:
        """True nếu đây là critical/high -> cần alerting"""
        return self.priority in (Priority.HIGH.value, Priority.CRITICAL.value)

    def to_dict(self) -> dict:
        return {
            "stt": self.stt,
            "ts_sec": self.ts_sec,
            "label": self.label,
            "src": self.src,
            "dst": self.dst,
            "sport": self.sport,
            "dport": self.dport,
            "proto": self.proto,
            "priority": self.priority,
            "category": self.category,
            "alert_id": self.alert_id,
            **self.details
        }

    def to_json_line(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class Summary:
    """
    Tổng kết phân tích cho một pcap / time window.
    Mở rộng: alerts_generated, top_protocols, error_count.
    """
    module_name: str
    interface: str
    time_window: str            # Format: YYYY-MM-DD_HH
    pcap_file: str

    # Stats cơ bản
    total_packets: int = 0
    analyzed_packets: int = 0
    total_hits: int = 0
    alerts_generated: int = 0    # Số detection priority >= high

    # Phân loại
    labels: Dict[str, int] = field(default_factory=dict)
    top_protocols: Dict[str, int] = field(default_factory=dict)

    # Top talkers
    top_sources: List[tuple] = field(default_factory=list)
    top_destinations: List[tuple] = field(default_factory=list)

    # Timing
    start_time: float = 0.0
    end_time: float = 0.0
    duration_sec: float = 0.0

    # Errors
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "module_name": self.module_name,
            "interface": self.interface,
            "time_window": self.time_window,
            "pcap_file": self.pcap_file,
            "total_packets": self.total_packets,
            "analyzed_packets": self.analyzed_packets,
            "total_hits": self.total_hits,
            "alerts_generated": self.alerts_generated,
            "labels": self.labels,
            "top_protocols": self.top_protocols,
            "top_sources": self.top_sources,
            "top_destinations": self.top_destinations,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_sec": self.duration_sec,
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ---------- Read helpers (đối xứng với write_summary/write_detections) ----------

def read_summary(path) -> Summary:
    """
    Đọc lại Summary từ file JSON đã ghi bởi BaseModule.write_summary().

    Args:
        path: đường dẫn tới file {basename}.summary.json

    Returns:
        Summary object dựng lại từ JSON.
    """
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return Summary(**data)


def read_detections(path) -> List[Detection]:
    """
    Đọc lại list Detection từ file JSONL đã ghi bởi BaseModule.write_detections()
    (hoặc write_alerts(), cùng format).

    Lưu ý: Detection.to_dict() flatten `details` vào top-level JSON, nên khi đọc
    ngược lại phải tách field nào thuộc dataclass gốc, field nào thuộc `details`.

    Args:
        path: đường dẫn tới file {basename}.index.jsonl hoặc {basename}.alerts.jsonl

    Returns:
        List các Detection object dựng lại từ JSONL.
    """
    known_fields = {
        "stt", "ts_sec", "label", "src", "dst", "sport", "dport",
        "proto", "priority", "category", "alert_id",
    }
    detections: List[Detection] = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            core = {k: v for k, v in data.items() if k in known_fields}
            details = {k: v for k, v in data.items() if k not in known_fields}
            detections.append(Detection(**core, details=details))
    return detections


# ---------- Base interfaces ----------

class BaseModule(ABC):
    """
    Batch analysis module - xử lý PCAP file sau khi rotator đóng file.
    Implement `name` property + `analyze()` method.

    Phù hợp với:
    - Heavy analysis cần đọc lại nhiều lần (statistics, ML, ...)
    - Stateful detection cần nhìn toàn bộ flow
    - Offline forensic
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Tên module (lowercase, alphanumeric + underscore)"""
        pass

    @property
    def description(self) -> str:
        return "No description"

    @property
    def version(self) -> str:
        return "1.0.0"

    @abstractmethod
    def analyze(
        self,
        pcap_path: str,
        output_dir: str,
        interface: str,
        time_window: str,
    ) -> Summary:
        """
        Phân tích PCAP file, ghi output.

        Args:
            pcap_path: Đường dẫn tới PCAP đã rotate
            output_dir: Thư mục gốc output
            interface: Tên interface
            time_window: Chuỗi YYYY-MM-DD_HH

        Returns:
            Summary object
        """
        pass

    # ---------- Output helpers (giữ nguyên API cũ + thêm write_alert) ----------

    def get_output_dir(self, base_dir: str, time_window: str) -> Path:
        """Tạo base_dir/module_name/YYYY-MM-DD/"""
        date_str = time_window.split('_')[0] if '_' in time_window else time_window
        output_dir = Path(base_dir) / self.name / date_str
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def get_output_basename(self, interface: str, time_window: str) -> str:
        return f"{interface}_{time_window}"

    def write_summary(self, output_dir: Path, basename: str, summary: Summary):
        """Ghi summary JSON"""
        summary_path = output_dir / f"{basename}.summary.json"
        try:
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write(summary.to_json())
            logger.info(f"Wrote summary: {summary_path}")
        except Exception as e:
            logger.error(f"Error writing summary: {e}")

    def write_detections(self, output_dir: Path, basename: str, detections: List[Detection]):
        """Ghi detections JSONL"""
        if not detections:
            return
        index_path = output_dir / f"{basename}.index.jsonl"
        try:
            with open(index_path, 'w', encoding='utf-8') as f:
                for det in detections:
                    f.write(det.to_json_line() + '\n')
            logger.info(f"Wrote {len(detections)} detections: {index_path}")
        except Exception as e:
            logger.error(f"Error writing detections: {e}")

    def write_alerts(self, output_dir: Path, basename: str, detections: List[Detection]):
        """
        Ghi file alerts.jsonl riêng - chỉ chứa detection priority >= high.
        Đây là input cho alerting sinks (webhook/slack/syslog/...).
        """
        alerts = [d for d in detections if d.is_alert]
        if not alerts:
            return
        alerts_path = output_dir / f"{basename}.alerts.jsonl"
        try:
            with open(alerts_path, 'w', encoding='utf-8') as f:
                for det in alerts:
                    f.write(det.to_json_line() + '\n')
            logger.info(f"Wrote {len(alerts)} alerts: {alerts_path}")
        except Exception as e:
            logger.error(f"Error writing alerts: {e}")

    def write_output(
        self,
        output_dir: str,
        interface: str,
        time_window: str,
        summary: Summary,
        detections: List[Detection] = None,
    ):
        """
        Ghi tất cả output:
        - {basename}.summary.json
        - {basename}.index.jsonl (nếu có detections)
        - {basename}.alerts.jsonl (nếu có alerts)
        """
        out_dir = self.get_output_dir(output_dir, time_window)
        basename = self.get_output_basename(interface, time_window)

        self.write_summary(out_dir, basename, summary)
        if detections:
            self.write_detections(out_dir, basename, detections)
            self.write_alerts(out_dir, basename, detections)


class LiveModule(ABC):
    """
    Live/streaming analysis module.
    Nhận packet realtime từ CaptureEngine, trả về Detection ngay lập tức.
    Phù hợp với: low-latency alerting, early warning.

    Module KHÔNG chờ batch - phải trả về trong vài chục ms.
    Backpressure: nếu on_packet() block quá lâu, runner sẽ skip gọi.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Tên module"""
        pass

    @property
    def description(self) -> str:
        return "Live detection module"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def max_latency_ms(self) -> float:
        """Ngưỡng latency - nếu vượt quá, runner sẽ skip packet này"""
        return 50.0

    @abstractmethod
    def on_packet(
        self,
        pkt_info,            # PacketInfo (forward reference - core.decoder.PacketInfo)
        decoded,             # DecodedPacket hoặc None nếu decode fail
    ) -> Optional[Detection]:
        """
        Xử lý một packet realtime.

        Args:
            pkt_info: PacketInfo từ CaptureEngine
            decoded: DecodedPacket (None nếu decode fail)

        Returns:
            Detection nếu phát hiện bất thường, None nếu bình thường.
            Nên return None trong fast path.
        """
        pass

    def on_start(self):
        """Hook khi runner bắt đầu - dùng để init state"""
        pass

    def on_stop(self):
        """Hook khi runner dừng - dùng để flush state"""
        pass

    def health_check(self) -> bool:
        """
        Kiểm tra module còn sống không. Runner dùng để detect crash.
        Mặc định luôn True. Module stateful nên override nếu cần.
        """
        return True
