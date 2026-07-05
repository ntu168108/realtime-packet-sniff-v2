"""
Dummy Analysis Module - Module demo đầy đủ
- Batch mode: phân tích PCAP rotated file
- Live mode: stream từng packet qua detector
- Detection thật:
  * Port scan: sliding window 5s, threshold configurable
  * DNS tunneling: entropy subdomain + length
  * Beaconing: regular interval (Jitter thấp)
- Auto flush detections theo batch size + timeout
"""

import math
import time
import logging
from collections import Counter, deque, defaultdict
from typing import List, Dict, Optional, Deque, Tuple

from ..base import (
    BaseModule, LiveModule, Summary, Detection,
    Priority, Category,
)
from core.pcap_writer import PcapReader
from core.decoder import decode_packet

logger = logging.getLogger(__name__)


def _detect_port_scan(ts, pkt_info, decoded, port_hits, *,
                     window_sec, threshold, alerted_keys, label_suffix):
    if not (decoded.src_addr and decoded.dst_port and decoded.protocol_name == "TCP"):
        return None
    dq = port_hits[decoded.src_addr]
    dq.append((ts, decoded.dst_port))
    while dq and ts - dq[0][0] > window_sec:
        dq.popleft()
    unique_ports = {p for _, p in dq}
    if len(unique_ports) < threshold:
        return None
    label = "port-scan" + label_suffix
    key = (decoded.src_addr, label)
    if key in alerted_keys:
        return None
    alerted_keys.add(key)
    return Detection(
        stt=pkt_info.stt, ts_sec=pkt_info.ts_sec, label=label,
        src=decoded.src_addr, dst="multiple", dport=len(unique_ports),
        proto="TCP", priority=Priority.HIGH.value,
        category=Category.RECON.value,
        details={"unique_ports": len(unique_ports),
                 "window_sec": window_sec, "threshold": threshold},
    )


def _detect_dns_tunnel(pkt_info, decoded, *,
                       entropy_threshold, subdomain_max,
                       alerted_keys, label_suffix):
    if not (decoded.protocol_name == "DNS" and decoded.dst_port == 53):
        return None
    qname = DummyModule._extract_dns_qname(decoded)
    if not (qname and decoded.src_addr):
        return None
    first_label = qname.split('.')[0]
    entropy = DummyModule._shannon_entropy(first_label)
    if entropy < entropy_threshold and len(first_label) < subdomain_max:
        return None
    label = "dns-tunnel" + label_suffix
    key = (decoded.src_addr, label)
    if key in alerted_keys:
        return None
    alerted_keys.add(key)
    return Detection(
        stt=pkt_info.stt, ts_sec=pkt_info.ts_sec, label=label,
        src=decoded.src_addr, dport=53, proto="DNS",
        priority=Priority.HIGH.value, category=Category.EXFIL.value,
        details={"qname": qname, "entropy": round(entropy, 2),
                 "label_len": len(first_label)},
    )


def _detect_beaconing(ts, pkt_info, decoded, beacon_intervals, *,
                      jitter_ratio, min_packets,
                      alerted_keys, label_suffix):
    if not (decoded.dst_addr and decoded.protocol_name in ("TCP", "UDP", "HTTPS", "HTTP")):
        return None
    dq = beacon_intervals[decoded.dst_addr]
    dq.append(ts)
    if len(dq) < min_packets:
        return None
    intervals = [dq[i] - dq[i - 1] for i in range(1, len(dq))]
    intervals = [x for x in intervals if x > 0]
    if len(intervals) < min_packets - 1:
        return None
    mean = sum(intervals) / len(intervals)
    if mean <= 0:
        return None
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    jitter = math.sqrt(variance) / mean
    if jitter > jitter_ratio or mean >= 300:
        return None
    label = "beaconing" + label_suffix
    key = (decoded.dst_addr, label)
    if key in alerted_keys:
        return None
    alerted_keys.add(key)
    return Detection(
        stt=pkt_info.stt, ts_sec=pkt_info.ts_sec, label=label,
        dst=decoded.dst_addr, proto=decoded.protocol_name,
        priority=Priority.CRITICAL.value, category=Category.C2.value,
        details={"interval_mean_sec": round(mean, 2),
                 "jitter_ratio": round(jitter, 4),
                 "samples": len(intervals)},
    )


# ============================================================
                    # BATCH MODULE
# ============================================================

class DummyModule(BaseModule):
    """
    Batch module demo:
    - Protocol distribution
    - Top talkers
    - Port scan (sliding window 5s, configurable threshold)
    - DNS tunneling (entropy + long subdomain)
    - Beaconing detection
    """

    def __init__(
        self,
        port_scan_threshold: int = 20,
        port_scan_window_sec: float = 5.0,
        dns_entropy_threshold: float = 4.0,
        dns_subdomain_max: int = 30,
        beacon_jitter_ratio: float = 0.15,
        beacon_min_packets: int = 6,
    ):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window_sec = port_scan_window_sec
        self.dns_entropy_threshold = dns_entropy_threshold
        self.dns_subdomain_max = dns_subdomain_max
        self.beacon_jitter_ratio = beacon_jitter_ratio
        self.beacon_min_packets = beacon_min_packets

    @property
    def name(self) -> str:
        return "dummy"

    @property
    def description(self) -> str:
        return "Demo module: stats + port-scan + dns-tunnel + beaconing"

    @property
    def version(self) -> str:
        return "2.0.0"

    def analyze(
        self,
        pcap_path: str,
        output_dir: str,
        interface: str,
        time_window: str,
    ) -> Summary:
        start_time = time.time()

        # Sliding window port hits: src_ip -> deque[(ts, dport)]
        port_hits: Dict[str, Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=10000)
        )
        # Beacon: dst_ip -> deque[ts]
        beacon_intervals: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=64)
        )

        proto_counts: Counter = Counter()
        src_counts: Counter = Counter()
        dst_counts: Counter = Counter()

        detections: List[Detection] = []
        total_packets = 0
        analyzed_packets = 0
        errors: List[str] = []
        alerted_keys: set = set()  # dedup: (src, label) -> chỉ fire 1 lần

        try:
            with PcapReader(pcap_path) as reader:
                for pkt_info in reader:
                    total_packets += 1
                    try:
                        decoded = decode_packet(pkt_info.data)
                        analyzed_packets += 1
                        ts = pkt_info.ts_sec + (pkt_info.ts_usec or 0) / 1e6

                        proto = decoded.protocol_name or "UNKNOWN"
                        proto_counts[proto] += 1
                        if decoded.src_addr:
                            src_counts[decoded.src_addr] += 1
                        if decoded.dst_addr:
                            dst_counts[decoded.dst_addr] += 1

                        # ----- Port scan (sliding window) -----
                        det = _detect_port_scan(
                            ts, pkt_info, decoded, port_hits,
                            window_sec=self.port_scan_window_sec,
                            threshold=self.port_scan_threshold,
                            alerted_keys=alerted_keys,
                            label_suffix="",
                        )
                        if det is not None:
                            detections.append(det)

                        # ----- DNS tunneling (qname từ DNS payload) -----
                        det = _detect_dns_tunnel(
                            pkt_info, decoded,
                            entropy_threshold=self.dns_entropy_threshold,
                            subdomain_max=self.dns_subdomain_max,
                            alerted_keys=alerted_keys,
                            label_suffix="",
                        )
                        if det is not None:
                            detections.append(det)

                        # ----- Beaconing (regular interval) -----
                        det = _detect_beaconing(
                            ts, pkt_info, decoded, beacon_intervals,
                            jitter_ratio=self.beacon_jitter_ratio,
                            min_packets=self.beacon_min_packets,
                            alerted_keys=alerted_keys,
                            label_suffix="",
                        )
                        if det is not None:
                            detections.append(det)

                    except Exception as e:
                        if len(errors) < 10:
                            errors.append(f"Packet {pkt_info.stt}: {str(e)}")
        except Exception as e:
            logger.error(f"Error reading PCAP: {e}")
            errors.append(f"PCAP read error: {str(e)}")

        end_time = time.time()
        alerts_count = sum(1 for d in detections if d.is_alert)

        summary = Summary(
            module_name=self.name,
            interface=interface,
            time_window=time_window,
            pcap_file=pcap_path,
            total_packets=total_packets,
            analyzed_packets=analyzed_packets,
            total_hits=len(detections),
            alerts_generated=alerts_count,
            labels={
                "port-scan": sum(1 for d in detections if d.label == "port-scan"),
                "dns-tunnel": sum(1 for d in detections if d.label == "dns-tunnel"),
                "beaconing": sum(1 for d in detections if d.label == "beaconing"),
            },
            top_protocols=dict(proto_counts.most_common(10)),
            top_sources=src_counts.most_common(10),
            top_destinations=dst_counts.most_common(10),
            start_time=start_time,
            end_time=end_time,
            duration_sec=end_time - start_time,
            errors=errors,
        )
        # Lưu cả labels protocol vào summary để backward-compat
        summary.labels.update({
            f"proto_{k}": v for k, v in proto_counts.most_common(10)
        })

        self.write_output(
            output_dir=output_dir,
            interface=interface,
            time_window=time_window,
            summary=summary,
            detections=detections,
        )
        return summary

    # ----- helpers -----

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Entropy Shannon của 1 string"""
        if not s:
            return 0.0
        freq: Counter = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @staticmethod
    def _extract_dns_qname(decoded) -> Optional[str]:
        """
        Trích qname từ DNS payload nếu có.
        decoded.info_str có thể chứa hint, fallback parse payload.
        """
        try:
            # Thử dùng info_str trước (format: "... DNS ...")
            # Rồi parse raw payload: bỏ DNS header 12 bytes, rồi đọc labels
            payload = decoded.payload
            if not payload or len(payload) < 12:
                return None
            # Skip 12-byte header
            labels = []
            i = 12
            while i < len(payload) and payload[i] != 0:
                length = payload[i]
                i += 1
                if length & 0xC0:  # pointer
                    break
                if i + length > len(payload):
                    break
                try:
                    label = payload[i:i+length].decode('ascii', errors='ignore')
                    labels.append(label)
                    i += length
                except Exception:
                    break
            return '.'.join(labels) if labels else None
        except Exception:
            return None


# ============================================================
                    # LIVE MODULE
# ============================================================

class DummyLiveModule(LiveModule):
    """
    Live module demo - dùng cùng detectors nhưng stream-based.
    State nằm trong instance, không persist giữa các lần restart.
    Flush detection định kỳ (mỗi N packet hoặc M giây).
    """

    def __init__(
        self,
        port_scan_threshold: int = 15,
        port_scan_window_sec: float = 5.0,
        dns_entropy_threshold: float = 4.0,
        dns_subdomain_max: int = 30,
        beacon_jitter_ratio: float = 0.15,
        beacon_min_packets: int = 5,
        flush_interval_sec: float = 5.0,
        on_flush: Optional[callable] = None,
    ):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window_sec = port_scan_window_sec
        self.dns_entropy_threshold = dns_entropy_threshold
        self.dns_subdomain_max = dns_subdomain_max
        self.beacon_jitter_ratio = beacon_jitter_ratio
        self.beacon_min_packets = beacon_min_packets
        self.flush_interval_sec = flush_interval_sec
        self._on_flush = on_flush  # callback để runner emit alert

        # Sliding window state
        self._port_hits: Dict[str, Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=5000)
        )
        self._beacon_intervals: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=32)
        )
        self._alerted_keys: set = set()
        self._last_flush = time.time()

    @property
    def name(self) -> str:
        return "dummy-live"

    @property
    def description(self) -> str:
        return "Live detector: port-scan + dns-tunnel + beaconing"

    @property
    def version(self) -> str:
        return "2.0.0"

    @property
    def max_latency_ms(self) -> float:
        # Live cần nhanh - nếu vượt thì skip packet
        return 10.0

    def on_start(self):
        logger.info(f"{self.name} started")
        self._last_flush = time.time()

    def on_stop(self):
        logger.info(f"{self.name} stopped")

    def on_packet(self, pkt_info, decoded) -> Optional[Detection]:
        if decoded is None:
            return None
        ts = pkt_info.ts_sec + (pkt_info.ts_usec or 0) / 1e6

        det: Optional[Detection] = None

        # Port scan (TCP)
        det = _detect_port_scan(
            ts, pkt_info, decoded, self._port_hits,
            window_sec=self.port_scan_window_sec,
            threshold=self.port_scan_threshold,
            alerted_keys=self._alerted_keys,
            label_suffix="-live",
        )

        # DNS tunneling (only if port-scan guard didn't match)
        if det is None:
            det = _detect_dns_tunnel(
                pkt_info, decoded,
                entropy_threshold=self.dns_entropy_threshold,
                subdomain_max=self.dns_subdomain_max,
                alerted_keys=self._alerted_keys,
                label_suffix="-live",
            )

        # Beaconing runs always (state update); only sets det if no other did
        beacon_det = _detect_beaconing(
            ts, pkt_info, decoded, self._beacon_intervals,
            jitter_ratio=self.beacon_jitter_ratio,
            min_packets=self.beacon_min_packets,
            alerted_keys=self._alerted_keys,
            label_suffix="-live",
        )
        if det is None:
            det = beacon_det

        if det and det.is_alert and self._on_flush:
            try:
                self._on_flush(det)
            except Exception:
                pass

        # Periodic flush state để tránh alerted_keys phình to
        if ts - self._last_flush > self.flush_interval_sec:
            self._alerted_keys.clear()
            self._last_flush = ts

        return det

    def health_check(self) -> bool:
        # State quá to -> suspect memory leak
        return len(self._alerted_keys) < 100_000


# For auto-discovery: phải export cả 2
__all__ = ['DummyModule', 'DummyLiveModule']
