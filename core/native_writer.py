"""Bộ ghi PCAP bằng chứng dùng dumpcap (native, không mất gói khi tải cao).

Vấn đề: đường bắt gói mặc định (Scapy AsyncSniffer -> RingBuffer drop-oldest ->
dispatcher Python ghi pcap) không theo kịp burst tốc độ cao (đo thực tế: mất 60%
gói trong cú POST 100MB) vì mỗi gói phải đi qua callback Python + GIL.

Giải pháp: chạy `dumpcap` (đi kèm Wireshark, dùng libpcap trực tiếp trong C) với
kernel buffer LỚN để ghi file pcap "ground truth" song song. dumpcap không đụng
tới Python nên gần như không drop, giữ trọn bằng chứng ngay cả khi nhánh phân tích
Python có nghẽn.

Cách dùng:
    w = DumpcapWriter(interface="ens19", out_dir="/var/lib/sniff-web/sniff_data",
                      buffer_mb=512, ring_seconds=3600, snaplen=0)
    w.start()
    ...
    print(w.drop_stats())   # {'received': N, 'dropped': M, 'drop_pct': ...}
    w.stop()

Yêu cầu: cài Wireshark/tshark (có `dumpcap`) và cấp quyền bắt gói cho user
(vd trên Debian/Ubuntu: `sudo dpkg-reconfigure wireshark-common` + thêm user vào
nhóm `wireshark`, hoặc `sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)`).
"""
from __future__ import annotations

import logging
import re
import shutil
import signal
import subprocess
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# dumpcap in ra stderr dòng kiểu: "Packets received/dropped on interface 'ens19':
# 126669/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0)" khi kết thúc, và cập nhật
# định kỳ nếu bật -M. Ta parse cặp received/dropped.
_STATS_RE = re.compile(r"received/dropped[^:]*:\s*(\d+)/(\d+)", re.IGNORECASE)


class DumpcapWriter:
    """Ghi pcap bằng chứng qua dumpcap với kernel buffer lớn + rotation.

    Chạy dumpcap như tiến trình con daemon; đọc stderr nền để lấy thống kê
    received/dropped (phơi ra Grafana để phát hiện mất gói mà KHÔNG cần thiết
    bị thứ 3).
    """

    def __init__(
        self,
        interface: str,
        out_dir: str,
        *,
        buffer_mb: int = 512,
        ring_seconds: int = 3600,
        ring_filesize_kb: Optional[int] = 1_048_576,  # 1 GiB
        snaplen: int = 0,                              # 0 = full packet
        bpf_filter: str = "",
        file_prefix: str = "evidence",
        dumpcap_bin: Optional[str] = None,
    ) -> None:
        self.interface = interface
        self.out_dir = Path(out_dir)
        self.buffer_mb = buffer_mb
        self.ring_seconds = ring_seconds
        self.ring_filesize_kb = ring_filesize_kb
        self.snaplen = snaplen
        self.bpf_filter = bpf_filter
        self.file_prefix = file_prefix
        self.dumpcap_bin = dumpcap_bin or shutil.which("dumpcap")

        self._proc: Optional[subprocess.Popen] = None
        self._reader: Optional[threading.Thread] = None
        self._received = 0
        self._dropped = 0
        self._lock = threading.Lock()

    def _build_cmd(self) -> list:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        out_pattern = str(self.out_dir / f"{self.file_prefix}_{self.interface}.pcap")
        cmd = [
            self.dumpcap_bin,
            "-i", self.interface,
            "-B", str(self.buffer_mb),          # kernel capture buffer (MiB) — mấu chốt chống drop
            "-w", out_pattern,
            "-n",                               # ring buffer (multiple files) thay vì 1 file
            "-b", f"duration:{self.ring_seconds}",
            "-s", str(self.snaplen),            # 0 = full snaplen
            "--print",                          # in thống kê định kỳ ra stderr
        ]
        if self.ring_filesize_kb:
            cmd += ["-b", f"filesize:{self.ring_filesize_kb}"]
        if self.bpf_filter:
            cmd += ["-f", self.bpf_filter]      # BPF ở KERNEL (tiết kiệm buffer)
        return cmd

    def start(self) -> None:
        if not self.dumpcap_bin:
            raise RuntimeError(
                "Không tìm thấy 'dumpcap'. Cài Wireshark/tshark và cấp quyền "
                "cap_net_raw cho dumpcap."
            )
        if self._proc is not None:
            return
        cmd = self._build_cmd()
        logger.info("DumpcapWriter start: %s", " ".join(cmd))
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._reader = threading.Thread(
            target=self._read_stderr, name="dumpcap-stats", daemon=True
        )
        self._reader.start()

    def _read_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        for line in self._proc.stderr:
            m = _STATS_RE.search(line)
            if m:
                with self._lock:
                    self._received = int(m.group(1))
                    self._dropped = int(m.group(2))
            else:
                logger.debug("dumpcap: %s", line.rstrip())

    def drop_stats(self) -> dict:
        """Trả về {'received', 'dropped', 'drop_pct'} — đẩy lên Grafana."""
        with self._lock:
            recv, drop = self._received, self._dropped
        pct = (100.0 * drop / recv) if recv else 0.0
        return {"received": recv, "dropped": drop, "drop_pct": round(pct, 3)}

    def stop(self, timeout: float = 5.0) -> None:
        if self._proc is None:
            return
        try:
            self._proc.send_signal(signal.SIGINT)   # dumpcap flush + in stats cuối
            self._proc.wait(timeout=timeout)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass
        finally:
            logger.info("DumpcapWriter stop: %s", self.drop_stats())
            self._proc = None
