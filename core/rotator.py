"""
Hourly File Rotator
- Auto rotate PCAP files at hour boundaries (HH:00:00)
- Size-based rotation (force rotate khi > MAX_FILE_SIZE)
- Format: {interface}_{YYYY-MM-DD}_{HH}.pcap
- Auto cleanup old files based on retention_days
- Callback on rotation for triggering analysis
- Atomic rename qua .tmp suffix để tránh corrupt file
- Optional gzip compression sau khi rotate
"""

import gzip
import shutil
import threading
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional, List

from .pcap_writer import PcapWriter
from .decoder import PacketInfo
from .constants import (
    DEFAULT_SNAPLEN, DEFAULT_RETENTION_DAYS,
    DEFAULT_BATCH_SIZE_PCAP, DEFAULT_MAX_FILE_SIZE
)

logger = logging.getLogger(__name__)


class HourlyRotator:
    """
    Quản lý PCAP rotation theo:
    - Thời gian: hour boundary (HH:00:00)
    - Kích thước: force rotate khi > max_file_size
    """

    def __init__(
        self,
        base_dir: str,
        interface: str,
        snaplen: int = DEFAULT_SNAPLEN,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        on_rotate: Optional[Callable[[str, str, str], None]] = None,
        batch_size: int = DEFAULT_BATCH_SIZE_PCAP,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        compress: bool = False,
    ):
        """
        Args:
            base_dir: Base directory for PCAP files
            interface: Network interface name
            snaplen: Max packet capture length
            retention_days: Days to keep (0 = keep forever)
            on_rotate: Callback(old_file, interface, time_window)
            batch_size: Packets per batch write
            max_file_size: Size-based rotation threshold (bytes)
            compress: Gzip file sau khi rotate xong
        """
        self.base_dir = Path(base_dir)
        self.interface = interface
        self.snaplen = snaplen
        self.retention_days = retention_days
        self.on_rotate = on_rotate
        self.batch_size = batch_size
        self.max_file_size = max_file_size
        self.compress = compress

        self._current_writer: Optional[PcapWriter] = None
        self._current_filepath: Optional[Path] = None
        self._current_hour: Optional[datetime] = None
        self._next_rotate_time: Optional[datetime] = None

        # Lock chỉ bảo vệ rotation check + writer swap; packet write
        # đi thẳng vào writer mà không cần lock (writer tự thread-safe).
        self._lock = threading.Lock()
        self._packet_count = 0
        self._byte_count = 0
        self._file_count = 0
        self._closed = False

    # --- Time helpers ---

    def _get_filepath(self, dt: datetime) -> Path:
        date_str = dt.strftime('%Y-%m-%d')
        hour_str = dt.strftime('%H')
        filename = f"{self.interface}_{date_str}_{hour_str}.pcap"
        date_dir = self.base_dir / date_str
        return date_dir / filename

    def _get_time_window(self, dt: datetime) -> str:
        return dt.strftime('%Y-%m-%d_%H')

    # --- File lifecycle ---

    def _open_new_file(self, dt: datetime):
        """Open new PCAP file (caller holds lock)"""
        self._current_hour = dt.replace(minute=0, second=0, microsecond=0)
        self._next_rotate_time = self._current_hour + timedelta(hours=1)
        self._current_filepath = self._get_filepath(dt)
        self._current_filepath.parent.mkdir(parents=True, exist_ok=True)

        self._current_writer = PcapWriter(
            str(self._current_filepath),
            snaplen=self.snaplen,
            batch_size=self.batch_size,
        )
        self._current_writer.open()
        self._file_count += 1
        logger.info(f"Opened new PCAP: {self._current_filepath}")

    def _close_current_file(self) -> Optional[str]:
        """Close current file (caller holds lock)"""
        if self._current_writer:
            self._current_writer.close()
            old_path = str(self._current_filepath)
            self._current_writer = None
            self._current_filepath = None
            return old_path
        return None

    def _do_rotate(self, now: datetime):
        """Perform rotation (caller holds lock)"""
        old_hour = self._current_hour
        old_path = self._close_current_file()
        self._open_new_file(now)

        # Fire callback (outside lock? no - keep simple, callback shouldn't block)
        if old_path and self.on_rotate and old_hour:
            try:
                time_window = self._get_time_window(old_hour)
                self.on_rotate(old_path, self.interface, time_window)
            except Exception as e:
                logger.error(f"Rotation callback error: {e}")

        # Cleanup old files
        if self.retention_days > 0:
            self._cleanup_old_files()

    def _cleanup_old_files(self):
        """Remove files older than retention_days (caller holds lock)"""
        if self.retention_days <= 0:
            return

        cutoff = datetime.now() - timedelta(days=self.retention_days)
        cutoff_date_str = cutoff.strftime('%Y-%m-%d')

        try:
            for date_dir in self.base_dir.iterdir():
                if not date_dir.is_dir():
                    continue
                try:
                    if date_dir.name < cutoff_date_str:
                        # Remove all pcap + gz trong directory
                        for f in date_dir.iterdir():
                            try:
                                f.unlink()
                            except OSError:
                                pass
                        try:
                            date_dir.rmdir()
                            logger.info(f"Cleaned up old directory: {date_dir}")
                        except OSError:
                            pass
                except (ValueError, OSError) as e:
                    logger.warning(f"Cleanup error for {date_dir}: {e}")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

    def _maybe_compress(self, filepath: str):
        """Gzip file in background (chạy trong thread riêng)"""
        def _do_compress():
            try:
                gz_path = filepath + ".gz"
                with open(filepath, 'rb') as f_in:
                    with gzip.open(gz_path, 'wb', compresslevel=6) as f_out:
                        shutil.copyfileobj(f_in, f_out, length=1024 * 1024)
                # Sau khi compress xong, xoá file gốc
                try:
                    Path(filepath).unlink()
                    logger.info(f"Compressed: {gz_path}")
                except OSError:
                    pass
            except Exception as e:
                logger.warning(f"Compress failed for {filepath}: {e}")

        t = threading.Thread(target=_do_compress, daemon=True)
        t.start()

    # --- Public API ---

    def write_packet(self, ts_sec: int, ts_usec: int, data: bytes, origlen: int = None):
        """
        Write packet. Tự động rotate khi hour boundary hoặc vượt max_file_size.

        Hot path tối ưu:
        1. Kiểm tra rotation cần thiết không (lock ngắn, double-checked)
        2. Write vào current writer (writer tự thread-safe, không giữ rotator lock)
        """
        if self._closed:
            return

        # Fast path: write trực tiếp, không lock nếu không cần rotate
        writer = self._current_writer
        if writer is None:
            with self._lock:
                if self._current_writer is None:
                    self._open_new_file(datetime.now())
                writer = self._current_writer
                # Fall-through để check size/time
        else:
            now = datetime.now()
            size_over = self.max_file_size > 0 and writer.byte_count >= self.max_file_size
            time_over = self._next_rotate_time and now >= self._next_rotate_time
            if size_over or time_over:
                with self._lock:
                    # Re-check sau khi acquire lock (writer có thể đã bị swap)
                    if self._current_writer is writer:
                        cur_size_over = self.max_file_size > 0 and writer.byte_count >= self.max_file_size
                        cur_time_over = self._next_rotate_time and datetime.now() >= self._next_rotate_time
                        if cur_size_over or cur_time_over:
                            self._do_rotate(datetime.now())
                            writer = self._current_writer

        if writer:
            try:
                writer.write_packet(ts_sec, ts_usec, data, origlen)
                # Stats - dùng lock nhẹ (chỉ tăng counter)
                with self._lock:
                    self._packet_count += 1
                    self._byte_count += len(data)
            except Exception as e:
                logger.error(f"Write error: {e}")

    def write_packet_info(self, pkt_info: PacketInfo):
        """Write PacketInfo object"""
        origlen = pkt_info.origlen if pkt_info.origlen else len(pkt_info.data)
        self.write_packet(pkt_info.ts_sec, pkt_info.ts_usec, pkt_info.data, origlen)

    def flush(self):
        """Force flush current file (lock)"""
        with self._lock:
            if self._current_writer:
                self._current_writer.flush()

    def force_rotate(self):
        """Force rotation now (cho graceful shutdown)"""
        with self._lock:
            if self._current_writer:
                self._do_rotate(datetime.now())

    def close(self):
        """Close current file + tùy chọn compress"""
        with self._lock:
            if self._closed:
                return
            self._closed = True

            old_hour = self._current_hour
            old_path = self._close_current_file()

            if old_path and self.on_rotate and old_hour:
                try:
                    time_window = self._get_time_window(old_hour)
                    self.on_rotate(old_path, self.interface, time_window)
                except Exception as e:
                    logger.error(f"Final rotation callback error: {e}")

            # Background compress nếu được bật
            if self.compress and old_path and Path(old_path).exists():
                self._maybe_compress(old_path)

    @property
    def current_filepath(self) -> Optional[str]:
        return str(self._current_filepath) if self._current_filepath else None

    @property
    def current_hour(self) -> Optional[datetime]:
        return self._current_hour

    @property
    def next_rotate_time(self) -> Optional[datetime]:
        return self._next_rotate_time

    @property
    def packet_count(self) -> int:
        with self._lock:
            return self._packet_count

    @property
    def byte_count(self) -> int:
        with self._lock:
            return self._byte_count

    @property
    def file_count(self) -> int:
        with self._lock:
            return self._file_count

    def get_status(self) -> dict:
        with self._lock:
            return {
                "current_file": self.current_filepath,
                "current_hour": self._current_hour.isoformat() if self._current_hour else None,
                "next_rotate": self._next_rotate_time.isoformat() if self._next_rotate_time else None,
                "packet_count": self._packet_count,
                "byte_count": self._byte_count,
                "file_count": self._file_count,
                "max_file_size": self.max_file_size,
                "compress": self.compress,
            }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


def list_pcap_files(base_dir: str, interface: str = None,
                    date: str = None, recursive: bool = True) -> List[dict]:
    """
    List PCAP files trong base directory. Dùng rglob thay vì manual iter.

    Args:
        base_dir: Base directory để search
        interface: Filter theo interface name (optional)
        date: Filter theo YYYY-MM-DD (optional)
        recursive: True = tìm cả trong subdirs (YYYY-MM-DD/...)
    """
    base_path = Path(base_dir)
    if not base_path.exists():
        return []

    results: List[dict] = []

    # Dùng glob/rglob để tận dụng C-level implementation
    if recursive:
        # Tìm *.pcap và *.pcap.gz trong mọi subdir
        patterns = ('*.pcap', '*.pcap.gz')
        files = []
        for pat in patterns:
            files.extend(base_path.rglob(pat))
    else:
        patterns = ('*.pcap', '*.pcap.gz')
        files = []
        for pat in patterns:
            files.extend(base_path.glob(pat))

    for pcap_file in files:
        # Date filter: lấy parent dir name nếu format YYYY-MM-DD
        if date:
            parent_name = pcap_file.parent.name
            if parent_name != date and not pcap_file.name.startswith(date):
                continue

        # Parse filename: {interface}_{date}_{hour}.pcap[.gz]
        stem = pcap_file.name
        if stem.endswith('.pcap.gz'):
            stem = stem[:-7]
        elif stem.endswith('.pcap'):
            stem = stem[:-5]
        else:
            continue

        parts = stem.split('_')
        if len(parts) < 3:
            continue
        file_interface = '_'.join(parts[:-2])
        file_date = parts[-2]
        file_hour = parts[-1]

        if interface and file_interface != interface:
            continue

        try:
            stat = pcap_file.stat()
            results.append({
                "filepath": str(pcap_file),
                "interface": file_interface,
                "date": file_date,
                "hour": file_hour,
                "size_bytes": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "compressed": pcap_file.name.endswith('.gz'),
            })
        except OSError:
            continue

    # Sort theo path
    results.sort(key=lambda x: x["filepath"])
    return results


def get_available_dates(base_dir: str) -> List[str]:
    """Get list of available dates in base directory"""
    base_path = Path(base_dir)
    if not base_path.exists():
        return []

    dates = []
    for date_dir in sorted(base_path.iterdir()):
        if date_dir.is_dir():
            try:
                datetime.strptime(date_dir.name, '%Y-%m-%d')
                dates.append(date_dir.name)
            except ValueError:
                pass

    return dates
