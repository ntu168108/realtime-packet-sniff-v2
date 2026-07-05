"""
PCAP File Writer/Reader
- Standard libpcap format
- Batched writes for performance
- Thread-safe operations
- Direct os.write() bypass Python buffering cho high-throughput
- os.fsync mỗi batch chống mất data khi crash
"""

import os
import struct
import threading
import time
from pathlib import Path
from typing import Iterator, Optional
from dataclasses import dataclass

from .constants import (
    PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
    PCAP_LINKTYPE_ETHERNET, DEFAULT_SNAPLEN, DEFAULT_BATCH_SIZE_PCAP
)
from .decoder import PacketInfo


@dataclass
class PcapGlobalHeader:
    """PCAP file global header (24 bytes)"""
    magic: int = PCAP_MAGIC
    version_major: int = PCAP_VERSION_MAJOR
    version_minor: int = PCAP_VERSION_MINOR
    thiszone: int = 0           # GMT offset (always 0)
    sigfigs: int = 0            # Timestamp accuracy
    snaplen: int = DEFAULT_SNAPLEN
    linktype: int = PCAP_LINKTYPE_ETHERNET

    def to_bytes(self) -> bytes:
        return struct.pack(
            '<IHHIIII',
            self.magic,
            self.version_major,
            self.version_minor,
            self.thiszone,
            self.sigfigs,
            self.snaplen,
            self.linktype
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'PcapGlobalHeader':
        if len(data) < 24:
            raise ValueError("Invalid PCAP header: too short")

        magic = struct.unpack('<I', data[0:4])[0]

        # Check endianness
        if magic == 0xa1b2c3d4:
            fmt = '<'  # Little endian
        elif magic == 0xd4c3b2a1:
            fmt = '>'  # Big endian
        else:
            raise ValueError(f"Invalid PCAP magic: 0x{magic:08x}")

        values = struct.unpack(f'{fmt}IHHIIII', data[:24])
        return cls(
            magic=values[0],
            version_major=values[1],
            version_minor=values[2],
            thiszone=values[3],
            sigfigs=values[4],
            snaplen=values[5],
            linktype=values[6]
        )


@dataclass
class PcapPacketHeader:
    """PCAP packet header (16 bytes)"""
    ts_sec: int
    ts_usec: int
    caplen: int
    origlen: int

    def to_bytes(self) -> bytes:
        return struct.pack('<IIII', self.ts_sec, self.ts_usec, self.caplen, self.origlen)

    @classmethod
    def from_bytes(cls, data: bytes, big_endian: bool = False) -> 'PcapPacketHeader':
        fmt = '>IIII' if big_endian else '<IIII'
        values = struct.unpack(fmt, data[:16])
        return cls(
            ts_sec=values[0],
            ts_usec=values[1],
            caplen=values[2],
            origlen=values[3]
        )


# Size of a PCAP packet header on disk (16 bytes) - pre-computed for hot loop
_PKT_HDR_SIZE = 16


class PcapWriter:
    """
    PCAP file writer với batched writes + os.fsync mỗi batch.
    Thread-safe cho multi-threaded capture.

    Hot path:
    - write_packet(): acquire lock ngắn, extend buffer, release.
    - Khi buffer >= batch_size thì flush (cùng lock) bằng os.write() trực tiếp.
    - os.fsync() mỗi batch để chống mất data khi crash (optional).
    """

    def __init__(self, filepath: str, snaplen: int = DEFAULT_SNAPLEN,
                 batch_size: int = DEFAULT_BATCH_SIZE_PCAP,
                 linktype: int = PCAP_LINKTYPE_ETHERNET,
                 fsync: bool = True,
                 fsync_interval: float = 1.0):
        """
        Args:
            filepath: Output .pcap file path
            snaplen: Max bytes per packet
            batch_size: Flush sau N packets
            linktype: PCAP linktype (default Ethernet)
            fsync: Gọi os.fsync() sau mỗi batch (an toàn nhưng chậm hơn)
            fsync_interval: Minimum seconds giữa 2 fsync calls (rate limit)
        """
        self.filepath = Path(filepath)
        self.snaplen = snaplen
        self.batch_size = max(1, batch_size)
        self.linktype = linktype
        self.fsync_enabled = fsync
        self.fsync_interval = fsync_interval

        # File descriptor (None nếu chưa open)
        self._fd: Optional[int] = None
        # Buffer bytearray để batch trước khi ghi
        self._buffer = bytearray()
        self._packet_count = 0
        self._byte_count = 0
        self._pending_packets = 0
        self._lock = threading.Lock()
        self._closed = False
        self._last_fsync_ts: float = 0.0

    def open(self):
        """Open file (atomic qua .tmp) và write global header"""
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        # Write tạm vào .tmp rồi rename - tránh corrupt file khi crash
        tmp_path = str(self.filepath) + ".tmp"
        self._fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)

        # Write global header
        header = PcapGlobalHeader(snaplen=self.snaplen, linktype=self.linktype)
        os.write(self._fd, header.to_bytes())
        # Atomic rename để user thấy file hợp lệ
        os.replace(tmp_path, self.filepath)

    def write_packet(self, ts_sec: int, ts_usec: int, data: bytes, origlen: int = None):
        """
        Write a packet vào buffer. Flush khi batch_size reached.
        Hot path: lock ngắn + buffer extend.
        """
        if self._closed or self._fd is None:
            return

        if origlen is None:
            origlen = len(data)

        # Truncate nếu packet > snaplen
        caplen = min(len(data), self.snaplen)
        captured_data = data[:caplen]

        # Build packet header inline (16 bytes) - tránh allocate PcapPacketHeader
        pkt_hdr = struct.pack('<IIII', ts_sec, ts_usec, caplen, origlen)

        with self._lock:
            # Add to buffer
            self._buffer.extend(pkt_hdr)
            self._buffer.extend(captured_data)
            self._pending_packets += 1
            self._packet_count += 1
            self._byte_count += caplen

            # Flush if batch reached
            if self._pending_packets >= self.batch_size:
                self._flush_buffer()

    def write_packet_info(self, pkt_info: PacketInfo):
        """Write PacketInfo object"""
        origlen = pkt_info.origlen if pkt_info.origlen else len(pkt_info.data)
        self.write_packet(pkt_info.ts_sec, pkt_info.ts_usec, pkt_info.data, origlen)

    def _flush_buffer(self):
        """
        Flush buffer ra disk qua os.write().
        MUST hold self._lock.

        Trả về True nếu đã ghi, False nếu buffer rỗng.
        """
        if not self._buffer or self._fd is None:
            return False
        # os.write nhận memoryview để tránh copy
        try:
            os.write(self._fd, memoryview(self._buffer))
        except (OSError, ValueError):
            # File descriptor có thể đã đóng
            self._buffer.clear()
            self._pending_packets = 0
            return False
        self._buffer.clear()
        self._pending_packets = 0

        # os.fsync mỗi batch (rate-limited)
        if self.fsync_enabled:
            now = time.monotonic()
            if now - self._last_fsync_ts >= self.fsync_interval:
                try:
                    os.fsync(self._fd)
                except OSError:
                    pass
                self._last_fsync_ts = now
        return True

    def flush(self):
        """
        Force flush buffer ra disk.

        NOTE: Hàm này acquire lock; nếu caller đã giữ lock thì dùng _flush_buffer()
        để tránh deadlock.
        """
        with self._lock:
            self._flush_buffer()
            # Thử flush Python layer (no-op cho raw fd) + fsync
            if self._fd is not None:
                try:
                    os.fsync(self._fd)
                except OSError:
                    pass
                self._last_fsync_ts = time.monotonic()

    def close(self):
        """Close file (flush + close fd + atomic rename nếu .tmp tồn tại)"""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._flush_buffer()
            if self._fd is not None:
                try:
                    os.fsync(self._fd)
                except OSError:
                    pass
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def byte_count(self) -> int:
        return self._byte_count

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class PcapReader:
    """
    PCAP file reader
    Iterates over packets in file
    """

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self._file = None
        self._header = None
        self._big_endian = False
        self._packet_stt = 0

    def open(self):
        """Open file and read global header"""
        self._file = open(self.filepath, 'rb')
        self._packet_stt = 0  # Reset for fresh iteration
        header_data = self._file.read(24)

        if len(header_data) < 24:
            raise ValueError("Invalid PCAP file: too short")

        self._header = PcapGlobalHeader.from_bytes(header_data)
        self._big_endian = (self._header.magic == 0xd4c3b2a1)

    @property
    def header(self) -> Optional[PcapGlobalHeader]:
        return self._header

    def read_packet(self) -> Optional[PacketInfo]:
        """Read next packet, return None at EOF"""
        if self._file is None:
            return None

        # Read packet header
        pkt_header_data = self._file.read(16)
        if len(pkt_header_data) < 16:
            return None

        pkt_header = PcapPacketHeader.from_bytes(pkt_header_data, self._big_endian)

        # Read packet data
        data = self._file.read(pkt_header.caplen)
        if len(data) < pkt_header.caplen:
            return None

        self._packet_stt += 1

        return PacketInfo(
            stt=self._packet_stt,
            ts_sec=pkt_header.ts_sec,
            ts_usec=pkt_header.ts_usec,
            caplen=pkt_header.caplen,
            origlen=pkt_header.origlen,
            data=data
        )

    def __iter__(self) -> Iterator[PacketInfo]:
        """Iterate over all packets (auto-open nếu chưa mở)"""
        if self._file is None:
            self.open()
        # Reset để có thể iterate nhiều lần
        self._file.seek(24)  # skip global header
        self._packet_stt = 0
        while True:
            pkt = self.read_packet()
            if pkt is None:
                break
            yield pkt

    def close(self):
        """Close file"""
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


def count_packets(filepath: str) -> int:
    """Count packets in PCAP file"""
    count = 0
    with PcapReader(filepath) as reader:
        for _ in reader:
            count += 1
    return count


def get_pcap_info(filepath: str) -> dict:
    """Get PCAP file info"""
    path = Path(filepath)
    if not path.exists():
        return {"error": "File not found"}

    with PcapReader(filepath) as reader:
        first_ts = None
        last_ts = None
        count = 0
        total_bytes = 0

        for pkt in reader:
            ts = pkt.ts_sec + pkt.ts_usec / 1e6
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            count += 1
            total_bytes += pkt.caplen

    return {
        "filepath": str(path),
        "size_bytes": path.stat().st_size,
        "packet_count": count,
        "total_bytes": total_bytes,
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
        "duration": (last_ts - first_ts) if first_ts and last_ts else 0,
        "snaplen": reader.header.snaplen if reader.header else 0,
    }
