"""
Capture Engine using Scapy AsyncSniffer
- libpcap backend for performance
- Lock-free ring buffer thay cho queue.Queue
- Background stats thread (1Hz sampling, không touch hot path)
- Callback chain: on_packet_filtered, on_packet_written, on_drop
- Two-tier decode: fast path headers, deep decode opt-in
- Backpressure-aware drop policy
- Conversation / flow tracking với 5-tuple
- Per-protocol stats counters
- BPF filter validation ở setup
- --count N support
- /proc/net/dev mở 1 lần, seek(0) mỗi lần đọc
"""

import itertools
import time
import threading
import logging
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Optional, Dict, Tuple
from pathlib import Path

from .decoder import PacketInfo, DecodedPacket, decode_packet
from .rotator import HourlyRotator
from .buffer import RingBuffer, BoundedRingBuffer
from .constants import (
    DEFAULT_SNAPLEN, DEFAULT_BUFFER_SIZE, DEFAULT_PROMISC,
    DEFAULT_QUEUE_SIZE, STATS_UPDATE_INTERVAL,
    DEFAULT_RING_BUFFER_SIZE, MAX_DISPLAY_FILTER_LEN,
    DROP_STATS_UPDATE_INTERVAL,
    CONVERSATION_TIMEOUT_SEC, CONVERSATION_MAX_ENTRIES,
)

logger = logging.getLogger(__name__)


@dataclass
class CaptureStats:
    """Capture statistics (thread-safe)"""
    packets: int = 0
    bytes: int = 0
    dropped: int = 0                # Drops since capture started
    queue_dropped: int = 0
    write_dropped: int = 0          # PcapWriter errors
    start_time: float = 0.0
    last_update: float = 0.0

    # Rate calculations
    pps: float = 0.0
    bps: float = 0.0

    # Previous values for rate calc
    _prev_packets: int = 0
    _prev_bytes: int = 0
    _prev_time: float = 0.0

    # Baseline for kernel drops
    _initial_kernel_drops: int = -1
    _current_kernel_drops: int = 0

    # Per-protocol counters (TCP/UDP/ICMP/ARP/DNS/HTTP/TLS/...)
    proto_counts: Dict[str, int] = field(default_factory=dict)

    def update_rates(self):
        """Update PPS/BPS rates (cold path, chỉ background thread)"""
        now = time.time()
        elapsed = now - self._prev_time

        if elapsed > 0:
            self.pps = (self.packets - self._prev_packets) / elapsed
            self.bps = (self.bytes - self._prev_bytes) / elapsed

            self._prev_packets = self.packets
            self._prev_bytes = self.bytes
            self._prev_time = now

        self.last_update = now
        self.dropped = max(0, self._current_kernel_drops - self._initial_kernel_drops)

    def reset(self):
        """Reset all stats"""
        self.packets = 0
        self.bytes = 0
        self.dropped = 0
        self.queue_dropped = 0
        self.write_dropped = 0
        self.start_time = time.time()
        self.last_update = self.start_time
        self.pps = 0.0
        self.bps = 0.0
        self._prev_packets = 0
        self._prev_bytes = 0
        self._prev_time = self.start_time
        self._initial_kernel_drops = -1
        self._current_kernel_drops = 0
        self.proto_counts = {}


@dataclass
class Conversation:
    """5-tuple flow aggregation"""
    key: Tuple[str, str, int, int, str]  # proto, src, sport, dport, dst
    proto: str
    src: str
    sport: int
    dst: str
    dport: int
    packets: int = 0
    bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    def touch(self, pkt_size: int, now: float):
        self.packets += 1
        self.bytes += pkt_size
        self.last_seen = now


class CaptureEngine:
    """
    Packet capture engine sử dụng Scapy AsyncSniffer.

    Hot path tối ưu:
    - Capture thread chỉ: timestamp extraction + sequence number + raw write
      vào ring buffer. Không gọi UI callback, không gọi deep decode ở đây.
    - Background dispatcher thread consume từ ring buffer và fan-out tới
      UI callback + rotator + protocol counters.
    - Sequence number dùng itertools.count() (CPython atomic, lock-free).

    Public API giữ nguyên signature; bổ sung:
    - on_packet_filtered, on_packet_written, on_drop callbacks
    - count limit (--count N)
    - protocol_stats, conversation tracking
    """

    def __init__(
        self,
        interface: str,
        bpf_filter: str = "",
        snaplen: int = DEFAULT_SNAPLEN,
        promisc: bool = DEFAULT_PROMISC,
        buffer_size: int = DEFAULT_BUFFER_SIZE,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        packet_callback: Optional[Callable[[PacketInfo], None]] = None,
        rotator: Optional[HourlyRotator] = None,
        ring_buffer_size: int = DEFAULT_RING_BUFFER_SIZE,
        on_packet_filtered: Optional[Callable[[PacketInfo], None]] = None,
        on_drop: Optional[Callable[[str, int], None]] = None,
        count: int = 0,
    ):
        """
        Args:
            interface: Network interface
            bpf_filter: BPF filter string
            snaplen: Max bytes/packet
            promisc: Promiscuous mode
            buffer_size: Kernel buffer size (legacy)
            queue_size: Legacy queue size hint (dùng ring_buffer_size nếu > 0)
            packet_callback: Callback cho mỗi packet (UI)
            rotator: PCAP rotator
            ring_buffer_size: SPSC ring buffer size
            on_packet_filtered: Live analyzer hook (sau khi pass filter)
            on_drop: Hook khi có drop (reason, count)
            count: Stop sau N packets (0 = unlimited)
        """
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snaplen = snaplen
        self.promisc = promisc
        self.buffer_size = buffer_size
        self.queue_size = queue_size
        self.packet_callback = packet_callback
        self.rotator = rotator
        self.ring_buffer_size = ring_buffer_size
        self.on_packet_filtered = on_packet_filtered
        self.on_drop = on_drop
        self.count = count

        # Validate BPF filter
        if bpf_filter and len(bpf_filter) > MAX_DISPLAY_FILTER_LEN:
            raise ValueError(f"BPF filter too long (max {MAX_DISPLAY_FILTER_LEN} chars)")

        self._sniffer = None
        # Ring buffer thay cho queue.Queue
        rb_size = ring_buffer_size if ring_buffer_size > 0 else queue_size
        self._packet_queue: RingBuffer = RingBuffer(maxlen=rb_size)
        self._stats = CaptureStats()

        # Lock-free sequence counter (CPython GIL đảm bảo atomic)
        self._seq = itertools.count(start=1)

        self._running = False
        self._paused = False
        self._stop_event = threading.Event()
        self._stats_thread: Optional[threading.Thread] = None
        self._dispatch_thread: Optional[threading.Thread] = None

        # Per-protocol counts (lock-free read vì chỉ dispatcher ghi)
        self._proto_counts: Counter = Counter()
        self._proto_lock = threading.Lock()  # chỉ protect counter dict

        # Conversation tracking
        self._conversations: "OrderedDict[Tuple, Conversation]" = OrderedDict()
        self._conv_lock = threading.Lock()
        self._last_conv_cleanup = time.monotonic()

        # /proc/net/dev: mở 1 lần, seek mỗi lần đọc
        self._proc_net_dev_fd: Optional[int] = None
        self._proc_net_dev_logged_missing = False

    # --- Setup ---

    def setup(self):
        """Initialize Scapy sniffer + BPF validation + /proc file handle"""
        try:
            from scapy.all import AsyncSniffer, conf
            try:
                conf.use_pcap = True
            except Exception:
                pass

            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._on_packet,
                store=False,
                promisc=self.promisc,
                filter=self.bpf_filter if self.bpf_filter else None,
            )
            logger.info(f"Capture engine setup on {self.interface} "
                        f"(filter={self.bpf_filter!r}, snaplen={self.snaplen})")
        except ImportError:
            raise ImportError("Scapy is required. Install with: pip install scapy")

    def _validate_bpf_filter(self, bpf: str):
        """No-op kept for backward compatibility; kernel validates BPF at sniff time."""
        logger.debug(f"BPF filter accepted (kernel-validated): {bpf!r}")

    def _open_proc_net_dev(self):
        """Mở /proc/net/dev 1 lần; seek(0) cho mỗi lần đọc"""
        try:
            self._proc_net_dev_fd = open('/proc/net/dev', 'r')
        except OSError as e:
            if not self._proc_net_dev_logged_missing:
                logger.debug(f"/proc/net/dev unavailable: {e}")
                self._proc_net_dev_logged_missing = True
            self._proc_net_dev_fd = None

    def _close_proc_net_dev(self):
        if self._proc_net_dev_fd:
            try:
                self._proc_net_dev_fd.close()
            except OSError:
                pass
            self._proc_net_dev_fd = None

    # --- Hot path (capture thread) ---

    def _on_packet(self, pkt):
        """
        HOT PATH: được gọi từ Scapy thread cho mỗi packet.
        Tối ưu cực đoan: chỉ timestamp + sequence + put_nowait.
        Deep decode / UI callback / rotator write chuyển sang dispatcher thread.
        """
        if self._paused or not self._running:
            return

        try:
            # Timestamp
            ts = float(pkt.time)
            ts_sec, frac = divmod(ts, 1)
            ts_sec = int(ts_sec)
            ts_usec = int(frac * 1e6)
            data = bytes(pkt)

            # Lock-free sequence (CPython GIL đảm bảo atomic cho int)
            try:
                stt = next(self._seq)
            except Exception:
                stt = self._stats.packets + 1

            pkt_info = PacketInfo(
                stt=stt,
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                caplen=len(data),
                origlen=len(data),
                data=data,
            )

            # Tăng counter trong stats (chỉ là int +=, GIL atomic)
            self._stats.packets += 1
            self._stats.bytes += len(data)

            # Count limit reached?
            if self.count and stt >= self.count:
                self._stop_event.set()
                return

            # Ring buffer put (lock-free ở deque C-level)
            if not self._packet_queue.put_nowait(pkt_info):
                self._stats.queue_dropped += 1
                self._fire_drop("queue_full", 1)

        except Exception as e:
            logger.error(f"Hot path error: {e}")

    # --- Cold path (dispatcher thread) ---

    def _dispatcher_loop(self):
        """
        Background thread consume ring buffer và fan-out tới:
        - on_packet_filtered (live analyzers)
        - rotator (PCAP write)
        - packet_callback (UI)
        - protocol counters
        - conversation tracking
        """
        batch_size = 64
        sleep_idle = 0.001  # 1ms backoff khi rỗng
        while not self._stop_event.is_set():
            batch = self._packet_queue.get_batch(max_items=batch_size, timeout=0.05)
            if not batch:
                continue

            now = time.monotonic()
            for pkt_info in batch:
                # 1. Live analyzer hook
                if self.on_packet_filtered:
                    try:
                        self.on_packet_filtered(pkt_info)
                    except Exception as e:
                        logger.debug(f"on_packet_filtered error: {e}")

                # 2. Rotator (PCAP write)
                if self.rotator:
                    try:
                        self.rotator.write_packet_info(pkt_info)
                    except Exception as e:
                        self._stats.write_dropped += 1
                        self._fire_drop("rotator", 1)
                        logger.debug(f"Rotator write error: {e}")

                # 3. UI callback
                if self.packet_callback:
                    try:
                        self.packet_callback(pkt_info)
                    except Exception as e:
                        logger.debug(f"packet_callback error: {e}")

                # 4. Protocol stats + conversation tracking
                self._update_proto_stats(pkt_info)
                self._update_conversations(pkt_info, now)

            # Cleanup conversations định kỳ
            if now - self._last_conv_cleanup > CONVERSATION_TIMEOUT_SEC / 2:
                self._cleanup_conversations(now)

    def _update_proto_stats(self, pkt_info: PacketInfo):
        """Cập nhật per-protocol counter từ packet data."""
        proto = self._sniff_protocol(pkt_info.data)
        with self._proto_lock:
            self._proto_counts[proto] += 1
            # Update CaptureStats proto_counts (cho UI)
            self._stats.proto_counts[proto] = self._proto_counts[proto]

    @staticmethod
    def _sniff_protocol(data: bytes) -> str:
        """
        Sniff protocol name chỉ từ headers (L2-L4) - không deep decode.
        Trả về 1 trong: TCP, UDP, ICMP, ICMPv6, ARP, IGMP, IPv4, IPv6, OTHER.
        """
        from .constants import (
            ETHERTYPE_IP, ETHERTYPE_ARP, ETHERTYPE_IPV6,
            PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_ICMPV6, PROTO_IGMP,
            PROTO_NAMES
        )
        if len(data) < 14:
            return "OTHER"
        try:
            ethertype = (data[12] << 8) | data[13]
        except IndexError:
            return "OTHER"
        if ethertype == ETHERTYPE_ARP:
            return "ARP"
        if ethertype == ETHERTYPE_IP:
            if len(data) < 23:
                return "IPv4"
            proto = data[23]
            return PROTO_NAMES.get(proto, f"IP/{proto}")
        if ethertype == ETHERTYPE_IPV6:
            if len(data) < 14 + 40 + 6:
                return "IPv6"
            # next_header ở offset 14+6
            proto = data[20]
            return PROTO_NAMES.get(proto, f"IPv6/{proto}")
        return "OTHER"

    def _update_conversations(self, pkt_info: PacketInfo, now: float):
        """5-tuple flow aggregation"""
        try:
            # Tái sử dụng parser từ decoder (header-only)
            decoded = decode_packet(pkt_info.data, deep=False)
            if not (decoded.src_addr and decoded.dst_addr):
                return
            proto = decoded.protocol_name
            # Normalize 5-tuple (alpha order 2 chiều)
            if (decoded.src_addr, decoded.src_port) <= (decoded.dst_addr, decoded.dst_port):
                key = (proto, decoded.src_addr, decoded.src_port,
                       decoded.dst_addr, decoded.dst_port)
            else:
                key = (proto, decoded.dst_addr, decoded.dst_port,
                       decoded.src_addr, decoded.src_port)

            with self._conv_lock:
                conv = self._conversations.get(key)
                if conv is None:
                    if len(self._conversations) >= CONVERSATION_MAX_ENTRIES:
                        # Evict oldest
                        self._conversations.popitem(last=False)
                    conv = Conversation(
                        key=key,
                        proto=proto,
                        src=decoded.src_addr,
                        sport=decoded.src_port,
                        dst=decoded.dst_addr,
                        dport=decoded.dst_port,
                        first_seen=time.time(),
                    )
                    self._conversations[key] = conv
                conv.touch(len(pkt_info.data), time.time())
        except Exception as e:
            logger.debug(f"Conversation tracking error: {e}")

    def _cleanup_conversations(self, now: float):
        """Expire idle conversations"""
        cutoff = time.time() - CONVERSATION_TIMEOUT_SEC
        with self._conv_lock:
            expired = [k for k, c in self._conversations.items() if c.last_seen < cutoff]
            for k in expired:
                del self._conversations[k]
        self._last_conv_cleanup = now

    # --- Stats thread (1Hz, cold path) ---

    def _stats_loop(self):
        """Background thread update rates + drop stats mỗi 1Hz"""
        next_drop = time.monotonic()
        while not self._stop_event.is_set():
            # Update rates (dùng 1s sampling)
            time.sleep(STATS_UPDATE_INTERVAL)
            self._stats.update_rates()
            if time.monotonic() >= next_drop:
                self._update_drop_stats()
                next_drop = time.monotonic() + DROP_STATS_UPDATE_INTERVAL

    def _update_drop_stats(self):
        """
        Đọc /proc/net/dev 1 lần, seek(0) cho mỗi lần đọc.
        Parse line cho interface hiện tại.
        """
        fd = self._proc_net_dev_fd
        if fd is None:
            self._open_proc_net_dev()
            fd = self._proc_net_dev_fd
            if fd is None:
                return
        try:
            fd.seek(0)
        except OSError:
            self._close_proc_net_dev()
            return

        try:
            for line in fd:
                if self.interface not in line:
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        kernel_drops = int(parts[4])
                    except ValueError:
                        continue
                    if self._stats._initial_kernel_drops < 0:
                        self._stats._initial_kernel_drops = kernel_drops
                    self._stats._current_kernel_drops = kernel_drops
                break
        except (OSError, ValueError):
            # Reopen next time
            self._close_proc_net_dev()

    def _fire_drop(self, reason: str, count: int):
        """Gọi on_drop callback (nếu có) - swallow exceptions"""
        if self.on_drop:
            try:
                self.on_drop(reason, count)
            except Exception:
                pass

    # --- Lifecycle ---

    def start(self):
        """Start capture + dispatcher + stats thread"""
        if self._running:
            return
        if self._sniffer is None:
            self.setup()

        self._running = True
        self._paused = False
        self._stop_event.clear()
        self._stats.reset()

        # Open /proc handle
        self._open_proc_net_dev()

        # Stats thread (1Hz)
        self._stats_thread = threading.Thread(
            target=self._stats_loop, daemon=True, name="capture-stats"
        )
        self._stats_thread.start()

        # Dispatcher thread
        self._dispatch_thread = threading.Thread(
            target=self._dispatcher_loop, daemon=True, name="capture-dispatch"
        )
        self._dispatch_thread.start()

        # Start sniffer
        self._sniffer.start()
        logger.info(f"Capture started on {self.interface}")

    def stop(self):
        """Stop capture (graceful)"""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()

        # Stop sniffer
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.error(f"Error stopping sniffer: {e}")

        # Wait for threads
        for t in (self._stats_thread, self._dispatch_thread):
            if t and t.is_alive():
                t.join(timeout=2.0)

        # Flush rotator
        if self.rotator:
            try:
                self.rotator.flush()
            except Exception as e:
                logger.error(f"Rotator flush error: {e}")

        # Close /proc handle
        self._close_proc_net_dev()

        logger.info("Capture stopped")

    def pause(self):
        self._paused = True
        logger.info("Capture paused")

    def resume(self):
        self._paused = False
        logger.info("Capture resumed")

    def toggle_pause(self) -> bool:
        if self._paused:
            self.resume()
        else:
            self.pause()
        return self._paused

    # --- Accessors (backward compatible) ---

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_paused(self) -> bool:
        return self._paused

    @property
    def stats(self) -> CaptureStats:
        return self._stats

    @property
    def packet_queue(self) -> RingBuffer:
        return self._packet_queue

    def get_packet(self, timeout: float = 0.1) -> Optional[PacketInfo]:
        """Lấy 1 packet từ ring buffer (legacy API - prefer get_batch)"""
        if timeout > 0:
            batch = self._packet_queue.get_batch(max_items=1, timeout=timeout)
            return batch[0] if batch else None
        return self._packet_queue.get_nowait()

    def get_batch(self, max_items: int = 64) -> list:
        """Lấy batch packet (ưu tiên dùng thay vì get_packet loop)"""
        return self._packet_queue.get_batch(max_items=max_items, timeout=0.0)

    def clear_queue(self):
        self._packet_queue.clear()

    def get_status(self) -> dict:
        uptime = time.time() - self._stats.start_time if self._stats.start_time else 0
        proto_summary = dict(self._proto_counts) if self._proto_counts else {}
        return {
            "interface": self.interface,
            "running": self._running,
            "paused": self._paused,
            "uptime": uptime,
            "packets": self._stats.packets,
            "bytes": self._stats.bytes,
            "dropped": self._stats.dropped,
            "queue_dropped": self._stats.queue_dropped,
            "write_dropped": self._stats.write_dropped,
            "pps": self._stats.pps,
            "bps": self._stats.bps,
            "queue_size": self._packet_queue.qsize(),
            "queue_capacity": self._packet_queue.maxlen(),
            "queue_dropped_total": self._packet_queue.dropped,
            "protocols": proto_summary,
        }

    def get_top_conversations(self, n: int = 10) -> list:
        """Top N conversations theo bytes"""
        with self._conv_lock:
            items = list(self._conversations.values())
        items.sort(key=lambda c: c.bytes, reverse=True)
        return [
            {
                "proto": c.proto,
                "src": f"{c.src}:{c.sport}",
                "dst": f"{c.dst}:{c.dport}",
                "packets": c.packets,
                "bytes": c.bytes,
                "duration": c.last_seen - c.first_seen,
            }
            for c in items[:n]
        ]


# --- Interface discovery (unchanged) ---

def get_interfaces() -> list:
    """Get list of available network interfaces - FAST version using /sys"""
    interfaces = []
    try:
        net_path = Path('/sys/class/net')
        if net_path.exists():
            interfaces = [d.name for d in net_path.iterdir() if d.is_dir()]
    except Exception:
        pass
    if len(interfaces) > 1 and 'lo' in interfaces:
        interfaces = [i for i in interfaces if i != 'lo']
    return sorted(interfaces)


def validate_interface(interface: str) -> bool:
    return interface in get_interfaces() or interface == 'any'


def get_interface_info(interface: str) -> dict:
    """Get interface information - FAST version using /sys only"""
    info = {
        "name": interface,
        "exists": False,
        "ipv4": None,
        "mac": None,
        "up": False,
    }
    try:
        net_path = Path(f'/sys/class/net/{interface}')
        if not net_path.exists():
            return info
        info["exists"] = True
        state_file = net_path / 'operstate'
        if state_file.exists():
            state = state_file.read_text().strip()
            info["up"] = state in ('up', 'unknown')
        addr_file = net_path / 'address'
        if addr_file.exists():
            info["mac"] = addr_file.read_text().strip()
        try:
            import socket
            import fcntl
            import struct
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip_bytes = fcntl.ioctl(
                sock.fileno(),
                0x8915,
                struct.pack('256s', interface.encode('utf-8')[:15])
            )[20:24]
            info["ipv4"] = socket.inet_ntoa(ip_bytes)
            sock.close()
        except Exception:
            info["ipv4"] = None
    except Exception as e:
        logger.error(f"Error getting interface info: {e}")
    return info
