"""
List View - Hiển thị danh sách packets kiểu Wireshark
Refactored: live filter, search, top-talkers, sparkline, differential rendering,
color rules, pause-keep-state
"""

import sys
import threading
import queue
import time
import select
import termios
import tty
import gc
import re
import os
import ipaddress
from typing import Optional, List, Dict, Any, Callable, Tuple
from collections import deque, OrderedDict, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.colors import (
    clear_screen, hide_cursor, show_cursor,
    bold, cyan, green, yellow, red, dim, magenta, orange, bright,
    get_terminal_size,
    format_number, format_rate,
    Colors, color, format_protocol, format_rate_graph,
)
from core.decoder import decode_packet, DecodedPacket, PacketInfo


# ============================================================
# Constants
# ============================================================

# Columns
COL_STT = 8
COL_TIME = 12
COL_SRC = 32
COL_DST = 32
COL_PROTO = 8
COL_LEN = 7
COL_INFO = 35

# Modes for the view
MODE_LIST = 'list'
MODE_TOP_TALKERS = 'top_talkers'
MODE_FILTER_INPUT = 'filter_input'
MODE_SEARCH_INPUT = 'search_input'

# Color rules thresholds
LARGE_PKT_THRESHOLD = 1500
JUMBO_PKT_THRESHOLD = 9000
SYN_FLOOD_RATE_THRESHOLD = 100   # SYN/s từ 1 src để nghi ngờ flood


# ============================================================
# PacketFilter - BPF-style display filter
# ============================================================

class PacketFilter:
    """
    BPF-style display filter cho live view.

    Hỗ trợ cú pháp đơn giản:
        tcp                - protocol name match
        udp port 53        - proto + port
        host 1.2.3.4       - any direction
        src 10.0.0.1       - src match
        dst 10.0.0.2       - dst match
        port 80            - either side
        net 192.168.0.0/16 - subnet match (CIDR)
        and, or, not       - boolean
    """

    def __init__(self, expr: str = ""):
        self.expr = expr.strip()
        self._compiled_re: Optional[re.Pattern] = None
        self._port: Optional[int] = None
        self._proto: Optional[str] = None
        self._host: Optional[str] = None
        self._src: Optional[str] = None
        self._dst: Optional[str] = None
        self._network: Optional[Tuple[str, int]] = None  # (base_ip, prefix_len)
        self._negate = False
        self._parse()

    def _parse(self):
        """Parse simple BPF expression thành predicates."""
        if not self.expr:
            return

        expr = self.expr.lower().strip()

        # Detect NOT
        if expr.startswith('not '):
            self._negate = True
            expr = expr[4:].strip()

        tokens = expr.split()

        i = 0
        while i < len(tokens):
            t = tokens[i]

            if t == 'and':
                # Currently only single-predicate: bỏ qua
                i += 1
                continue
            elif t == 'or':
                i += 1
                continue
            elif t in ('tcp', 'udp', 'icmp', 'arp', 'ipv4', 'ipv6', 'dns', 'http', 'tls', 'quic', 'dhcp', 'ntp', 'ssh'):
                self._proto = t
            elif t == 'host':
                if i + 1 < len(tokens):
                    self._host = tokens[i + 1]
                    i += 1
            elif t == 'src':
                if i + 1 < len(tokens):
                    val = tokens[i + 1]
                    if val in ('port',):
                        if i + 2 < len(tokens):
                            self._src_port = int(tokens[i + 2])
                            i += 2
                    else:
                        self._src = val
                        i += 1
            elif t == 'dst':
                if i + 1 < len(tokens):
                    val = tokens[i + 1]
                    if val in ('port',):
                        if i + 2 < len(tokens):
                            self._dst_port = int(tokens[i + 2])
                            i += 2
                    else:
                        self._dst = val
                        i += 1
            elif t == 'port':
                if i + 1 < len(tokens):
                    self._port = int(tokens[i + 1])
                    i += 1
            elif t == 'net':
                if i + 1 < len(tokens):
                    self._network = self._parse_cidr(tokens[i + 1])
                    i += 1
            else:
                # Substring search fallback (info_str search)
                if not self._compiled_re:
                    self._compiled_re = re.compile(re.escape(t), re.IGNORECASE)

            i += 1

    @staticmethod
    def _parse_cidr(cidr: str) -> Optional["ipaddress.IPv4Network"]:
        """Parse CIDR như '192.168.0.0/16' -> ipaddress.IPv4Network."""
        try:
            return ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return None

    def _ip_in_network(self, ip: str) -> bool:
        if not self._network:
            return True
        try:
            return ipaddress.ip_address(ip) in self._network
        except Exception:
            return False

    def match(self, pkt_info: PacketInfo, decoded: Optional[DecodedPacket]) -> bool:
        """Trả về True nếu packet khớp filter."""
        if not self.expr:
            return True

        result = True  # default nếu không có predicate nào match

        # Protocol predicate
        if self._proto:
            proto = (decoded.protocol_name if decoded else 'UNKNOWN').lower()
            # Cho phép 'tcp' match cả TCP packets; 'http'/'dns' match app protocol
            if self._proto in ('http', 'dns', 'tls', 'quic', 'dhcp', 'ntp', 'ssh'):
                proto_info = decoded.proto if decoded else None
                if not proto_info or proto_info.name.lower() != self._proto:
                    result = False
            elif proto != self._proto:
                result = False

        # Port predicate
        if result and self._port is not None:
            src_port = decoded.src_port if decoded else 0
            dst_port = decoded.dst_port if decoded else 0
            if self._port not in (src_port, dst_port):
                result = False

        # Host predicate
        if result and self._host:
            src = decoded.src_addr if decoded else ''
            dst = decoded.dst_addr if decoded else ''
            if self._host not in (src, dst):
                result = False

        # Src predicate
        if result and self._src:
            src = decoded.src_addr if decoded else ''
            if self._src not in src:
                result = False

        # Dst predicate
        if result and self._dst:
            dst = decoded.dst_addr if decoded else ''
            if self._dst not in dst:
                result = False

        # Network predicate
        if result and self._network:
            src = decoded.src_addr if decoded else ''
            dst = decoded.dst_addr if decoded else ''
            if not (self._ip_in_network(src) or self._ip_in_network(dst)):
                result = False

        # Substring predicate
        if result and self._compiled_re:
            search_str = ''
            if decoded:
                search_str = f"{decoded.src_addr} {decoded.dst_addr} {decoded.protocol_name} {decoded.info_str}"
            if not self._compiled_re.search(search_str):
                result = False

        # Negate
        if self._negate:
            result = not result

        return result


# ============================================================
# Rate tracker - cho sparkline
# ============================================================

class RateTracker:
    """Theo dõi lịch sử pps/bps cho sparkline chart."""

    def __init__(self, window: int = 30):
        """
        Args:
            window: số sample giữ lại (mỗi sample = 1s)
        """
        self.window = window
        self.pps_history: deque = deque(maxlen=window)
        self.bps_history: deque = deque(maxlen=window)
        self._last_sample_time = time.time()
        self._last_packets = 0
        self._last_bytes = 0
        self._lock = threading.Lock()

    def update(self, total_packets: int, total_bytes: int):
        """Cập nhật sample mới (gọi mỗi giây)."""
        now = time.time()
        with self._lock:
            elapsed = now - self._last_sample_time
            if elapsed >= 1.0:
                dpkt = total_packets - self._last_packets
                dbytes = total_bytes - self._last_bytes
                pps = dpkt / elapsed if elapsed > 0 else 0
                bps = dbytes / elapsed if elapsed > 0 else 0
                self.pps_history.append(int(pps))
                self.bps_history.append(int(bps))
                self._last_packets = total_packets
                self._last_bytes = total_bytes
                self._last_sample_time = now

    def get_pps_graph(self, width: int = 20) -> str:
        with self._lock:
            return format_rate_graph(list(self.pps_history), width=width)

    def get_bps_graph(self, width: int = 20) -> str:
        with self._lock:
            return format_rate_graph(list(self.bps_history), width=width)


# ============================================================
# Top talkers tracker
# ============================================================

class TopTalkers:
    """Theo dõi top talkers (src IP, dst IP, port, conversation pair)."""

    def __init__(self, max_remember: int = 50000):
        self.src_count: Dict[str, int] = defaultdict(int)
        self.dst_count: Dict[str, int] = defaultdict(int)
        self.port_count: Dict[int, int] = defaultdict(int)
        self.proto_count: Dict[str, int] = defaultdict(int)
        self.pair_count: Dict[Tuple[str, str], int] = defaultdict(int)
        self.syn_count: Dict[str, int] = defaultdict(int)  # SYN flood detection
        self._syn_window_start = time.time()
        self._syn_lock = threading.Lock()
        self.max_remember = max_remember

    def record(self, decoded: Optional[DecodedPacket], pkt_len: int):
        """Record stats cho packet."""
        if decoded is None:
            return

        with self._syn_lock:
            if decoded.src_addr:
                self.src_count[decoded.src_addr] += 1
            if decoded.dst_addr:
                self.dst_count[decoded.dst_addr] += 1
            if decoded.src_port:
                self.port_count[decoded.src_port] += 1
            if decoded.dst_port:
                self.port_count[decoded.dst_port] += 1
            if decoded.protocol_name:
                self.proto_count[decoded.protocol_name] += 1

            # Conversation pair (sorted để không phân biệt chiều)
            if decoded.src_addr and decoded.dst_addr:
                pair = tuple(sorted([decoded.src_addr, decoded.dst_addr]))
                self.pair_count[pair] += 1

            # SYN flood detection: TCP với SYN flag set
            if decoded.tcp and (decoded.tcp.flags & 0x02):  # SYN flag
                self.syn_count[decoded.src_addr] += 1

            # Trim nếu quá lớn
            if len(self.src_count) > self.max_remember:
                self._trim()

    def _trim(self):
        """Trim top đến top 50% nếu vượt max_remember."""
        for d in (self.src_count, self.dst_count, self.port_count,
                  self.proto_count, self.pair_count):
            if len(d) > self.max_remember // 2:
                top = sorted(d.items(), key=lambda x: x[1], reverse=True)[:self.max_remember // 4]
                d.clear()
                for k, v in top:
                    d[k] = v

    def check_syn_flood(self) -> List[Tuple[str, int]]:
        """
        Trả về list (src_ip, syn_per_sec) cho các src vượt threshold.
        Reset window sau khi check.
        """
        now = time.time()
        elapsed = now - self._syn_window_start
        if elapsed < 1.0:
            return []

        suspects = []
        with self._syn_lock:
            for src, count in self.syn_count.items():
                rate = count / elapsed
                if rate >= SYN_FLOOD_RATE_THRESHOLD:
                    suspects.append((src, int(rate)))

        # Reset cho window tiếp theo
        self.syn_count.clear()
        self._syn_window_start = now
        suspects.sort(key=lambda x: x[1], reverse=True)
        return suspects

    def top_src(self, n: int = 10) -> List[Tuple[str, int]]:
        return sorted(self.src_count.items(), key=lambda x: x[1], reverse=True)[:n]

    def top_dst(self, n: int = 10) -> List[Tuple[str, int]]:
        return sorted(self.dst_count.items(), key=lambda x: x[1], reverse=True)[:n]

    def top_ports(self, n: int = 10) -> List[Tuple[int, int]]:
        return sorted(self.port_count.items(), key=lambda x: x[1], reverse=True)[:n]

    def top_pairs(self, n: int = 10) -> List[Tuple[Tuple[str, str], int]]:
        return sorted(self.pair_count.items(), key=lambda x: x[1], reverse=True)[:n]

    def proto_breakdown(self) -> List[Tuple[str, int]]:
        return sorted(self.proto_count.items(), key=lambda x: x[1], reverse=True)

    def reset(self):
        with self._syn_lock:
            self.src_count.clear()
            self.dst_count.clear()
            self.port_count.clear()
            self.proto_count.clear()
            self.pair_count.clear()
            self.syn_count.clear()
            self._syn_window_start = time.time()


# ============================================================
# Decode cache
# ============================================================

class DecodeCache:
    """
    Cache decoded results, keyed by (stt, len(data), first_bytes_hash).
    Tránh re-decode khi packet vẫn trong queue.
    """

    def __init__(self, maxsize: int = 10000):
        self._cache: OrderedDict = OrderedDict()
        self._maxsize = maxsize
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get_or_decode(self, pkt_info: PacketInfo) -> Optional[DecodedPacket]:
        # Skip packets quá ngắn (không có ethernet header đầy đủ)
        if len(pkt_info.data) < 14:
            return None

        # Key dựa trên stt + length + vài bytes đầu
        data_hash = hash(pkt_info.data[:64])
        key = (pkt_info.stt, len(pkt_info.data), data_hash)

        with self._lock:
            if key in self._cache:
                self.hits += 1
                self._cache.move_to_end(key)
                return self._cache[key]

        # Decode ngoài lock để không block readers
        try:
            decoded = decode_packet(pkt_info.data)
        except Exception:
            decoded = None

        with self._lock:
            self._cache[key] = decoded
            self.misses += 1
            while len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)

        return decoded

    def clear(self):
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0


# ============================================================
# Main PacketListView
# ============================================================

class PacketListView:
    """
    Hiển thị danh sách packets kiểu Wireshark với:

    - Auto-scroll, pause (giữ state)
    - Live BPF-style display filter ('/')
    - Incremental search trong paused mode
    - Top talkers view ('t')
    - Sparkline pps/bps trong stats bar
    - Color rules (SYN flood orange, large pkt bright, RST red, DNS cyan, HTTP green)
    - Differential rendering: chỉ redraw khi có thay đổi
    """

    # Protocol colors (giữ nguyên để tương thích)
    PROTO_COLORS = {
        'TCP': Colors.GREEN,
        'UDP': Colors.BLUE,
        'ICMP': Colors.MAGENTA,
        'ARP': Colors.YELLOW,
        'IPv4': Colors.CYAN,
        'IPv6': Colors.CYAN,
        'DNS': Colors.CYAN,
        'HTTP': Colors.GREEN,
        'TLS': Colors.BRIGHT_BLUE,
        'QUIC': Colors.BRIGHT_BLUE,
        'DHCP': Colors.BRIGHT_YELLOW,
    }

    def __init__(
        self,
        packet_queue: queue.Queue,
        on_quit: Callable,
        stats_callback: Callable[[], Dict[str, Any]],
        file_info_callback: Callable[[], Dict[str, Any]],
        on_pause: Optional[Callable[[bool], None]] = None,
        on_save_exit: Optional[Callable[[], None]] = None,
        on_show_detail: Optional[Callable[[int], None]] = None,
        cache_size: int = 5000,
    ):
        self.packet_queue = packet_queue
        self.on_quit = on_quit
        self.stats_callback = stats_callback
        self.file_info_callback = file_info_callback
        self.on_pause = on_pause
        self.on_save_exit = on_save_exit
        self.on_show_detail = on_show_detail

        # Packet cache
        self.cache_size = cache_size
        self.packets: deque = deque(maxlen=cache_size)
        self.decode_cache = DecodeCache(maxsize=cache_size)

        # Display state
        self.paused = False
        self.running = False
        self.start_time = time.time()

        # Modes
        self.mode = MODE_LIST
        self.input_buffer = ""
        self.input_prompt = ""

        # Filter & search
        self.filter = PacketFilter("")
        self.search_query = ""

        # Trackers
        self.rate_tracker = RateTracker(window=30)
        self.top_talkers = TopTalkers()

        # Threading
        self._display_thread: Optional[threading.Thread] = None
        self._input_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Terminal state
        self._old_settings = None
        self._terminal_restored = False

        # Performance counters
        self._packets_processed = 0
        self._last_gc = time.time()

        # Differential rendering - cache last drawn screen
        self._last_screen_hash: Optional[int] = None
        self._last_screen_lines: List[str] = []

        # Top talkers state
        self._top_talkers_view = 0  # 0=src, 1=dst, 2=ports, 3=pairs

        # Color rules state
        self._syn_flood_suspects: List[Tuple[str, int]] = []

    # ------------------------------------------------------------
    # Terminal setup
    # ------------------------------------------------------------

    def _setup_terminal(self):
        try:
            self._old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
        except Exception:
            self._old_settings = None

    def _restore_terminal(self):
        if self._old_settings and not self._terminal_restored:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self._old_settings)
                self._terminal_restored = True
            except Exception:
                pass

    # ------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------

    @staticmethod
    def _truncate_ipv6(addr: str, max_len: int) -> str:
        if len(addr) <= max_len:
            return addr
        if addr.count(':') < 2:
            return addr[:max_len]
        parts = addr.split(':')
        if len(parts) >= 4:
            keep_first = 2
            last_seg = parts[-1] if parts[-1] else parts[-2]
            truncated = ':'.join(parts[:keep_first]) + ':...:' + last_seg
            if len(truncated) <= max_len:
                return truncated
        return addr[:max_len - 3] + '...'

    def _get_header_line(self) -> str:
        cols = [
            ("STT", COL_STT),
            ("Thời gian", COL_TIME),
            ("Nguồn", COL_SRC),
            ("Đích", COL_DST),
            ("Proto", COL_PROTO),
            ("Dài", COL_LEN),
            ("Thông tin", COL_INFO),
        ]
        parts = [bold(name.ljust(width)) for name, width in cols]
        return ' '.join(parts)

    def _color_for_packet(self, pkt_info: PacketInfo, decoded: Optional[DecodedPacket]) -> Optional[str]:
        """
        Trả về ANSI color code theo color rules:
        - SYN flood suspect: orange
        - Large packet (>1500): bright
        - Failed TCP (RST): red
        - DNS: cyan
        - HTTP: green
        """
        # Priority order: failed > SYN flood > app_protocol > size > default

        # Failed TCP - RST flag
        if decoded and decoded.tcp:
            flags = decoded.tcp.flags
            if flags & 0x04:  # RST
                return Colors.RED

        # App protocol colors
        if decoded and decoded.proto and decoded.proto.is_app_protocol:
            name = decoded.proto.name
            if name in self.PROTO_COLORS:
                return self.PROTO_COLORS[name]

        # Large packet
        if pkt_info.origlen > JUMBO_PKT_THRESHOLD:
            return Colors.BRIGHT_MAGENTA  # Jumbo
        elif pkt_info.origlen > LARGE_PKT_THRESHOLD:
            return Colors.BRIGHT_WHITE  # Large

        # Base protocol
        if decoded:
            return self.PROTO_COLORS.get(decoded.protocol_name)

        return None

    def _format_packet_row(self, pkt_info: PacketInfo, decoded: Optional[DecodedPacket]) -> str:
        try:
            elapsed = pkt_info.ts_sec - int(self.start_time)
            time_str = f"{elapsed:>8}.{pkt_info.ts_usec // 1000:03d}"

            proto = decoded.protocol_name if decoded else 'UNKNOWN'
            proto_color = self.PROTO_COLORS.get(proto, Colors.WHITE)

            # Highlight search match
            search_match = False
            if self.search_query and decoded:
                search_str = f"{decoded.src_addr} {decoded.dst_addr} {decoded.protocol_name} {decoded.info_str}".lower()
                search_match = self.search_query.lower() in search_str

            src = decoded.src_addr if decoded else ''
            dst = decoded.dst_addr if decoded else ''

            if decoded and decoded.src_port:
                src = f"{src}:{decoded.src_port}"
            if decoded and decoded.dst_port:
                dst = f"{dst}:{decoded.dst_port}"

            src = self._truncate_ipv6(src or '-', COL_SRC - 1).ljust(COL_SRC)
            dst = self._truncate_ipv6(dst or '-', COL_DST - 1).ljust(COL_DST)

            info_str = (decoded.info_str if decoded else '')[:COL_INFO - 1]

            # Apply row color rule
            row_color = self._color_for_packet(pkt_info, decoded)
            if row_color and not search_match:
                # Wrap entire row with color
                row = ' '.join([
                    str(pkt_info.stt).rjust(COL_STT),
                    time_str.ljust(COL_TIME),
                    src,
                    dst,
                    color(proto.ljust(COL_PROTO), proto_color),
                    str(pkt_info.origlen).rjust(COL_LEN),
                    info_str,
                ])
                row = color(row, row_color)
            else:
                # Default rendering
                proto_str = color(proto.ljust(COL_PROTO), proto_color)
                row = ' '.join([
                    str(pkt_info.stt).rjust(COL_STT),
                    time_str.ljust(COL_TIME),
                    src,
                    dst,
                    proto_str,
                    str(pkt_info.origlen).rjust(COL_LEN),
                    info_str,
                ])

            # Highlight search match with reverse video
            if search_match:
                row = f"{Colors.REVERSE}{row}{Colors.RESET}"

            return row
        except Exception:
            return f"{pkt_info.stt:>8} [Error formatting packet]"

    # ------------------------------------------------------------
    # Stats bar & sparkline
    # ------------------------------------------------------------

    def _draw_stats_bar(self, term_width: int) -> str:
        try:
            stats = self.stats_callback()

            parts = [
                f"Nhận: {format_number(stats.get('packets', 0))}",
                f"Rớt: {format_number(stats.get('dropped', 0))}",
                f"Tốc độ: {format_rate(stats.get('pps', 0), ' pkt/s')}",
                f"Băng thông: {format_rate(stats.get('bps', 0) * 8, 'bps')}",
                f"Cache: {len(self.packets)}/{self.cache_size}",
            ]
            stats_str = dim(' | '.join(parts))

            # Sparkline (20 chars)
            pps_graph = self.rate_tracker.get_pps_graph(width=20)
            bps_graph = self.rate_tracker.get_bps_graph(width=20)

            return (
                stats_str + "\n"
                + dim("  pps: ") + pps_graph + " "
                + dim("bps: ") + bps_graph
            )
        except Exception:
            return dim("Stats: N/A")

    def _draw_file_info(self) -> str:
        try:
            file_info = self.file_info_callback()
            current_file = file_info.get('current_file', 'N/A')
            next_rotate = file_info.get('next_rotate', 'N/A')
            retention = file_info.get('retention_days', 7)

            if current_file and len(current_file) > 50:
                current_file = '...' + current_file[-47:]

            return dim(f"File: {current_file} | Cắt: {next_rotate} | Giữ: {retention} ngày")
        except Exception:
            return dim("File: N/A")

    def _draw_protocol_breakdown(self) -> str:
        """Mini protocol breakdown bar."""
        breakdown = self.top_talkers.proto_breakdown()[:6]
        if not breakdown:
            return ""
        total = sum(c for _, c in breakdown) or 1
        parts = []
        for name, count in breakdown[:5]:
            pct = count * 100 // total
            color_code = self.PROTO_COLORS.get(name, Colors.WHITE)
            parts.append(f"{color(name, color_code)}:{pct}%")
        return dim("Proto: ") + ' '.join(parts)

    def _draw_syn_flood_warning(self) -> str:
        """Nếu có SYN flood suspect, hiển thị warning line."""
        if not self._syn_flood_suspects:
            return ""
        top_src, top_rate = self._syn_flood_suspects[0]
        return orange(f"⚠ SYN flood suspect: {top_src} ({top_rate} SYN/s)")

    # ------------------------------------------------------------
    # Top talkers view
    # ------------------------------------------------------------

    def _draw_top_talkers_screen(self, term_width: int, term_height: int) -> List[str]:
        """Render top talkers view."""
        lines = []
        lines.append(bold(" TOP TALKERS ") + dim("[Nhấn t để chuyển tab, Esc để thoát]"))

        # Tab indicator
        tabs = ["SRC IP", "DST IP", "PORTS", "CONVERSATIONS"]
        tab_idx = self._top_talkers_view % len(tabs)
        tab_str = '  '.join(
            (cyan(f"[{t}]") if i == tab_idx else dim(f" {t} "))
            for i, t in enumerate(tabs)
        )
        lines.append(tab_str)
        lines.append(dim('─' * min(term_width, 80)))

        if tab_idx == 0:
            lines.extend(self._render_talker_list(
                self.top_talkers.top_src(15),
                'IP nguồn', '#SRC'
            ))
        elif tab_idx == 1:
            lines.extend(self._render_talker_list(
                self.top_talkers.top_dst(15),
                'IP đích', '#DST'
            ))
        elif tab_idx == 2:
            lines.extend(self._render_port_list(
                self.top_talkers.top_ports(15)
            ))
        elif tab_idx == 3:
            lines.extend(self._render_pair_list(
                self.top_talkers.top_pairs(15)
            ))

        # Fill remaining
        while len(lines) < term_height - 4:
            lines.append('')

        # Stats and controls
        lines.append(dim('─' * min(term_width, 80)))
        lines.append(self._draw_stats_bar(term_width))
        lines.append(dim("[t] Tab tiếp | [Esc] Quay lại list view"))

        return lines

    def _render_talker_list(self, items, header_name, count_label) -> List[str]:
        lines = [bold(f" Top 10 {header_name}"), '']
        max_count = items[0][1] if items else 1
        for i, (name, count) in enumerate(items[:10], 1):
            bar_len = (count * 20 // max_count) if max_count else 0
            bar = '█' * bar_len
            lines.append(f"  {cyan(f'{i:>2}.')} {self._truncate_ipv6(name, 30):<30} "
                         f"{format_number(count):>8} {dim(bar)}")
        return lines

    def _render_port_list(self, items) -> List[str]:
        from core.decoder import get_port_name
        lines = [bold(" Top 10 Ports"), '']
        max_count = items[0][1] if items else 1
        for i, (port, count) in enumerate(items[:10], 1):
            bar_len = (count * 20 // max_count) if max_count else 0
            bar = '█' * bar_len
            name = get_port_name(port) if port else ''
            lines.append(f"  {cyan(f'{i:>2}.')} {yellow(f'{port:<6}')} {dim(name or ''):<20} "
                         f"{format_number(count):>8} {dim(bar)}")
        return lines

    def _render_pair_list(self, items) -> List[str]:
        lines = [bold(" Top 10 Conversations"), '']
        max_count = items[0][1] if items else 1
        for i, ((a, b), count) in enumerate(items[:10], 1):
            bar_len = (count * 20 // max_count) if max_count else 0
            bar = '█' * bar_len
            pair = f"{self._truncate_ipv6(a, 18)} <-> {self._truncate_ipv6(b, 18)}"
            lines.append(f"  {cyan(f'{i:>2}.')} {pair:<40} "
                         f"{format_number(count):>8} {dim(bar)}")
        return lines

    # ------------------------------------------------------------
    # Main screen rendering
    # ------------------------------------------------------------

    def _build_screen(self, term_width: int, term_height: int) -> List[str]:
        """Build list of lines to render."""
        if self.mode == MODE_TOP_TALKERS:
            return self._draw_top_talkers_screen(term_width, term_height)

        # LIST mode
        lines = []
        status = yellow(" [TẠM DỪNG]") if self.paused else green(" [ĐANG CHẠY]")
        mode_extra = ""
        if self.mode == MODE_FILTER_INPUT:
            mode_extra = cyan(f" [FILTER: /{self.input_buffer}_]")
        elif self.mode == MODE_SEARCH_INPUT:
            mode_extra = cyan(f" [SEARCH: /{self.input_buffer}_]")
        elif self.filter.expr:
            mode_extra = dim(f" [Filter: {self.filter.expr}]")
        elif self.search_query:
            mode_extra = dim(f" [Search: {self.search_query}]")

        lines.append(bold(" SNIFF - Đang bắt gói tin ") + status + mode_extra)
        lines.append(self._draw_file_info())
        lines.append(self._draw_protocol_breakdown())
        lines.append('')
        lines.append(self._get_header_line())
        lines.append(dim('─' * min(term_width, 120)))

        # SYN flood warning
        syn_warn = self._draw_syn_flood_warning()
        if syn_warn:
            lines.append(syn_warn)

        # Packets area
        available_lines = term_height - 11  # header(7) + footer(3) + buffer(1)
        if self.filter.expr or self.search_query:
            with self._lock:
                packets_snapshot = list(self.packets)
        else:
            with self._lock:
                packets_snapshot = list(self.packets)[-available_lines:]

        # Filter packets
        displayed = []
        for pkt_info, decoded in packets_snapshot:
            if self.filter.expr and not self.filter.match(pkt_info, decoded):
                continue
            displayed.append((pkt_info, decoded))

        # Nếu có search, highlight match
        if self.search_query:
            displayed = [p for p in displayed if self._matches_search(p)]

        # Nếu có filter, hiển thị hết (không truncate theo available_lines)
        # nếu không thì truncate
        if not self.filter.expr and not self.search_query:
            displayed = displayed[-available_lines:]

        for pkt_info, decoded in displayed:
            row = self._format_packet_row(pkt_info, decoded)
            lines.append(row)

        # Padding
        target = term_height - 4
        while len(lines) < target:
            lines.append('')

        # Stats and controls
        lines.append(dim('─' * min(term_width, 120)))
        lines.append(self._draw_stats_bar(term_width))

        controls = cyan("[Space]") + " Pause  " + \
                   cyan("[S]") + " Save  " + \
                   cyan("[Q]") + " Quit  " + \
                   cyan("[/]") + " Filter  " + \
                   cyan("[t]") + " Talkers  " + \
                   cyan("[Enter]") + " Detail"
        if self.paused:
            controls += "  " + cyan("[s]") + "earch"
        lines.append(controls)

        return lines[:term_height]

    def _matches_search(self, pkt_tuple: Tuple[PacketInfo, Optional[DecodedPacket]]) -> bool:
        pkt_info, decoded = pkt_tuple
        if not self.search_query:
            return True
        if not decoded:
            return False
        search_str = f"{decoded.src_addr} {decoded.dst_addr} {decoded.protocol_name} {decoded.info_str}".lower()
        return self.search_query.lower() in search_str

    def _draw_screen(self, new_packets: List[tuple]):
        """
        Vẽ màn hình với differential rendering.

        Tính hash của screen state, nếu không thay đổi -> skip redraw.
        """
        try:
            term_width, term_height = get_terminal_size()

            # Build screen lines
            lines = self._build_screen(term_width, term_height)

            # Differential: chỉ redraw khi content thay đổi
            content = '\n'.join(lines)
            content_hash = hash(content)

            if content_hash == self._last_screen_hash:
                return  # Không có gì thay đổi, skip

            self._last_screen_hash = content_hash
            self._last_screen_lines = lines

            # Single write call - escape sequences per line
            out = []
            out.append('\033[H')  # Home
            for i, line in enumerate(lines[:term_height]):
                # \033[2K clears entire line, \033[{row};1H positions cursor
                out.append(f'\033[{i + 1};1H\033[2K{line}')

            # Join once, write once
            sys.stdout.write(''.join(out))
            sys.stdout.flush()
        except Exception:
            pass

    # ------------------------------------------------------------
    # Display loop
    # ------------------------------------------------------------

    def _display_loop(self):
        hide_cursor()
        clear_screen()
        self._last_screen_hash = None

        last_draw = 0
        last_rate_sample = 0
        last_syn_check = 0
        new_packets = []
        batch_size = 100

        while self.running:
            try:
                # Khi PAUSED: KHÔNG drop queue (pause-keep-state)
                # Chỉ đơn giản skip decode/display, queue vẫn được đọc
                if self.paused:
                    # Drain một phần queue để tránh tràn kernel buffer,
                    # nhưng KHÔNG decode hay hiển thị
                    drained = 0
                    try:
                        while drained < 1000:
                            self.packet_queue.get_nowait()
                            drained += 1
                    except queue.Empty:
                        pass

                    # Sleep dài hơn khi paused
                    time.sleep(0.2)
                    # Vẫn redraw định kỳ để show "paused" state
                    now = time.time()
                    if now - last_draw >= 0.5:
                        self._draw_screen([])
                        last_draw = now
                    continue

                # RUNNING: đọc batch và xử lý
                packets_read = 0
                while packets_read < batch_size:
                    try:
                        pkt_info = self.packet_queue.get_nowait()

                        # Decode với cache
                        decoded = self.decode_cache.get_or_decode(pkt_info)

                        with self._lock:
                            self.packets.append((pkt_info, decoded))

                        # Track top talkers
                        self.top_talkers.record(decoded, pkt_info.origlen)
                        new_packets.append((pkt_info, decoded))
                        packets_read += 1
                        self._packets_processed += 1

                    except queue.Empty:
                        break

                # Sample rate cho sparkline (mỗi giây)
                now = time.time()
                if now - last_rate_sample >= 1.0:
                    stats = self.stats_callback()
                    self.rate_tracker.update(
                        stats.get('packets', 0),
                        stats.get('bytes', 0),
                    )
                    last_rate_sample = now

                # Check SYN flood (mỗi 2s)
                if now - last_syn_check >= 2.0:
                    self._syn_flood_suspects = self.top_talkers.check_syn_flood()
                    last_syn_check = now

                # Vẽ lại màn hình (max 10 FPS)
                if now - last_draw >= 0.1:
                    self._draw_screen(new_packets)
                    new_packets.clear()
                    last_draw = now

                # Periodic GC (mỗi 30 giây)
                if now - self._last_gc >= 30.0:
                    gc.collect()
                    self._last_gc = now

                # Sleep ngắn để giảm CPU khi idle
                if packets_read == 0:
                    time.sleep(0.02)
                else:
                    time.sleep(0.005)

            except Exception:
                time.sleep(0.1)

        show_cursor()

    # ------------------------------------------------------------
    # Input loop
    # ------------------------------------------------------------

    def _handle_input_char(self, ch: str):
        """Xử lý 1 char trong input mode (filter/search)."""
        if ch == '\x1b':  # ESC
            self.mode = MODE_LIST
            self.input_buffer = ""
            return
        elif ch in ('\r', '\n'):  # Enter
            if self.mode == MODE_FILTER_INPUT:
                self.filter = PacketFilter(self.input_buffer)
            elif self.mode == MODE_SEARCH_INPUT:
                self.search_query = self.input_buffer
            self.mode = MODE_LIST
            self.input_buffer = ""
            return
        elif ch == '\x7f' or ch == '\b':  # Backspace
            self.input_buffer = self.input_buffer[:-1]
            return
        elif ch == '\x03':  # Ctrl+C
            self.running = False
            self.on_quit()
            return
        elif ch.isprintable():
            self.input_buffer += ch

    def _input_loop(self):
        while self.running:
            try:
                # Check input available
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    ch = sys.stdin.read(1)

                    # Input mode: gõ filter hoặc search
                    if self.mode in (MODE_FILTER_INPUT, MODE_SEARCH_INPUT):
                        self._handle_input_char(ch)
                        # Redraw ngay để update input buffer
                        self._last_screen_hash = None
                        continue

                    # Normal mode
                    if ch == ' ':
                        # Toggle pause
                        self.paused = not self.paused
                        if self.on_pause:
                            try:
                                self.on_pause(self.paused)
                            except Exception:
                                pass
                        if not self.paused:
                            # Clear queue on resume
                            cleared = 0
                            try:
                                while True:
                                    self.packet_queue.get_nowait()
                                    cleared += 1
                            except queue.Empty:
                                pass
                            # Reset top talkers on resume (fresh session)
                            self.top_talkers.reset()
                            self.rate_tracker = RateTracker(window=30)
                    elif ch.lower() == 's' and not self.paused:
                        # Save and exit
                        self.running = False
                        if self._display_thread:
                            self._display_thread.join(timeout=0.5)
                        self._restore_terminal()
                        show_cursor()
                        if self.on_save_exit:
                            try:
                                self.on_save_exit()
                            except Exception:
                                pass
                    elif ch.lower() == 'q':
                        self.running = False
                        self.on_quit()
                    elif ch == '/':
                        # Vào filter input mode (hoặc search nếu paused)
                        if self.paused:
                            self.mode = MODE_SEARCH_INPUT
                            self.input_buffer = self.search_query
                        else:
                            self.mode = MODE_FILTER_INPUT
                            self.input_buffer = self.filter.expr
                        self._last_screen_hash = None
                    elif ch.lower() == 't':
                        # Toggle top talkers view
                        if self.mode == MODE_TOP_TALKERS:
                            self._top_talkers_view += 1
                        else:
                            self.mode = MODE_TOP_TALKERS
                            self._top_talkers_view = 0
                        self._last_screen_hash = None
                    elif ch == '\x1b':  # ESC
                        if self.mode == MODE_TOP_TALKERS:
                            self.mode = MODE_LIST
                            self._last_screen_hash = None
                    elif ch == '\r' or ch == '\n':
                        # Enter detail view for newest packet
                        if self.on_show_detail and self.packets:
                            last_pkt = self.packets[-1][0]
                            try:
                                self.on_show_detail(last_pkt.stt)
                            except Exception:
                                pass
            except Exception:
                pass

    # ------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------

    def start(self):
        """Bắt đầu hiển thị."""
        self.running = True
        self.start_time = time.time()
        self.packets.clear()
        self.decode_cache.clear()
        self.paused = False
        self.mode = MODE_LIST
        self.input_buffer = ""
        self.search_query = ""
        self.filter = PacketFilter("")
        self.top_talkers.reset()
        self.rate_tracker = RateTracker(window=30)
        self._syn_flood_suspects = []
        self._last_screen_hash = None
        self._packets_processed = 0
        self._last_gc = time.time()
        self._terminal_restored = False

        self._setup_terminal()

        self._display_thread = threading.Thread(target=self._display_loop, daemon=True)
        self._input_thread = threading.Thread(target=self._input_loop, daemon=True)

        self._display_thread.start()
        self._input_thread.start()

    def stop(self):
        """Dừng hiển thị."""
        self.running = False

        if self._display_thread:
            self._display_thread.join(timeout=1.0)
        if self._input_thread:
            self._input_thread.join(timeout=1.0)

        if not self._terminal_restored:
            self._restore_terminal()
            show_cursor()

        self.packets.clear()
        self.decode_cache.clear()
        gc.collect()

    def wait(self):
        """Chờ cho đến khi dừng."""
        while self.running:
            time.sleep(0.1)

    # ------------------------------------------------------------
    # External API
    # ------------------------------------------------------------

    def set_filter(self, expr: str):
        """Set filter từ bên ngoài."""
        self.filter = PacketFilter(expr)
        self._last_screen_hash = None

    def get_filter(self) -> str:
        return self.filter.expr
