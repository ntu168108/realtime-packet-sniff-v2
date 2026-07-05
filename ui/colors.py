"""
ANSI Color utilities và UI helpers
"""

import os
import sys
from typing import List, Optional


# ============================================================
# ANSI Escape Codes
# ============================================================

class Colors:
    """ANSI color codes"""

    # Reset
    RESET = '\033[0m'

    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    REVERSE = '\033[7m'

    # Foreground colors
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Bright foreground
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    # Extended colors (256-color palette) - for sparklines etc.
    # Various gradient stops for sparklines
    SPARK_LOW = '\033[38;5;24m'
    SPARK_MID = '\033[38;5;82m'
    SPARK_HIGH = '\033[38;5;220m'


class Cursor:
    """Cursor control sequences"""

    # Cursor movement
    UP = '\033[{n}A'
    DOWN = '\033[{n}B'
    FORWARD = '\033[{n}C'
    BACK = '\033[{n}D'

    # Cursor position
    HOME = '\033[H'
    POSITION = '\033[{row};{col}H'

    # Save/restore
    SAVE = '\033[s'
    RESTORE = '\033[u'

    # Visibility
    HIDE = '\033[?25l'
    SHOW = '\033[?25h'


class Screen:
    """Screen control sequences"""

    # Clear screen
    CLEAR = '\033[2J'
    CLEAR_LINE = '\033[2K'
    CLEAR_TO_END = '\033[0J'
    CLEAR_TO_LINE_END = '\033[0K'

    # Scrolling
    SCROLL_UP = '\033[{n}S'
    SCROLL_DOWN = '\033[{n}T'


# ============================================================
# Helper functions
# ============================================================

def supports_color() -> bool:
    """Kiểm tra terminal có hỗ trợ màu không"""
    # Kiểm tra biến môi trường
    if os.environ.get('NO_COLOR'):
        return False
    if os.environ.get('FORCE_COLOR'):
        return True

    # Kiểm tra stdout
    if not hasattr(sys.stdout, 'isatty'):
        return False
    if not sys.stdout.isatty():
        return False

    # Kiểm tra TERM
    term = os.environ.get('TERM', '')
    if term == 'dumb':
        return False

    return True


_color_enabled = supports_color()


def color(text: str, *codes) -> str:
    """
    Thêm màu vào text

    Usage:
        color("Hello", Colors.RED, Colors.BOLD)
    """
    if not _color_enabled or not codes:
        return text

    prefix = ''.join(codes)
    return f"{prefix}{text}{Colors.RESET}"


def red(text: str) -> str:
    return color(text, Colors.RED)


def green(text: str) -> str:
    return color(text, Colors.GREEN)


def yellow(text: str) -> str:
    return color(text, Colors.YELLOW)


def blue(text: str) -> str:
    return color(text, Colors.BLUE)


def cyan(text: str) -> str:
    return color(text, Colors.CYAN)


def magenta(text: str) -> str:
    return color(text, Colors.MAGENTA)


def white(text: str) -> str:
    return color(text, Colors.WHITE)


def bold(text: str) -> str:
    return color(text, Colors.BOLD)


def dim(text: str) -> str:
    return color(text, Colors.DIM)


def bright(text: str) -> str:
    """Bright white - dùng cho large packets (>1500)"""
    return color(text, Colors.BRIGHT_WHITE, Colors.BOLD)


def success(text: str) -> str:
    return color(text, Colors.GREEN, Colors.BOLD)


def error(text: str) -> str:
    return color(text, Colors.RED, Colors.BOLD)


def info(text: str) -> str:
    return color(text, Colors.CYAN)


# ============================================================
# Protocol-based coloring helpers
# ============================================================

# Map tên protocol sang màu ANSI
PROTOCOL_COLOR_MAP = {
    'TCP': Colors.GREEN,
    'UDP': Colors.BLUE,
    'ICMP': Colors.MAGENTA,
    'ICMPv6': Colors.MAGENTA,
    'ARP': Colors.YELLOW,
    'IPv4': Colors.CYAN,
    'IPv6': Colors.CYAN,
    'IGMP': Colors.BRIGHT_MAGENTA,
    'DNS': Colors.CYAN,
    'HTTP': Colors.GREEN,
    'TLS': Colors.BRIGHT_BLUE,
    'SSL': Colors.BRIGHT_BLUE,
    'QUIC': Colors.BRIGHT_BLUE,
    'DHCP': Colors.BRIGHT_YELLOW,
    'NTP': Colors.YELLOW,
    'SSH': Colors.BRIGHT_GREEN,
    'FTP': Colors.BRIGHT_GREEN,
    'SMTP': Colors.BRIGHT_GREEN,
    'TELNET': Colors.BRIGHT_YELLOW,
    'SNMP': Colors.BRIGHT_MAGENTA,
    'RDP': Colors.BRIGHT_MAGENTA,
}


def format_protocol(pkt) -> str:
    """
    Trả về protocol name đã được wrap màu ANSI theo protocol.

    Args:
        pkt: DecodedPacket hoặc bất kỳ object có thuộc tính `.protocol_name`

    Returns:
        Colored protocol string (e.g., green "TCP", cyan "DNS")
    """
    if pkt is None:
        return dim('UNKNOWN')
    proto_name = getattr(pkt, 'protocol_name', 'UNKNOWN') or 'UNKNOWN'
    color_code = PROTOCOL_COLOR_MAP.get(proto_name, Colors.WHITE)
    return color(proto_name, color_code)


# ============================================================
# Sparkline / Rate graph
# ============================================================

# Unicode block characters for sparklines (8 levels of intensity)
SPARK_CHARS = ' ▁▂▃▄▅▆▇█'


def format_rate_graph(
    values: List[int],
    width: Optional[int] = None,
    color: bool = True,
) -> str:
    """
    Tạo sparkline mini chart từ list giá trị số.

    Sử dụng Unicode block chars (U+2581..U+2588) để vẽ mini chart
    của pps/bps theo thời gian.

    Args:
        values: list các giá trị số theo thứ tự thời gian (cũ -> mới)
        width: số cột tối đa (None = dùng hết list)
        color: True = gradient màu theo intensity

    Returns:
        String sparkline có thể in trực tiếp vào stats bar
    """
    if not values:
        return dim(' ' * (width or 8))

    # Lấy width giá trị cuối (mới nhất ở bên phải)
    if width and len(values) > width:
        values = values[-width:]
    elif width:
        # Pad với space nếu chưa đủ width
        values = ([0] * (width - len(values))) + list(values)

    if not values:
        return ' ' * (width or 8)

    max_val = max(values) or 1
    out_chars = []
    out_colors = []

    for v in values:
        # Map 0..max_val -> 0..8 (block char index)
        ratio = v / max_val if max_val > 0 else 0
        idx = min(len(SPARK_CHARS) - 1, int(ratio * (len(SPARK_CHARS) - 1)))
        out_chars.append(SPARK_CHARS[idx])

        if color and _color_enabled:
            if ratio < 0.33:
                out_colors.append(Colors.SPARK_LOW)
            elif ratio < 0.66:
                out_colors.append(Colors.SPARK_MID)
            else:
                out_colors.append(Colors.SPARK_HIGH)
        else:
            out_colors.append('')

    # Build string với màu
    if color and _color_enabled:
        parts = []
        for ch, cl in zip(out_chars, out_colors):
            if cl:
                parts.append(f"{cl}{ch}{Colors.RESET}")
            else:
                parts.append(ch)
        return ''.join(parts)

    return ''.join(out_chars)


# ============================================================
# Screen functions
# ============================================================

def clear_screen():
    """Xóa màn hình"""
    if _color_enabled:
        print(Screen.CLEAR + Cursor.HOME, end='', flush=True)
    else:
        # Fallback: print nhiều dòng trống
        print('\n' * 50)


def move_cursor(row: int, col: int):
    """Di chuyển cursor đến vị trí"""
    if _color_enabled:
        print(f'\033[{row};{col}H', end='', flush=True)


def hide_cursor():
    """Ẩn cursor"""
    if _color_enabled:
        print(Cursor.HIDE, end='', flush=True)


def show_cursor():
    """Hiện cursor"""
    if _color_enabled:
        print(Cursor.SHOW, end='', flush=True)


def get_terminal_size() -> tuple:
    """Lấy kích thước terminal (columns, rows)"""
    try:
        size = os.get_terminal_size()
        return (size.columns, size.lines)
    except Exception:
        return (80, 24)  # Default


# ============================================================
# UI Components
# ============================================================

def print_header(text: str, char: str = '='):
    """In header với đường kẻ"""
    width = get_terminal_size()[0]
    line = char * width
    print(dim(line))
    print(bold(text.center(width)))
    print(dim(line))


def print_divider(char: str = '-'):
    """In đường kẻ ngang"""
    width = get_terminal_size()[0]
    print(dim(char * width))


def print_menu_item(key: str, text: str, selected: bool = False):
    """In một menu item"""
    if selected:
        print(f"  {bright('[' + key + ']')} {bold(text)}")
    else:
        print(f"  {cyan('[' + key + ']')} {text}")


def print_status(label: str, value: str, status_type: str = 'info'):
    """In status line"""
    label_formatted = f"{label}:"
    if status_type == 'success':
        value_formatted = success(value)
    elif status_type == 'error':
        value_formatted = error(value)
    else:
        value_formatted = info(value)

    print(f"  {dim(label_formatted)} {value_formatted}")


def format_number(n: int) -> str:
    """Format số với dấu phẩy phân cách"""
    return f"{n:,}"


def format_rate(rate: float, unit: str = '/s') -> str:
    """Format rate với đơn vị phù hợp"""
    if rate >= 1_000_000:
        return f"{rate / 1_000_000:.2f}M{unit}"
    elif rate >= 1_000:
        return f"{rate / 1_000:.2f}K{unit}"
    else:
        return f"{rate:.2f}{unit}"