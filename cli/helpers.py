"""CLI helpers: paths, version, logging, small utility functions."""

import os
import sys
import shutil
import logging
import logging.handlers
from pathlib import Path

from ui.colors import red, yellow, bold

# --- Version & paths ---
__version__ = "0.2.0"

# helpers.py lives at cli/helpers.py, so its parent's parent is the repo root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = PROJECT_ROOT / "sniff_data"
DEFAULT_PID_FILE = "/var/run/sniff.pid"
DEFAULT_LOG_FILE = "/var/log/sniff/sniff.log"
DEFAULT_LOG_DIR = "/var/log/sniff"

# Minimum free disk bytes (100 MB) before we start warning
MIN_FREE_DISK_BYTES = 100 * 1024 * 1024


# ----------------------------- Logging setup -----------------------------

def setup_logging(log_file: str, verbose: bool = False):
    """Configure root logger; line-buffered file so tail -f works."""
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Reset handlers (avoid duplicates if main() called twice in tests)
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        '%(asctime)s %(levelname)-7s [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    # Console (stderr, line-buffered)
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(fmt)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.addHandler(console)

    # File (rotated)
    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        # Rotate at 10MB, keep 5 backups
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5,
            encoding="utf-8",
        )
        fh.setFormatter(fmt)
        fh.setLevel(logging.DEBUG)
        root.addHandler(fh)
    except OSError as e:
        # Fall back to stderr-only if cannot write to log file
        sys.stderr.write(f"warn: cannot open log file {log_file}: {e}\n")


logger = logging.getLogger('sniff')


# ----------------------------- Helpers -----------------------------

def check_root():
    if os.geteuid() != 0:
        sys.stderr.write(red("Error: Root privileges required for packet capture\n"))
        sys.stderr.write(f"Run with: sudo {sys.argv[0]} ...\n")
        sys.exit(1)


def ensure_output_dir(path: str) -> Path:
    """Create output dir if missing; check writability. Exit on failure."""
    p = Path(path)
    try:
        p.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.stderr.write(red(f"Error: cannot create output dir {p}: {e}\n"))
        sys.exit(2)
    if not os.access(p, os.W_OK | os.X_OK):
        sys.stderr.write(red(f"Error: output dir {p} is not writable\n"))
        sys.exit(2)
    return p


def check_disk_space(path: str) -> int:
    """Return free bytes on the filesystem containing `path`. Warn if low."""
    try:
        usage = shutil.disk_usage(path)
        free = usage.free
        if free < MIN_FREE_DISK_BYTES:
            sys.stderr.write(yellow(
                f"Warning: only {free // (1024*1024)} MB free at {path} "
                f"(threshold {MIN_FREE_DISK_BYTES // (1024*1024)} MB)\n"
            ))
        return free
    except OSError as e:
        sys.stderr.write(yellow(f"Warning: cannot stat disk usage: {e}\n"))
        return -1


def parse_size_mb(s: str) -> int:
    """Parse '500' or '500MB' to bytes."""
    s = str(s).strip().upper()
    if s.endswith("MB"):
        s = s[:-2]
    elif s.endswith("GB"):
        return int(float(s[:-2]) * 1024 * 1024 * 1024)
    elif s.endswith("KB"):
        return int(float(s[:-2]) * 1024)
    return int(float(s) * 1024 * 1024)


def parse_time_secs(s: str) -> int:
    """Parse '60', '60s', '5m', '1h', '1d' to seconds."""
    s = str(s).strip().lower()
    if s.endswith("d"):
        return int(s[:-1]) * 86400
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("s"):
        s = s[:-1]
    return int(s)


SUPPORTED_PROTOCOLS = (
    "Ethernet", "IPv4", "IPv6", "TCP", "UDP", "ICMP", "ICMPv6", "ARP",
    "IGMP", "DNS", "HTTP", "TLS", "QUIC", "DHCP", "NTP",
)


def list_protocols():
    """Print supported protocols and exit."""
    print(bold("\nSupported protocols:"))
    for p in SUPPORTED_PROTOCOLS:
        print(f"  - {p}")
    print()
    print("Deep L7 detection (--display-filter) recognises: " +
          ", ".join(SUPPORTED_PROTOCOLS[9:]))
    print()
    sys.exit(0)
