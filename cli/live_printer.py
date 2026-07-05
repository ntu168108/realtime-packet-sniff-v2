"""Live NDJSON printer for the --live mode."""

import sys
import json

from core.decoder import decode_packet
from core.display_filter import DisplayFilter


class LivePrinter:
    """
    Stream packets as NDJSON (one JSON object per line) to stdout.
    Designed for piping to jq / grep / file.
    """

    def __init__(self, display_filter: str = "", exclude_ports=None):
        self._out = sys.stdout
        try:
            # Force line-buffered stdout for live piping
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(line_buffering=True)
        except Exception:
            pass
        self._filter = DisplayFilter(display_filter) if display_filter else None
        self._exclude_ports = set(exclude_ports or [])
        self._packets_emitted = 0

    def emit(self, pkt_info) -> bool:
        """Decode + filter + emit packet. Return True if emitted."""
        try:
            decoded = decode_packet(pkt_info.data, deep=False)
        except Exception:
            return False

        # Exclude ports
        if self._exclude_ports:
            if (decoded.src_port in self._exclude_ports or
                    decoded.dst_port in self._exclude_ports):
                return False

        # Display filter
        if self._filter and not self._filter.match(decoded):
            return False

        src = decoded.src_addr or "-"
        dst = decoded.dst_addr or "-"
        if decoded.src_port:
            src = f"{src}:{decoded.src_port}"
        if decoded.dst_port:
            dst = f"{dst}:{decoded.dst_port}"

        record = {
            "ts": f"{pkt_info.ts_sec}.{pkt_info.ts_usec:06d}",
            "stt": pkt_info.stt,
            "src": src,
            "dst": dst,
            "proto": decoded.protocol_name or "UNKNOWN",
            "len": pkt_info.caplen,
            "info": (decoded.info_str or "")[:160],
        }
        line = json.dumps(record, ensure_ascii=False) + "\n"
        try:
            self._out.write(line)
            self._packets_emitted += 1
            return True
        except (BrokenPipeError, OSError):
            # Downstream pipe closed (e.g. head exited)
            return False
