"""Main application class for sniff."""

import os
import sys
import time
import json
import signal
import logging
import threading
from pathlib import Path

from core.capture import CaptureEngine
from core.rotator import HourlyRotator
from core.constants import (
    BUFFER_PROFILES, DEFAULT_SNAPLEN, DEFAULT_PROMISC, DEFAULT_RETENTION_DAYS,
    DEFAULT_MAX_FILE_SIZE,
)
from core.decoder import decode_packet
from ui.list_view import PacketListView
from ui.colors import show_cursor, clear_screen, success, info, bold
from modules.runner import create_runner

from cli.live_printer import LivePrinter
from cli.helpers import (
    setup_logging, check_disk_space, MIN_FREE_DISK_BYTES,
    DEFAULT_DATA_DIR, DEFAULT_PID_FILE, DEFAULT_LOG_FILE, __version__,
)


logger = logging.getLogger('sniff')


class SniffApp:
    """Main application class"""

    def __init__(
        self,
        data_dir: str = None,
        interface: str = None,
        bpf_filter: str = "",
        snaplen: int = DEFAULT_SNAPLEN,
        promisc: bool = DEFAULT_PROMISC,
        buffer_profile: str = "balanced",
        retention_days: int = DEFAULT_RETENTION_DAYS,
        enable_modules: bool = True,
        pid_file: str = DEFAULT_PID_FILE,
        log_file: str = DEFAULT_LOG_FILE,
        live: bool = False,
        display_filter: str = "",
        count: int = 0,
        rotate_interval: int = 3600,
        rotate_size_mb: int = 0,
        no_rotate: bool = False,
        exclude_ports=None,
    ):
        self.data_dir = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snaplen = snaplen
        self.promisc = promisc
        self.buffer_profile = buffer_profile
        self.retention_days = retention_days
        self.enable_modules = enable_modules
        self.pid_file = pid_file
        self.log_file = log_file
        self.live = live
        self.display_filter_expr = display_filter
        self.count = count
        self.rotate_interval = rotate_interval
        self.rotate_size_mb = rotate_size_mb
        self.no_rotate = no_rotate
        self.exclude_ports = exclude_ports or []

        # Components
        self.capture: CaptureEngine = None
        self.rotator: HourlyRotator = None
        self.module_runner = None
        self.list_view: PacketListView = None
        self.live_printer: LivePrinter = None

        # State
        self._running = False
        self._shutdown_requested = False
        self._stop_reason = "user"
        self._lock = threading.Lock()

    # --- Signal handling (top of main so daemonize races don't matter) ---

    def _setup_signal_handlers(self):
        """Install signal handlers. Use SA_RESTART semantics where possible."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        try:
            signal.signal(signal.SIGHUP, self._sighup_handler)
        except (OSError, ValueError):
            pass
        try:
            signal.signal(signal.SIGUSR1, self._sigusr1_handler)
        except (OSError, ValueError):
            pass
        try:
            signal.signal(signal.SIGUSR2, self._sigusr2_handler)
        except (OSError, ValueError):
            pass

    def _signal_handler(self, signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info(f"Received {sig_name}, initiating graceful shutdown...")
        self._shutdown_requested = True
        self._stop_reason = sig_name
        # Schedule stop in main thread context
        try:
            if self.capture:
                self.capture._stop_event.set()
        except Exception:
            pass

    def _sighup_handler(self, signum, frame):
        """Re-open log file (for external logrotate)."""
        logger.info("SIGHUP received - reopening log handlers")
        # Simpler: re-install handlers
        try:
            setup_logging(self.log_file, verbose=False)
        except Exception as e:
            sys.stderr.write(f"warn: log reopen failed: {e}\n")

    def _sigusr1_handler(self, signum, frame):
        """Toggle verbose logging."""
        root = logging.getLogger()
        new_level = logging.DEBUG if root.level > logging.DEBUG else logging.INFO
        root.setLevel(new_level)
        logger.info(f"SIGUSR1: log level -> {logging.getLevelName(new_level)}")

    def _sigusr2_handler(self, signum, frame):
        """Force file rotation now."""
        logger.info("SIGUSR2: force rotation")
        if self.rotator:
            try:
                self.rotator.force_rotate()
            except Exception as e:
                logger.error(f"force_rotate failed: {e}")

    def _on_rotate(self, pcap_path: str, interface: str, time_window: str):
        """Callback when file rotates - queue for analysis"""
        if self.module_runner:
            self.module_runner.queue_analysis(pcap_path, interface, time_window)

    # --- Setup ---

    def setup(self):
        """Setup all components"""
        # Create directories
        self.data_dir.mkdir(parents=True, exist_ok=True)
        raw_dir = self.data_dir / "raw"
        raw_dir.mkdir(exist_ok=True)
        modules_dir = self.data_dir / "modules"
        modules_dir.mkdir(exist_ok=True)

        check_disk_space(str(self.data_dir))

        # Get buffer profile
        profile = BUFFER_PROFILES.get(self.buffer_profile, BUFFER_PROFILES['balanced'])

        # Setup module runner
        if self.enable_modules and not self.live:
            self.module_runner = create_runner(
                output_dir=str(modules_dir),
                auto_discover=True
            )

        # Setup rotator
        if self.no_rotate:
            # Single file: filename based on interface + epoch
            rotator_kwargs = dict(
                base_dir=str(raw_dir),
                interface=self.interface,
                snaplen=self.snaplen,
                retention_days=self.retention_days,
                on_rotate=self._on_rotate if self.module_runner else None,
            )
            # Disable size rotation effectively (huge value)
            rotator_kwargs["max_file_size"] = 0  # 0 disables size rotation
            self.rotator = HourlyRotator(**rotator_kwargs)
        else:
            self.rotator = HourlyRotator(
                base_dir=str(raw_dir),
                interface=self.interface,
                snaplen=self.snaplen,
                retention_days=self.retention_days,
                on_rotate=self._on_rotate if self.module_runner else None,
                max_file_size=(self.rotate_size_mb * 1024 * 1024
                               if self.rotate_size_mb > 0
                               else DEFAULT_MAX_FILE_SIZE),
            )

        # Live mode: prep stdout printer
        if self.live:
            self.live_printer = LivePrinter(
                display_filter=self.display_filter_expr,
                exclude_ports=self.exclude_ports,
            )

        # Setup capture engine
        self.capture = CaptureEngine(
            interface=self.interface,
            bpf_filter=self.bpf_filter,
            snaplen=self.snaplen,
            promisc=self.promisc,
            buffer_size=profile['buffer_size'],
            queue_size=profile['queue_size'],
            rotator=(self.rotator
                     if not (self.live and self.no_rotate)
                     else None),  # live+no-rotate => no PCAP file at all
            count=self.count,
            on_packet_filtered=(self._on_live_packet
                                if self.live else None),
        )

        # Initialize capture engine
        self.capture.setup()

        logger.info(
            f"Setup complete - Interface: {self.interface}, "
            f"Data dir: {self.data_dir}, "
            f"count={self.count or 'inf'}, "
            f"rotate_interval={self.rotate_interval}s, "
            f"rotate_size_mb={self.rotate_size_mb or 'default'}, "
            f"no_rotate={self.no_rotate}, "
            f"live={self.live}"
        )

    def _on_live_packet(self, pkt_info) -> None:
        """Capture-engine hook for live mode: print to stdout."""
        if self.live_printer is None:
            return
        try:
            emitted = self.live_printer.emit(pkt_info)
            if not emitted:
                # Downstream pipe closed: stop capture
                self.capture._stop_event.set()
        except Exception as e:
            logger.debug(f"live emit error: {e}")

    # --- Lifecycle ---

    def start(self):
        if self._running:
            return
        self._running = True

        # Start module runner
        if self.module_runner:
            self.module_runner.start()

        # Start capture
        self.capture.start()

        logger.info("Capture started")

    def stop(self):
        if not self._running:
            return
        self._running = False
        logger.info(f"Stopping capture (reason: {self._stop_reason})")

        # Stop list view first
        if self.list_view:
            try:
                self.list_view.stop()
            except Exception as e:
                logger.error(f"list_view.stop error: {e}")

        # Stop capture (flushes + closes dispatcher)
        if self.capture:
            try:
                self.capture.stop()
            except Exception as e:
                logger.error(f"capture.stop error: {e}")

        # Flush + close rotator (writes any pending PCAP block buffer to disk)
        if self.rotator:
            try:
                self.rotator.close()
            except Exception as e:
                logger.error(f"rotator.close error: {e}")

        # Stop module runner
        if self.module_runner:
            try:
                self.module_runner.stop(wait=True)
            except Exception as e:
                logger.error(f"module_runner.stop error: {e}")

        logger.info("Capture stopped")

    # --- Accessors / callbacks ---

    def _get_stats(self) -> dict:
        if self.capture:
            stats = self.capture.stats
            return {
                'packets': stats.packets,
                'dropped': stats.dropped + stats.queue_dropped,
                'bytes': stats.bytes,
                'pps': stats.pps,
                'bps': stats.bps,
                'paused': self.capture.is_paused,
            }
        return {}

    def _get_file_info(self) -> dict:
        if self.rotator:
            return {
                'current_file': self.rotator.current_filepath,
                'next_rotate': (self.rotator.next_rotate_time.strftime('%H:%M:%S')
                                if self.rotator.next_rotate_time else 'N/A'),
                'retention_days': self.retention_days,
            }
        return {}

    def _on_pause(self, paused: bool):
        if self.capture:
            if paused:
                self.capture.pause()
            else:
                self.capture.resume()

    def _on_save_exit(self):
        clear_screen()
        print()
        print(success("Đang lưu file..."))
        if self.rotator:
            self.rotator.flush()
            current_file = self.rotator.current_filepath
            if current_file:
                print(info(f"File đã lưu: {current_file}"))
        self._print_summary()
        print()
        print(info("Tạm biệt!"))
        time.sleep(1)

    def _on_quit(self):
        self.stop()

    def _print_summary(self) -> None:
        print()
        print(bold("Thống kê phiên capture:"))
        if self.capture:
            stats = self.capture.stats
            print(f"  Tổng gói:    {stats.packets:,}")
            print(f"  Tổng bytes:  {stats.bytes:,}")
            print(f"  Rớt:         {stats.dropped + stats.queue_dropped:,}")
        if self.live_printer:
            print(f"  Live NDJSON: {self.live_printer._packets_emitted:,} lines")

    def _write_summary_file(self) -> None:
        """Write JSON summary at the end (live + daemon mode)."""
        if not self.capture:
            return
        try:
            stats = self.capture.stats
            summary = {
                "version": __version__,
                "interface": self.interface,
                "stop_reason": self._stop_reason,
                "stop_time": time.time(),
                "packets": stats.packets,
                "bytes": stats.bytes,
                "dropped": stats.dropped,
                "queue_dropped": stats.queue_dropped,
                "write_dropped": stats.write_dropped,
                "protocols": dict(stats.proto_counts) if stats.proto_counts else {},
            }
            if self.rotator and self.rotator.current_filepath:
                summary["current_pcap"] = self.rotator.current_filepath
            if self.live_printer:
                summary["live_emitted"] = self.live_printer._packets_emitted
            # Sidecar JSON next to current PCAP
            if self.rotator and self.rotator.current_filepath:
                sidecar = str(self.rotator.current_filepath) + ".summary.json"
                with open(sidecar, "w") as f:
                    json.dump(summary, f, indent=2)
                logger.info(f"Summary written to {sidecar}")
            else:
                # No rotator; write to data_dir
                p = self.data_dir / "last_session.summary.json"
                with open(p, "w") as f:
                    json.dump(summary, f, indent=2)
                logger.info(f"Summary written to {p}")
        except Exception as e:
            logger.error(f"write_summary_file error: {e}")

    # --- Run modes ---

    def run_interactive(self):
        """Run with interactive UI"""
        self.setup()
        self.start()

        self.list_view = PacketListView(
            packet_queue=self.capture.packet_queue,
            on_quit=self._on_quit,
            stats_callback=self._get_stats,
            file_info_callback=self._get_file_info,
            on_pause=self._on_pause,
            on_save_exit=self._on_save_exit,
        )

        try:
            self.list_view.start()
            self.list_view.wait()
        finally:
            show_cursor()
            self.stop()

    def run_live(self):
        """Live NDJSON streaming mode (no TUI)."""
        self.setup()
        self.start()
        logger.info("Running in LIVE mode - NDJSON to stdout")
        # Wait for stop event (count limit, SIGTERM, broken pipe)
        try:
            while not self._shutdown_requested and self.capture._running:
                time.sleep(0.5)
                if self.count and self.capture.stats.packets >= self.count:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            self._write_summary_file()
            self.stop()

    def run_daemon(self):
        """Run as daemon (headless)"""
        self.setup()
        self.start()
        logger.info("Running in daemon mode (headless)")

        # Periodic checks (disk, FD count, stats log) every 30s
        last_check = time.monotonic()
        check_interval = 30.0
        last_low_disk_warn = 0.0
        try:
            while not self._shutdown_requested:
                # Signal-based event wait (interruptible by SIGTERM)
                if self.capture._stop_event.wait(timeout=1.0):
                    break
                now = time.monotonic()
                if now - last_check >= check_interval:
                    last_check = now
                    # Disk check
                    free = check_disk_space(str(self.data_dir))
                    if 0 < free < MIN_FREE_DISK_BYTES:
                        if now - last_low_disk_warn > 300:  # at most every 5 min
                            logger.warning(
                                f"Low disk: {free // (1024*1024)} MB free; "
                                f"consider -r 1 or larger --rotate-size"
                            )
                            last_low_disk_warn = now
                    # FD count (warn if >80% of system limit)
                    self._check_fd_count()
                    # Stats log every 10k packets
                    stats = self.capture.stats
                    if stats.packets > 0 and stats.packets % 10000 == 0:
                        logger.info(
                            f"Stats: {stats.packets} pkts, {stats.bytes} bytes, "
                            f"PPS: {stats.pps:.1f}, "
                            f"Dropped: {stats.dropped + stats.queue_dropped}"
                        )
        except KeyboardInterrupt:
            pass
        finally:
            self._write_summary_file()
            self.stop()

    @staticmethod
    def _check_fd_count():
        """Warn if /proc/self/fd count is high."""
        try:
            p = Path('/proc/self/fd')
            if not p.exists():
                return
            n = sum(1 for _ in p.iterdir())
            if n > 800:
                logger.warning(f"High FD count: {n}")
        except OSError:
            pass
