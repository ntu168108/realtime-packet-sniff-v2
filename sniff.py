#!/usr/bin/env python3
"""
SNIFF - Network Packet Capture Tool
Main entry point with CLI args and daemon mode

Usage:
    sudo python3 sniff.py                    # Interactive menu
    sudo python3 sniff.py -i eth0            # Quick capture on eth0
    sudo python3 sniff.py -i eth0 -d         # Daemon mode
    sudo python3 sniff.py --status           # Check daemon status
    sudo python3 sniff.py --stop             # Stop daemon
    sudo python3 sniff.py -i eth0 --live     # Live JSON stream to stdout
"""

import os
import sys
import argparse
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.capture import get_interfaces, validate_interface
from core.constants import (
    DEFAULT_SNAPLEN, DEFAULT_RETENTION_DAYS,
)
from ui.colors import bold, red, yellow

from cli.app import SniffApp
from cli.menu_mode import run_menu_mode
from cli.daemon import daemonize, get_daemon_status, stop_daemon, print_status
from cli.helpers import (
    __version__, parse_time_secs, parse_size_mb,
    list_protocols, check_root, ensure_output_dir, check_disk_space,
    setup_logging, DEFAULT_DATA_DIR, DEFAULT_PID_FILE, DEFAULT_LOG_FILE,
    logger,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sniff",
        description=f"SNIFF v{__version__} - Network Packet Capture Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
    sudo sniff                              # Interactive menu
    sudo sniff -i eth0                      # Quick capture on eth0
    sudo sniff -i eth0 -d                   # Daemon mode
    sudo sniff -i eth0 -f "tcp port 80"     # With BPF filter
    sudo sniff -i eth0 --live | jq .        # Live NDJSON to stdout
    sudo sniff -i eth0 --live --display-filter 'port 443'
    sudo sniff -i eth0 --count 1000         # Capture 1000 packets then stop
    sudo sniff --status                     # Check daemon status
    sudo sniff --stop                       # Stop daemon

Signals (daemon):
    SIGTERM  Graceful shutdown
    SIGINT   Faster shutdown
    SIGHUP   Re-open log file
    SIGUSR1  Toggle verbose log level
    SIGUSR2  Force file rotation now
""",
    )
    # Basic capture
    p.add_argument('-i', '--interface', help='Network interface to capture on')
    p.add_argument('-f', '--filter', default='',
                   help='BPF filter (kernel-side, e.g. "tcp port 80")')
    p.add_argument('-s', '--snaplen', type=int, default=DEFAULT_SNAPLEN,
                   help=f'Capture length (default: {DEFAULT_SNAPLEN})')
    p.add_argument('-p', '--no-promisc', action='store_true',
                   help='Disable promiscuous mode')
    p.add_argument('-b', '--buffer',
                   choices=['low', 'balanced', 'fast', 'max'],
                   default='balanced', help='Buffer profile')
    p.add_argument('-o', '--output', default=str(DEFAULT_DATA_DIR),
                   help='Output directory (default: ./sniff_data)')
    p.add_argument('-r', '--retention', type=int, default=DEFAULT_RETENTION_DAYS,
                   help=f'Days to keep files (default: {DEFAULT_RETENTION_DAYS})')

    # Rotation
    p.add_argument('--rotate-interval', type=parse_time_secs, default=3600,
                   help='Rotation interval in seconds (suffix s/m/h/d, default 3600=1h)')
    p.add_argument('--rotate-size', type=parse_size_mb, default=0,
                   help='Rotate when file exceeds size in MB (0=default 500MB)')
    p.add_argument('--no-rotate', action='store_true',
                   help='Single-file capture (no rotation)')

    # Live / display
    p.add_argument('--live', action='store_true',
                   help='Stream NDJSON to stdout (no TUI)')
    p.add_argument('--display-filter', default='',
                   help='Post-decode display filter (e.g. "port 80 and tcp")')
    p.add_argument('--count', type=int, default=0,
                   help='Stop after N packets (0=unlimited)')
    p.add_argument('--exclude-port', type=int, action='append', default=[],
                   help='Exclude this port (repeatable)')

    # Daemon management
    p.add_argument('-d', '--daemon', action='store_true',
                   help='Run as daemon (background)')
    p.add_argument('--pid-file', default=DEFAULT_PID_FILE,
                   help=f'PID file path (default: {DEFAULT_PID_FILE})')
    p.add_argument('--log-file', default=DEFAULT_LOG_FILE,
                   help=f'Log file path (default: {DEFAULT_LOG_FILE})')
    p.add_argument('--status', action='store_true',
                   help='Show daemon status')
    p.add_argument('--stop', action='store_true',
                   help='Stop daemon')
    p.add_argument('--stop-timeout', type=float, default=15.0,
                   help='Graceful timeout before SIGKILL (default: 15s)')

    # Info
    p.add_argument('--list-interfaces', action='store_true',
                   help='List available interfaces')
    p.add_argument('--list-protocols', action='store_true',
                   help='List supported protocols and exit')
    p.add_argument('--version', action='version',
                   version=f'sniff {__version__}')
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # ---- Special commands (don't require root) ----
    # Note: --version is handled by argparse's `action='version'` which
    # calls sys.exit(0) before we get here, so no manual check needed.
    if args.list_protocols:
        list_protocols()
        return

    if args.status:
        print_status(args.pid_file, args.log_file)
        return

    if args.stop:
        # Try /var/run first then fall back to /tmp
        rc = stop_daemon(args.pid_file, graceful_timeout=args.stop_timeout)
        sys.exit(0 if rc else 1)

    if args.list_interfaces:
        print(f"\n{bold('Available Interfaces:')}")
        for iface in get_interfaces():
            print(f"  - {iface}")
        print()
        return

    # ---- Real capture requires root ----
    check_root()

    # Ensure output dir + log dir exist and are writable
    ensure_output_dir(args.output)
    log_path = Path(args.log_file)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.stderr.write(yellow(f"Warning: cannot create log dir: {e}\n"))

    check_disk_space(args.output)

    # No interface specified - run menu mode
    if not args.interface:
        run_menu_mode(args.output)
        return

    # Validate interface
    if not validate_interface(args.interface):
        sys.stderr.write(red(f"Error: Interface '{args.interface}' not found\n"))
        sys.stderr.write(f"Available: {', '.join(get_interfaces())}\n")
        sys.exit(1)

    # Check if daemon already running
    if args.daemon:
        status = get_daemon_status(args.pid_file)
        if status["running"]:
            print(yellow(f"Daemon already running (PID: {status['pid']})"))
            sys.exit(1)

    # Build app
    app = SniffApp(
        data_dir=args.output,
        interface=args.interface,
        bpf_filter=args.filter,
        snaplen=args.snaplen,
        promisc=not args.no_promisc,
        buffer_profile=args.buffer,
        retention_days=args.retention,
        pid_file=args.pid_file,
        log_file=args.log_file,
        live=args.live,
        display_filter=args.display_filter,
        count=args.count,
        rotate_interval=args.rotate_interval,
        rotate_size_mb=args.rotate_size,
        no_rotate=args.no_rotate,
        exclude_ports=args.exclude_port,
    )

    # Install signal handlers BEFORE daemonize (so SIGTERM during fork is OK)
    app._setup_signal_handlers()

    if args.daemon:
        daemonize(args.pid_file, args.log_file)
        # Re-setup logging in the daemon (now that stdout is the log file)
        setup_logging(args.log_file)
        logger.info(f"SNIFF v{__version__} daemonized (PID {os.getpid()})")
        app.run_daemon()
    elif args.live:
        # Live mode: still want file logging
        setup_logging(args.log_file)
        try:
            app.run_live()
        except BrokenPipeError:
            # Downstream consumer (jq, head) closed pipe; that's OK
            sys.stderr.write(yellow("Downstream pipe closed; exiting live mode\n"))
            try:
                app.stop()
            except Exception:
                pass
    else:
        # Interactive: TUI uses /dev/tty via curses; stderr logging
        setup_logging(args.log_file)
        app.run_interactive()


if __name__ == '__main__':
    main()
