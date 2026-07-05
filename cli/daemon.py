"""Daemon-mode helpers: double-fork daemonize + lifecycle management."""

import os
import sys
import time
import signal
from pathlib import Path

from ui.colors import green, red, yellow, bold


def daemonize(pid_file: str, log_file: str, verbose: bool = False):
    """
    Daemonize the process using double-fork technique.
    Sets up line-buffered logging that survives log rotation via SIGHUP.
    """
    # Ensure log dir exists and is writable BEFORE forking
    log_path = Path(log_file)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.stderr.write(f"error: cannot create log dir: {e}\n")
        sys.exit(1)

    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"Fork #1 failed: {e}\n")
        sys.exit(1)

    os.chdir('/')
    os.setsid()
    os.umask(0)

    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"Fork #2 failed: {e}\n")
        sys.exit(1)

    sys.stdout.flush()
    sys.stderr.flush()

    # Redirect stdin from /dev/null
    with open('/dev/null', 'r') as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())

    # Redirect stdout+stderr to log file (write+append, line-buffered)
    # We use fdopen so buffering is explicit
    log_fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    log_fileobj = os.fdopen(log_fd, 'a', buffering=1)  # line-buffered
    os.dup2(log_fd, sys.stdout.fileno())
    os.dup2(log_fd, sys.stderr.fileno())

    # Write PID file (after we know our real PID)
    try:
        Path(pid_file).parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    try:
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
    except OSError as e:
        sys.stderr.write(f"warn: cannot write pid file {pid_file}: {e}\n")


# ----------------------------- Daemon management -----------------------------

def get_daemon_status(pid_file: str) -> dict:
    result = {"running": False, "pid": None}
    if not os.path.exists(pid_file):
        return result
    try:
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        result["running"] = True
        result["pid"] = pid
    except (ValueError, ProcessLookupError, PermissionError, OSError):
        pass
    return result


def stop_daemon(pid_file: str, graceful_timeout: float = 15.0) -> bool:
    """
    Stop daemon with escalation:
    1. SIGTERM, wait `graceful_timeout` seconds (rotator flushes)
    2. SIGINT, wait 3s
    3. SIGKILL
    """
    status = get_daemon_status(pid_file)
    if not status["running"]:
        print(yellow("Daemon is not running"))
        return False

    pid = status["pid"]
    try:
        # Stage 1: SIGTERM (graceful)
        os.kill(pid, signal.SIGTERM)
        print(green(f"Sent SIGTERM to PID {pid} (waiting up to {graceful_timeout:.0f}s)"))
        deadline = time.monotonic() + graceful_timeout
        while time.monotonic() < deadline:
            time.sleep(0.5)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                print(green("Daemon stopped (SIGTERM)"))
                if os.path.exists(pid_file):
                    try:
                        os.remove(pid_file)
                    except OSError:
                        pass
                return True

        # Stage 2: SIGINT
        try:
            os.kill(pid, signal.SIGINT)
            print(yellow("Daemon still running, sent SIGINT"))
        except ProcessLookupError:
            print(green("Daemon stopped"))
            if os.path.exists(pid_file):
                try:
                    os.remove(pid_file)
                except OSError:
                    pass
            return True

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            time.sleep(0.5)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                print(green("Daemon stopped (SIGINT)"))
                if os.path.exists(pid_file):
                    try:
                        os.remove(pid_file)
                    except OSError:
                        pass
                return True

        # Stage 3: SIGKILL
        print(red("Daemon still running, sending SIGKILL"))
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.5)
        if os.path.exists(pid_file):
            try:
                os.remove(pid_file)
            except OSError:
                pass
        return True

    except PermissionError:
        print(red(f"Error: no permission to signal PID {pid}"))
        return False
    except ProcessLookupError:
        # Process died between status check and kill
        if os.path.exists(pid_file):
            try:
                os.remove(pid_file)
            except OSError:
                pass
        return True
    except Exception as e:
        print(red(f"Error stopping daemon: {e}"))
        return False


def print_status(pid_file: str, log_file: str):
    status = get_daemon_status(pid_file)
    print(f"\n{bold('SNIFF Daemon Status')}")
    print("-" * 40)
    if status["running"]:
        print(f"Status: {green('Running')}")
        print(f"PID:    {status['pid']}")
        print(f"Log:    {log_file}")
    else:
        print(f"Status: {red('Not running')}")
    print()
