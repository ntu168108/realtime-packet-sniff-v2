# -*- coding: utf-8 -*-
import os
os.environ.setdefault("PYTHONUTF8", "1")

"""
pcap_watcher.py - Theo doi thu muc Filepcap/ va tu dong chay pipeline.

Khi mot file .pcap moi xuat hien (copy/move vao Filepcap/), watcher:
    1. Cho file on dinh kich thuoc (tranh doc file dang ghi do).
    2. Goi auto_pipeline.process_pcap(<pcap>).
    3. Sau khi xong: move file pcap sang Filepcap/processed/.

Ho tro 2 che do:
    - watchdog (neu da `pip install watchdog`): phan ung tuc thi qua OS event.
    - polling thuan (fallback): quet thu muc moi POLL_INTERVAL giay.

Cach dung:
    python pcap_watcher.py
    python pcap_watcher.py --watch-dir D:\\...\\Filepcap --poll 5 --process-existing
"""

import argparse
import logging
import shutil
import time
from pathlib import Path

from auto_pipeline import process_pcap, PCAP_DIR

# ---------------------------------------------------------------------------
# Cau hinh mac dinh
# ---------------------------------------------------------------------------
DEFAULT_WATCH_DIR = PCAP_DIR
PROCESSED_SUBDIR = "processed"
PCAP_EXTS = {".pcap", ".pcapng", ".cap"}

# Cho on dinh kich thuoc: kiem tra moi STABLE_INTERVAL giay,
# can STABLE_CHECKS lan lien tiep kich thuoc khong doi.
STABLE_INTERVAL = 3.0
STABLE_CHECKS = 3

# Polling fallback
POLL_INTERVAL = 5.0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("pcap_watcher")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_pcap(path: Path) -> bool:
    return path.suffix.lower() in PCAP_EXTS


def _wait_until_stable(path: Path) -> bool:
    """Cho den khi kich thuoc file on dinh. Tra ve False neu file bien mat."""
    last_size = -1
    stable_count = 0
    while True:
        try:
            size = path.stat().st_size
        except (FileNotFoundError, OSError):
            return False
        if size == last_size:
            stable_count += 1
            if stable_count >= STABLE_CHECKS:
                return True
        else:
            stable_count = 0
            last_size = size
        time.sleep(STABLE_INTERVAL)


def _move_to_processed(path: Path, watch_dir: Path) -> None:
    """Move file pcap da xu ly sang <watch_dir>/processed/."""
    processed_dir = watch_dir / PROCESSED_SUBDIR
    processed_dir.mkdir(parents=True, exist_ok=True)
    dest = processed_dir / path.name
    # Tranh ghi de: them hau to neu trung ten
    if dest.exists():
        stem, suffix = path.stem, path.suffix
        dest = processed_dir / f"{stem}_{int(time.time())}{suffix}"
    try:
        shutil.move(str(path), str(dest))
        logger.info("Da move pcap sang: %s", dest)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Khong the move pcap sang processed/: %s", exc)


def handle_pcap(path: Path, watch_dir: Path, seen: set) -> None:
    """Xu ly mot file pcap moi: cho on dinh -> pipeline -> move."""
    key = str(path.resolve())
    if key in seen:
        return
    seen.add(key)

    logger.info("Phat hien pcap moi: %s — cho on dinh kich thuoc...", path.name)
    if not _wait_until_stable(path):
        logger.warning("File bien mat hoac khong on dinh: %s", path.name)
        seen.discard(key)
        return

    logger.info("File on dinh. Bat dau pipeline: %s", path.name)
    ok = process_pcap(str(path))
    if ok:
        _move_to_processed(path, watch_dir)
    else:
        logger.warning("Pipeline loi cho %s — GIU NGUYEN file (khong move).",
                       path.name)


# ---------------------------------------------------------------------------
# Che do polling
# ---------------------------------------------------------------------------
def run_polling(watch_dir: Path, poll_interval: float, seen: set) -> None:
    logger.info("Che do POLLING (quet moi %.1fs). Ctrl+C de dung.", poll_interval)
    while True:
        try:
            for entry in sorted(watch_dir.glob("*")):
                if entry.is_file() and _is_pcap(entry):
                    handle_pcap(entry, watch_dir, seen)
            time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("Dung watcher (KeyboardInterrupt).")
            break


# ---------------------------------------------------------------------------
# Che do watchdog
# ---------------------------------------------------------------------------
def run_watchdog(watch_dir: Path, seen: set) -> bool:
    """Tra ve False neu watchdog chua cai (de fallback sang polling)."""
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        return False

    handler_self = {"watch_dir": watch_dir, "seen": seen}

    class _PcapHandler(FileSystemEventHandler):
        def _maybe_handle(self, src_path: str) -> None:
            p = Path(src_path)
            if p.is_file() and _is_pcap(p):
                handle_pcap(p, handler_self["watch_dir"], handler_self["seen"])

        def on_created(self, event):
            if not event.is_directory:
                self._maybe_handle(event.src_path)

        def on_moved(self, event):
            if not event.is_directory:
                self._maybe_handle(event.dest_path)

    observer = Observer()
    observer.schedule(_PcapHandler(), str(watch_dir), recursive=False)
    observer.start()
    logger.info("Che do WATCHDOG (phan ung tuc thi). Ctrl+C de dung.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Dung watcher (KeyboardInterrupt).")
        observer.stop()
    observer.join()
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Theo doi thu muc Filepcap/ va tu dong chay pipeline phan loai.",
    )
    parser.add_argument(
        "--watch-dir", default=str(DEFAULT_WATCH_DIR),
        help=f"Thu muc theo doi (mac dinh: {DEFAULT_WATCH_DIR}).",
    )
    parser.add_argument(
        "--poll", type=float, default=POLL_INTERVAL,
        help=f"Chu ky polling giay (mac dinh: {POLL_INTERVAL}).",
    )
    parser.add_argument(
        "--force-polling", action="store_true",
        help="Buoc dung polling ngay ca khi co watchdog.",
    )
    parser.add_argument(
        "--process-existing", action="store_true",
        help="Xu ly luon cac pcap dang co san trong thu muc khi khoi dong.",
    )
    args = parser.parse_args()

    watch_dir = Path(args.watch_dir).resolve()
    watch_dir.mkdir(parents=True, exist_ok=True)

    seen: set = set()

    logger.info("=" * 70)
    logger.info("PCAP WATCHER khoi dong")
    logger.info("  Thu muc theo doi: %s", watch_dir)
    logger.info("  Output processed: %s", watch_dir / PROCESSED_SUBDIR)
    logger.info("=" * 70)

    # Xu ly file co san neu duoc yeu cau (mac dinh: bo qua de tranh chay lai khoi luong cu)
    if args.process_existing:
        logger.info("Xu ly cac pcap co san trong thu muc...")
        for entry in sorted(watch_dir.glob("*")):
            if entry.is_file() and _is_pcap(entry):
                handle_pcap(entry, watch_dir, seen)
    else:
        # Danh dau file co san la "da thay" de chi xu ly file MOI di vao.
        for entry in watch_dir.glob("*"):
            if entry.is_file() and _is_pcap(entry):
                seen.add(str(entry.resolve()))
        logger.info("Bo qua %d pcap co san (dung --process-existing de xu ly).",
                    len(seen))

    if not args.force_polling:
        if run_watchdog(watch_dir, seen):
            return
        logger.info("Watchdog chua cai (pip install watchdog) -> dung polling.")

    run_polling(watch_dir, args.poll, seen)


if __name__ == "__main__":
    main()
