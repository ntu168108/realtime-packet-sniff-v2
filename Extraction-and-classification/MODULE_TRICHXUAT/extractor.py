# -*- coding: utf-8 -*-
"""
extractor.py - Entry point chính cho pipeline trích xuất đặc trưng PCAP.

Orchestrate 4 bước:
  1. Argus  → trích xuất Flow, Time & MAC features
  2. Zeek   → trích xuất Content, State & MAC features
  3. Mapper → chuẩn hóa tên cột theo UNSW-NB15
  4. Merger → gộp dữ liệu, xử lý MAC, xuất CSV cuối cùng

Cách sử dụng:
  python extractor.py traffic.pcap
  python extractor.py traffic.pcap -o output.csv --no-cleanup
  python extractor.py traffic.pcap --verbose
"""

import argparse
import logging
import os
import sys
import time

from config import OUTPUT_CSV, DEFAULT_OUTPUT_DIR
from pathlib import Path as _Path
_DEFAULT_PCAP_DIR_HELP = str(_Path(__file__).resolve().parent.parent / "Filepcap")
from argus_handler import run_argus
from zeek_handler import run_zeek
from data_mapper import map_data
from data_merger import merge_and_export

# ============================================================
# Logging setup
# ============================================================
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
LOG_DATE_FMT = "%Y-%m-%d %H:%M:%S"


logger = logging.getLogger("extractor")


# ============================================================
# Main pipeline
# ============================================================
def extract_features(
    pcap_file: str,
    output_name: str = None,
    output_dir: str = None,
    cleanup: bool = True,
) -> str:
    """
    Pipeline chính: trích xuất đặc trưng mạng từ file PCAP.

    Args:
        pcap_file:   Đường dẫn tới file .pcap đầu vào.
        output_name: Tên file CSV đầu ra (mặc định: final_features_nb15_with_mac.csv).
        output_dir:  Thư mục chứa file CSV đầu ra (mặc định: DEFAULT_OUTPUT_DIR).
        cleanup:     Có xóa file trung gian không (mặc định: True).

    Returns:
        Đường dẫn tuyệt đối tới file CSV kết quả.
    """
    # Xác định thư mục làm việc = thư mục chứa file PCAP
    pcap_file = os.path.abspath(pcap_file)

    # Xác định thư mục output (mặc định: DEFAULT_OUTPUT_DIR)
    if output_dir is None:
        output_dir = DEFAULT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)
    work_dir = os.path.dirname(pcap_file)

    if not os.path.isfile(pcap_file):
        raise FileNotFoundError(f"Khong tim thay file PCAP: '{pcap_file}'")

    logger.info("=" * 70)
    logger.info("BAT DAU PIPELINE TRICH XUAT DAC TRUNG PCAP")
    logger.info("=" * 70)
    logger.info("File dau vao   : %s", pcap_file)
    logger.info("Thu muc lam viec: %s", work_dir)
    logger.info("Thu muc dau ra  : %s", output_dir)

    start_time = time.time()

    def _step(n: int, title: str) -> None:
        logger.info("-" * 70)
        logger.info("BUOC %d/4: %s", n, title)
        logger.info("-" * 70)

    _step(1, "Trich xuat bang Argus")
    argus_csv = run_argus(pcap_file, work_dir)

    _step(2, "Trich xuat bang Zeek")
    zeek_csv = run_zeek(pcap_file, work_dir)

    _step(3, "Chuan hoa du lieu (Data Mapping)")
    df_argus, df_zeek = map_data(argus_csv, zeek_csv)

    _step(4, "Merge & Xuat CSV")
    
    pcap_base = os.path.splitext(os.path.basename(pcap_file))[0]
    if output_name is None:
        output_name = f"{pcap_base}_raw.csv"

    output_path = merge_and_export(
        df_argus, df_zeek, work_dir,
        output_name=output_name,
        output_dir=output_dir,
        cleanup=cleanup,
        base_name=pcap_base,
    )

    # ------------------------------------------------------------------
    # Tổng kết
    # ------------------------------------------------------------------
    elapsed = time.time() - start_time
    logger.info("=" * 70)
    logger.info("PIPELINE HOAN TAT")
    logger.info("  File ket qua: %s", output_path)
    logger.info("  Thoi gian   : %.2f giay", elapsed)
    logger.info("=" * 70)

    return output_path


# ============================================================
# CLI entry point
# ============================================================
def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Trich xuat dac trung mang tu file .pcap theo dinh dang UNSW-NB15, "
            "bao gom Dia chi MAC."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Vi du:\n"
            "  python extractor.py traffic.pcap\n"
            "  python extractor.py capture.pcap -o results.csv --verbose\n"
            "  python extractor.py data.pcap --no-cleanup\n"
            f"\nDuong dan mac dinh:\n"
            f"  PCAP input dir : {_DEFAULT_PCAP_DIR_HELP}\n"
            f"  CSV output dir : {DEFAULT_OUTPUT_DIR}\n"
        ),
    )

    parser.add_argument(
        "pcap_file",
        help="Duong dan toi file .pcap dau vao.",
    )

    parser.add_argument(
        "-o", "--output",
        default=None,
        help=f"Ten file CSV dau ra (mac dinh: {OUTPUT_CSV}).",
    )

    parser.add_argument(
        "--output-dir",
        default=None,
        help=f"Thu muc chua file CSV dau ra (mac dinh: {DEFAULT_OUTPUT_DIR}).",
    )

    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        default=False,
        help="Giu lai cac file trung gian (khong xoa).",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Bat che do debug log chi tiet.",
    )

    return parser.parse_args()


def main() -> None:
    """Entry point khi chạy từ CLI."""
    args = parse_args()

    setup_logging(verbose=args.verbose)

    try:
        output_file = extract_features(
            pcap_file=args.pcap_file,
            output_name=args.output,
            output_dir=args.output_dir,
            cleanup=not args.no_cleanup,
        )
        print(f"\n[OK] Hoan tat! File ket qua: {output_file}")
    except FileNotFoundError as exc:
        logger.error("[ERROR] Loi: %s", exc)
        sys.exit(1)
    except RuntimeError as exc:
        logger.error("[ERROR] Loi runtime: %s", exc)
        sys.exit(2)
    except Exception as exc:
        logger.exception("[ERROR] Loi khong mong doi: %s", exc)
        sys.exit(99)


if __name__ == "__main__":
    main()
