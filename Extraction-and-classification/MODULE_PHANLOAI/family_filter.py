#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
family_filter.py — Parameterized filter + classify for any family.

Replaces the 7 nearly-identical <family>_feature_filter.py scripts.
Call with `--class <Name>` or invoke run_family() in-process from
auto_pipeline / dos_classifier.
"""
import argparse
import logging
import sys
from pathlib import Path

from baseline_filter import run

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_output_dir(class_name: str) -> str:
    return str(_project_root() / "CSV" / f"Filter_{class_name}_feature")


def run_family(class_name: str, input_csv: str, output_csv: str) -> None:
    """Public API: filter+classify one CSV file for the given family."""
    run(class_name, input_csv, output_csv)


def _process_one(class_name: str, in_csv: Path, out_target) -> None:
    name = in_csv.stem
    if name.endswith(f"_{class_name.lower()}_features"):
        return
    base = name[:-4] if name.endswith("_raw") else name
    if out_target is None:
        out_csv = None
    elif out_target.is_dir() or str(out_target).endswith(("/", "\\")):
        out_csv = out_target / f"{base}_{class_name.lower()}_features.csv"
    else:
        out_csv = out_target
    logger.info(f"Processing: {in_csv.name}")
    run(class_name, str(in_csv), str(out_csv) if out_csv else None)


def main():
    parser = argparse.ArgumentParser(
        description="Filter + classify family attacks using baseline signature rules."
    )
    parser.add_argument("--class", dest="class_name", required=True,
                        help="Family class name: Generic, DoS, Exploits, Fuzzers, "
                             "Analysis, Reconnaissance, Shellcode.")
    parser.add_argument("input", nargs="?", default=None,
                        help="Input CSV file or directory.")
    parser.add_argument("-o", "--output", default=None)
    args = parser.parse_args()

    class_name = args.class_name
    in_path = Path(args.input) if args.input else Path(default_output_dir(class_name))
    out_path = Path(args.output) if args.output else None

    if in_path.is_dir():
        out_dir = out_path if out_path and out_path.is_dir() else (out_path or in_path)
        out_dir.mkdir(parents=True, exist_ok=True)
        for csv in sorted(in_path.glob("*.csv")):
            _process_one(class_name, csv, out_dir)
    elif in_path.is_file():
        _process_one(class_name, in_path, out_path)
    else:
        logger.error(f"Not found: {in_path}")
        sys.exit(1)


if __name__ == "__main__":
    main()