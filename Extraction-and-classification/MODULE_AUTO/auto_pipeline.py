# -*- coding: utf-8 -*-
import os
os.environ.setdefault("PYTHONUTF8", "1")

"""
auto_pipeline.py - Orchestrator tu dong cho mot file PCAP.

Luong xu ly cho moi pcap:
    1. extractor.py <pcap>            -> CSV_Full_feature/<base>_raw.csv
    2. add_features.py <base>_raw.csv -> CSV_Full_feature/<base>_dos_features.csv (49 cot)
    3. Lan luot 7 filter (che do file don le) doc <base>_dos_features.csv
       -> moi filter ghi vao thu muc Filter_<Type>_feature rieng.

Cach dung:
    python auto_pipeline.py duong_dan.pcap
    python auto_pipeline.py duong_dan.pcap --keep-intermediate
"""

import argparse
import logging
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Duong dan goc cac module (suy ra tu vi tri file nay, co the override bang env)
# ---------------------------------------------------------------------------
THIS_DIR = Path(__file__).resolve().parent       # .../Python/EaF/MODULE_AUTO
# Allow overriding roots via env so consumer can point at a different EC repo
# without breaking the default layout (Extraction-and-classification/*).
WORKSPACE_ROOT = Path(
    os.environ.get("NB15_WORKSPACE_ROOT", THIS_DIR.parent)
)                                               # default: THIS_DIR.parent (chua cac MODULE_*)
DATA_ROOT = Path(
    os.environ.get("NB15_DATA_ROOT", WORKSPACE_ROOT)
)                                               # default: WORKSPACE_ROOT (CSV, Filepcap nam trong WORKSPACE_ROOT)

MODULE_TRICHXUAT = WORKSPACE_ROOT / "MODULE_TRICHXUAT"
MODULE_PHANLOAI = WORKSPACE_ROOT / "MODULE_PHANLOAI"
CSV_FULL_FEATURE = DATA_ROOT / "CSV" / "CSV_Full_feature"
PCAP_DIR = DATA_ROOT / "Filepcap"

# Giu ten cu de tuong thich nguoc (vai cho khac co the import).
PROJECT_ROOT = DATA_ROOT

EXTRACTOR = MODULE_TRICHXUAT / "extractor.py"
ADD_FEATURES = MODULE_TRICHXUAT / "add_features.py"

# Danh sach 7 filter chay tuan tu cho moi pcap.
FILTERS = [
    "Generic",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Analysis",
    "Reconnaissance",
    "Shellcode",
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("auto_pipeline")


# ---------------------------------------------------------------------------
# Chon Python interpreter co pandas (cac script con can pandas/numpy)
# ---------------------------------------------------------------------------
def _resolve_python_cmd() -> list:
    """Nhu _resolve_python nhung tra ve list (de ghep voi args script)."""
    def _has_pandas(exe_cmd: list) -> bool:
        try:
            r = subprocess.run(
                exe_cmd + ["-c", "import pandas"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return r.returncode == 0
        except Exception:  # noqa: BLE001
            return False

    candidates: list = []
    env_py = os.environ.get("AUTO_PIPELINE_PYTHON")
    if env_py:
        candidates.append([env_py])
    candidates.append([sys.executable])
    candidates.append(["py", "-3"])
    candidates.append(["python"])

    for cand in candidates:
        if _has_pandas(cand):
            logger.info("Su dung Python interpreter: %s", " ".join(cand))
            return cand
    logger.warning(
        "Khong tim thay interpreter co pandas — dung mac dinh: %s", sys.executable
    )
    return [sys.executable]


PYTHON_CMD = [sys.executable]


# ---------------------------------------------------------------------------
# Helper chay subprocess
# ---------------------------------------------------------------------------
def _run(cmd: list, step_name: str) -> None:
    """Chay mot script con. Raise RuntimeError neu that bai."""
    logger.info("-> [%s] %s", step_name, " ".join(str(c) for c in cmd))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise RuntimeError(
            f"Buoc '{step_name}' that bai (return code {result.returncode})."
        )


# ---------------------------------------------------------------------------
# Pipeline chinh cho 1 pcap
# ---------------------------------------------------------------------------
def process_pcap(pcap_path: str) -> bool:
    """
    Chay full pipeline cho mot file pcap.

    Returns
    -------
    bool
        True neu thanh cong toan bo, False neu co buoc loi.
    """
    pcap = Path(pcap_path).resolve()
    if not pcap.is_file():
        logger.error("Khong tim thay file PCAP: %s", pcap)
        return False

    base = pcap.stem
    raw_csv = CSV_FULL_FEATURE / f"{base}_raw.csv"
    dos_features_csv = CSV_FULL_FEATURE / f"{base}_dos_features.csv"

    start = time.time()
    logger.info("=" * 70)
    logger.info("BAT DAU PIPELINE TU DONG cho: %s", pcap.name)
    logger.info("=" * 70)

    try:
        # --- Buoc 1: Trich xuat (extractor.py) ---------------------------
        logger.info("BUOC 1/4: Trich xuat dac trung (extractor.py)")
        _run(PYTHON_CMD + [str(EXTRACTOR), str(pcap), "--output-dir", str(CSV_FULL_FEATURE)],
             "extractor")

        if not raw_csv.is_file():
            raise RuntimeError(
                f"extractor khong sinh ra file mong doi: {raw_csv}"
            )

        # --- Buoc 2: Bo sung dac trung (add_features.py) -----------------
        logger.info("BUOC 2/4: Bo sung dac trung (add_features.py)")
        _run(PYTHON_CMD + [str(ADD_FEATURES), str(raw_csv)], "add_features")

        if not dos_features_csv.is_file():
            raise RuntimeError(
                f"add_features khong sinh ra file mong doi: {dos_features_csv}"
            )

        # --- Buoc 3: Phan loai HOP NHAT (1 flow -> dung 1 nhan) -----------
        # Truoc day: chay 7 filter DOC LAP, moi filter tu quyet dinh predicted_class
        # ma khong so sanh voi nhau (khong argmax). Hau qua tren traffic THAT:
        #   * DoS bi bo lot 100% (nguong UNSW-NB15 sttl>=142.5 / rate>=112k khong
        #     bao gio dat voi flood --rand-source bi bam thanh flow 1-goi rate=0).
        #   * 1 flow flood 1-goi trung ca Fuzzers LAN Reconnaissance cung luc ->
        #     bi dem 7 lan trong flows_all (Merge).
        # Bay gio: unified_classifier cham diem 6 ho + phat hien DoS (cong don +
        # cong volumetric cap segment) roi HOP NHAT ve dung 1 nhan/flow, ghi ra 7
        # CSV per-family (nhan chi hien o dung 1 bang). Schema/sink KHONG doi.
        logger.info("BUOC 3/4: Phan loai hop nhat (unified_classifier)")
        if str(MODULE_PHANLOAI) not in sys.path:
            sys.path.insert(0, str(MODULE_PHANLOAI))
        failed_filters = []
        try:
            from unified_classifier import write_family_csvs  # type: ignore
            csv_root = MODULE_PHANLOAI / ".." / "CSV"
            write_family_csvs(str(dos_features_csv), str(csv_root))
        except Exception as exc:
            logger.exception("  Phan loai hop nhat loi: %s", exc)
            failed_filters = list(FILTERS)

        # --- Buoc 4: Chay DoS Classification Engine (dos_classifier.py) --
        logger.info("BUOC 4/4: DoS Classification Engine (dos_classifier.py)")
        dos_classifier_path = MODULE_PHANLOAI / "dos_classifier.py"
        if dos_classifier_path.is_file():
            try:
                _run(
                    PYTHON_CMD + [
                        str(dos_classifier_path),
                        "--csv", str(dos_features_csv),
                        "--skip-filter",
                    ],
                    "dos_classifier",
                )
            except RuntimeError as exc:
                logger.warning("DoS Classifier khong chay duoc (khong chan pipeline): %s", exc)
        else:
            logger.warning("Khong tim thay dos_classifier.py tai: %s", dos_classifier_path)

        elapsed = time.time() - start
        logger.info("=" * 70)
        if failed_filters:
            logger.warning(
                "PIPELINE HOAN TAT CO LOI cho %s | %d/%d filter loi: %s | %.1fs",
                pcap.name, len(failed_filters), len(FILTERS),
                ", ".join(failed_filters), elapsed,
            )
            return False
        logger.info("PIPELINE HOAN TAT cho %s | %.1f giay", pcap.name, elapsed)
        logger.info("=" * 70)
        return True

    except RuntimeError as exc:
        logger.error("PIPELINE DUNG: %s", exc)
        return False
    except Exception as exc:  # noqa: BLE001
        logger.exception("Loi khong mong doi: %s", exc)
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Orchestrator tu dong: pcap -> extractor -> add_features -> 7 filter."
        ),
    )
    parser.add_argument("pcap", help="Duong dan toi file .pcap dau vao.")
    args = parser.parse_args()

    ok = process_pcap(args.pcap)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
