# -*- coding: utf-8 -*-
"""
argus_handler.py - Buoc 1: Chay Argus CLI de trich xuat Flow, Time & MAC Features.

Workflow:
  1. argus -r <pcap> -w traffic.argus   -> Tao file Argus binary
  2. ra -r traffic.argus -c , -s <fields> -> Xuat ra argus_temp.csv
"""

import subprocess
import logging
import os

from config import (
    ARGUS_FIELDS, ARGUS_BINARY, ARGUS_TEMP_CSV,
    ARGUS_BIN, RA_BIN,
    IS_WINDOWS, win_to_wsl_path, wsl_run,
)

logger = logging.getLogger(__name__)


def run_argus(pcap_file: str, work_dir: str) -> str:
    """
    Chay Argus va ra client de trich xuat dac trung flow tu file PCAP.

    Args:
        pcap_file: Duong dan tuyet doi toi file .pcap dau vao.
        work_dir:  Thu muc lam viec (chua file trung gian).

    Returns:
        Duong dan tuyet doi toi file argus_temp.csv da tao.

    Raises:
        RuntimeError: Neu lenh Argus hoac ra that bai.
    """
    argus_bin = os.path.join(work_dir, ARGUS_BINARY)
    argus_csv = os.path.join(work_dir, ARGUS_TEMP_CSV)

    # Xoa file cu neu ton tai de tranh viec argus ghi de append
    if os.path.isfile(argus_bin):
        os.remove(argus_bin)
    if os.path.isfile(argus_csv):
        os.remove(argus_csv)

    # Chuyen doi duong dan cho WSL neu can
    if IS_WINDOWS:
        wsl_pcap = win_to_wsl_path(pcap_file)
        wsl_argus_bin = win_to_wsl_path(argus_bin)
    else:
        wsl_pcap = pcap_file
        wsl_argus_bin = argus_bin

    # ------------------------------------------------------------------
    # Buoc 1a: Chuyen doi PCAP -> Argus binary
    # ------------------------------------------------------------------
    logger.info("Dang chay Argus: doc PCAP -> %s", argus_bin)
    try:
        result = wsl_run(
            [ARGUS_BIN, "-m", "-r", wsl_pcap, "-w", wsl_argus_bin],
            capture_output=True,
            text=True,
            check=True,
        )
        logger.debug("Argus stdout: %s", result.stdout)
    except subprocess.CalledProcessError as exc:
        logger.error("Argus that bai (exit code %d): %s", exc.returncode, exc.stderr)
        raise RuntimeError(
            f"Argus that bai khi doc '{pcap_file}': {exc.stderr}"
        ) from exc
    except FileNotFoundError:
        raise RuntimeError(
            f"Khong tim thay lenh 'argus' (da thu: {ARGUS_BIN}). "
            "Hay dam bao Argus 5.0.x da duoc cai dat va nam trong PATH."
        )

    # ------------------------------------------------------------------
    # Buoc 1b: Xuat Argus binary -> CSV bang client 'ra'
    # ------------------------------------------------------------------
    fields_str = ",".join(ARGUS_FIELDS)
    logger.info("Dang chay ra: xuat %d truong -> %s", len(ARGUS_FIELDS), argus_csv)

    try:
        result = wsl_run(
            [
                RA_BIN,
                "-r", wsl_argus_bin,
                "-n",                # Khong chuyen doi cong thanh ten dich vu
                "-u",                # Su dung dinh dang Unix timestamp cho thoi gian
                "-c", ",",           # Dau phan cach CSV
                "-s", fields_str,    # Chon truong xuat
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        # Ghi noi dung ra da xuat (bo qua dong header neu ra tu them)
        lines = result.stdout.strip().split("\n")
        with open(argus_csv, "w", encoding="utf-8") as f_out:
            f_out.write(",".join(ARGUS_FIELDS) + "\n")
            for line in lines:
                stripped = line.strip()
                # Bo qua dong trong
                if not stripped:
                    continue
                # Bo qua dong header do ra tu sinh (chua ten cot goc)
                if "SrcAddr" in stripped or "SrcMac" in stripped or "DstAddr" in stripped:
                    logger.debug("Bo qua header cua ra: %s", stripped[:80])
                    continue
                # ra thuong them khoang trang giua cac cot khi dung -c ","
                # -> loai bo khoang trang thua
                cleaned = ",".join(field.strip() for field in stripped.split(","))
                # Bo qua Argus management records (proto = 'man')
                fields = cleaned.split(",")
                proto_idx = ARGUS_FIELDS.index("proto") if "proto" in ARGUS_FIELDS else -1
                if proto_idx >= 0 and proto_idx < len(fields) and fields[proto_idx].lower() == "man":
                    continue
                f_out.write(cleaned + "\n")

        logger.info("Da tao thanh cong: %s", argus_csv)

    except subprocess.CalledProcessError as exc:
        logger.error("ra that bai (exit code %d): %s", exc.returncode, exc.stderr)
        raise RuntimeError(
            f"ra client that bai khi doc '{argus_bin}': {exc.stderr}"
        ) from exc
    except FileNotFoundError:
        raise RuntimeError(
            f"Khong tim thay lenh 'ra' (da thu: {RA_BIN}). "
            "Hay dam bao Argus client (ra) da duoc cai dat va nam trong PATH."
        )

    return argus_csv
