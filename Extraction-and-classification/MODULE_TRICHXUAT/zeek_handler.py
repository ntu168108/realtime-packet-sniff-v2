# -*- coding: utf-8 -*-
"""
zeek_handler.py - Buoc 2: Chay Zeek CLI de trich xuat Content, State & MAC Features.

Workflow:
  1. Tao thu muc tam chay Zeek (voi mac-logging script)
  2. zeek -r <pcap>          -> Sinh ra conn.log (va cac log khac)
  3. Doc conn.log truc tiep bang Python -> zeek_temp.csv
"""

import subprocess
import logging
import os
import shutil
import csv

from config import (
    ZEEK_TEMP_CSV, ZEEK_LOG_DIR, ZEEK_BIN,
    IS_WINDOWS, win_to_wsl_path, wsl_run,
)

logger = logging.getLogger(__name__)

# Cac truong can trich xuat tu conn.log (theo thu tu output mong muon)
# Ten cac truong can trich xuat tu conn.log (key == ten cot CSV)
WANTED_FIELDS = [
    "id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p",
    "proto", "service", "conn_state",
    # MAC fields - chi co khi bat mac-logging
    "orig_l2_addr", "resp_l2_addr",
    # HTTP and FTP fields
    "trans_depth", "res_bdy_len", "http_method",
    "is_ftp_login", "ftp_cmd",
]


def run_zeek(pcap_file: str, work_dir: str) -> str:
    """
    Chay Zeek va doc conn.log de trich xuat dac trung connection tu file PCAP.

    Args:
        pcap_file: Duong dan tuyet doi toi file .pcap dau vao.
        work_dir:  Thu muc lam viec (chua file trung gian).

    Returns:
        Duong dan tuyet doi toi file zeek_temp.csv da tao.

    Raises:
        RuntimeError: Neu lenh Zeek that bai.
    """
    zeek_log_dir = os.path.join(work_dir, ZEEK_LOG_DIR)
    zeek_csv = os.path.join(work_dir, ZEEK_TEMP_CSV)
    conn_log = os.path.join(zeek_log_dir, "conn.log")

    # ------------------------------------------------------------------
    # Buoc 2a: Tao thu muc tam va chay Zeek (voi mac-logging)
    # ------------------------------------------------------------------
    os.makedirs(zeek_log_dir, exist_ok=True)
    logger.info("Dang chay Zeek: doc PCAP -> %s/", zeek_log_dir)

    # Chuyen doi duong dan cho WSL neu can
    if IS_WINDOWS:
        wsl_pcap = win_to_wsl_path(pcap_file)
        wsl_log_dir = win_to_wsl_path(zeek_log_dir)
    else:
        wsl_pcap = pcap_file
        wsl_log_dir = zeek_log_dir

    try:
        # Them policy/protocols/conn/mac-logging de Zeek ghi MAC vao conn.log
        if IS_WINDOWS:
            result = wsl_run(
                ["bash", "-c",
                 f"cd '{wsl_log_dir}' && {ZEEK_BIN} -r '{wsl_pcap}' policy/protocols/conn/mac-logging"],
                capture_output=True,
                text=True,
                check=False,
            )
        else:
            result = wsl_run(
                [ZEEK_BIN, "-r", pcap_file, "policy/protocols/conn/mac-logging"],
                capture_output=True,
                text=True,
                check=False,
                cwd=zeek_log_dir,
            )

        # Neu mac-logging that bai, thu lai khong co no
        if result.returncode != 0:
            logger.warning(
                "Zeek voi mac-logging that bai, thu lai khong co mac-logging..."
            )
            logger.debug("Zeek stderr: %s", result.stderr)

            if IS_WINDOWS:
                result = wsl_run(
                    ["bash", "-c",
                     f"cd '{wsl_log_dir}' && {ZEEK_BIN} -r '{wsl_pcap}'"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
            else:
                result = wsl_run(
                    [ZEEK_BIN, "-r", pcap_file],
                    capture_output=True,
                    text=True,
                    check=True,
                    cwd=zeek_log_dir,
                )

        logger.debug("Zeek stdout: %s", result.stdout)
    except subprocess.CalledProcessError as exc:
        logger.error("Zeek that bai (exit code %d): %s", exc.returncode, exc.stderr)
        raise RuntimeError(
            f"Zeek that bai khi doc '{pcap_file}': {exc.stderr}"
        ) from exc
    except FileNotFoundError:
        raise RuntimeError(
            f"Khong tim thay lenh 'zeek' (da thu: {ZEEK_BIN}). "
            "Hay dam bao Zeek 8.x.x da duoc cai dat va nam trong PATH."
        )

    # ------------------------------------------------------------------
    # Buoc 2b: Kiem tra conn.log ton tai
    # ------------------------------------------------------------------
    # Zeek KHONG sinh conn.log khi segment khong co ket noi TCP/UDP nao no nhan
    # ra (vd 60s chi toan ARP/STP/goi di dang, hoac segment rat ngan). Truoc day
    # ta raise RuntimeError -> CA segment that bai va bi mat trang (2 segment bi
    # mat ngay sau dot tan cong trong du lieu thuc te). Thay vi vay: coi day la
    # "0 ket noi Zeek", ghi zeek_temp.csv RONG (chi header) va tiep tuc — dac
    # trung flow van den tu Argus (merge how=outer giu tat ca dong Argus).
    if not os.path.isfile(conn_log):
        logger.warning(
            "Zeek khong sinh conn.log tai '%s' (segment co the khong co ket noi "
            "TCP/UDP hop le). Tiep tuc voi dac trung Argus, Zeek rong.", conn_log)
        empty_cols = [
            "id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p",
            "proto", "service", "conn_state", "orig_l2_addr", "resp_l2_addr",
            "trans_depth", "res_bdy_len", "is_ftp_login", "http_method", "ftp_cmd",
        ]
        with open(zeek_csv, "w", encoding="utf-8", newline="") as f_out:
            csv.writer(f_out).writerow(empty_cols)
        return zeek_csv

    logger.info("Tim thay conn.log: %s", conn_log)

    # ------------------------------------------------------------------
    # Buoc 2c: Doc conn.log truc tiep bang Python
    # (dang tin cay hon zeek-cut khi cot khong ton tai)
    # ------------------------------------------------------------------
    header_fields, data_lines = _parse_zeek_log(conn_log)
    if not header_fields:
        raise RuntimeError(
            f"Khong tim thay dong #fields trong '{conn_log}'. "
            "File conn.log co the bi hong."
        )

    logger.info("conn.log co %d truong: %s", len(header_fields), header_fields)
    logger.info("conn.log co %d dong du lieu", len(data_lines))

    # Xac dinh index cua cac truong can trich xuat
    available = {}
    for field in WANTED_FIELDS:
        if field in header_fields:
            available[field] = header_fields.index(field)
        elif field not in ["trans_depth", "res_bdy_len", "http_method", "is_ftp_login", "ftp_cmd"]:
            logger.warning("Truong '%s' KHONG CO trong conn.log (bo qua)", field)

    # Doc du lieu tu http.log va ftp.log (neu co)
    # Thu tim trong thu muc tam truoc, neu khong co thu tim trong thu muc lam viec (fallback)
    http_log = os.path.join(zeek_log_dir, "http.log")
    if not os.path.isfile(http_log):
        http_log = os.path.join(work_dir, "http.log")
        
    ftp_log = os.path.join(zeek_log_dir, "ftp.log")
    if not os.path.isfile(ftp_log):
        ftp_log = os.path.join(work_dir, "ftp.log")

    http_data = _parse_http_log(http_log)
    ftp_data = _parse_ftp_log(ftp_log)

    logger.info("Da load du lieu HTTP cho %d uids", len(http_data))
    logger.info("Da load du lieu FTP cho %d uids", len(ftp_data))

    # Cot uid trong conn.log dung lam khoa anh xa
    uid_idx = header_fields.index("uid") if "uid" in header_fields else -1

    # CSV output columns. Tach truong so (default '0') va truong chuoi (default '').
    new_fields_num = ["trans_depth", "res_bdy_len", "is_ftp_login"]
    new_fields_str = ["http_method", "ftp_cmd"]
    new_fields = new_fields_num + new_fields_str
    csv_columns = [f for f in WANTED_FIELDS if f in available or f in new_fields]
    logger.info("Cac truong se xuat: %s", csv_columns)

    # ------------------------------------------------------------------
    # Buoc 2d: Ghi output ra zeek_temp.csv
    # ------------------------------------------------------------------
    with open(zeek_csv, "w", encoding="utf-8", newline="") as f_out:
        writer = csv.writer(f_out)
        writer.writerow(csv_columns)

        for parts in data_lines:
            row = []
            uid = parts[uid_idx] if (uid_idx != -1 and uid_idx < len(parts)) else ""
            
            for field in csv_columns:
                if field in new_fields:
                    val = "0" if field in new_fields_num else ""
                    if field in ("trans_depth", "res_bdy_len", "http_method") and uid in http_data:
                        val = str(http_data[uid][field])
                    elif field in ("is_ftp_login", "ftp_cmd") and uid in ftp_data:
                        val = str(ftp_data[uid][field])
                    row.append(val)
                elif field in available:
                    idx = available[field]
                    if idx < len(parts):
                        val = parts[idx]
                        # Zeek dung "-" cho gia tri trong
                        val = "" if val == "-" else val
                    else:
                        val = ""
                    row.append(val)
            writer.writerow(row)

    logger.info("Da tao thanh cong: %s (%d dong)", zeek_csv, len(data_lines))
    return zeek_csv


def _parse_zeek_log(log_path: str):
    """
    Doc va parse mot file log bat ky cua Zeek (TSV format).

    Returns:
        Tuple (header_fields, data_lines):
          - header_fields: List ten truong tu dong #fields
          - data_lines: List of list, moi dong du lieu da split bang tab
    """
    header_fields: list = []
    data_lines: list = []

    if not os.path.isfile(log_path):
        return header_fields, data_lines

    with open(log_path, "r", encoding="utf-8", newline="") as f:
        # First pass: extract header from `#fields` line
        for line in f:
            if line.startswith("#fields"):
                header_fields = line.rstrip("\n\r").split("\t")[1:]
                break
        f.seek(0)
        # Second pass: skip all `#` lines, parse data with csv.reader (TSV).
        reader = csv.reader(
            (line for line in f if line and not line.startswith("#")),
            delimiter="\t",
        )
        data_lines = [row for row in reader if row]
    return header_fields, data_lines


def _parse_http_log(http_log_path: str) -> dict:
    """
    Doc http.log va tong hop trans_depth, res_bdy_len, http_method theo uid.

    Returns:
        Dict {uid: {'trans_depth': int, 'res_bdy_len': int, 'http_method': str}}
    """
    http_data = {}
    header_fields, data_lines = _parse_zeek_log(http_log_path)
    if not header_fields:
        return http_data

    uid_idx = header_fields.index("uid") if "uid" in header_fields else -1
    depth_idx = header_fields.index("trans_depth") if "trans_depth" in header_fields else -1
    body_len_idx = header_fields.index("response_body_len") if "response_body_len" in header_fields else -1
    method_idx = header_fields.index("method") if "method" in header_fields else -1

    if uid_idx == -1:
        return http_data

    for parts in data_lines:
        if len(parts) <= uid_idx:
            continue
        uid = parts[uid_idx]
        
        trans_depth = 0
        if depth_idx != -1 and depth_idx < len(parts):
            val = parts[depth_idx]
            if val not in ("-", "", "(empty)"):
                try:
                    trans_depth = int(val)
                except ValueError:
                    pass

        res_bdy_len = 0
        if body_len_idx != -1 and body_len_idx < len(parts):
            val = parts[body_len_idx]
            if val not in ("-", "", "(empty)"):
                try:
                    res_bdy_len = int(val)
                except ValueError:
                    pass

        # Alg 3.4: luu gia tri HTTP method (GET/POST/...) lam mot phan cua key.
        # Viec dem ct_flw_http_mthd theo cua so truot duoc thuc hien o add_features.
        http_method = ""
        if method_idx != -1 and method_idx < len(parts):
            mval = parts[method_idx]
            if mval not in ("-", "", "(empty)"):
                http_method = mval.strip().upper()

        if uid not in http_data:
            http_data[uid] = {
                "trans_depth": trans_depth,
                "res_bdy_len": res_bdy_len,
                "http_method": http_method,
            }
        else:
            http_data[uid]["trans_depth"] = max(http_data[uid]["trans_depth"], trans_depth)
            http_data[uid]["res_bdy_len"] += res_bdy_len
            # Giu method dau tien khong rong (1 flow HTTP thuong cung method)
            if not http_data[uid]["http_method"] and http_method:
                http_data[uid]["http_method"] = http_method

    return http_data


def _parse_ftp_log(ftp_log_path: str) -> dict:
    """
    Doc ftp.log va tong hop is_ftp_login, ftp_cmd theo uid.

    Returns:
        Dict {uid: {'is_ftp_login': int, 'ftp_cmd': str}}
    """
    ftp_data = {}
    header_fields, data_lines = _parse_zeek_log(ftp_log_path)
    if not header_fields:
        return ftp_data

    uid_idx = header_fields.index("uid") if "uid" in header_fields else -1
    user_idx = header_fields.index("user") if "user" in header_fields else -1
    password_idx = header_fields.index("password") if "password" in header_fields else -1
    command_idx = header_fields.index("command") if "command" in header_fields else -1
    reply_code_idx = header_fields.index("reply_code") if "reply_code" in header_fields else -1

    if uid_idx == -1:
        return ftp_data

    for parts in data_lines:
        if len(parts) <= uid_idx:
            continue
        uid = parts[uid_idx]

        is_login = 0
        if reply_code_idx != -1 and reply_code_idx < len(parts):
            code = parts[reply_code_idx]
            if code == "230":
                is_login = 1
        
        if is_login == 0:
            user = parts[user_idx] if (user_idx != -1 and user_idx < len(parts)) else "-"
            password = parts[password_idx] if (password_idx != -1 and password_idx < len(parts)) else "-"
            if user not in ("-", "", "<unknown>") and password not in ("-", ""):
                is_login = 1

        has_cmd_val = ""
        if command_idx != -1 and command_idx < len(parts):
            cmd = parts[command_idx]
            if cmd not in ("-", "", "(empty)"):
                has_cmd_val = cmd.strip().upper()

        # Alg 3.6: luu gia tri FTP command lam mot phan cua key. Viec dem
        # ct_ftp_cmd theo cua so truot duoc thuc hien o add_features.
        if uid not in ftp_data:
            ftp_data[uid] = {"is_ftp_login": is_login, "ftp_cmd": has_cmd_val}
        else:
            if is_login == 1:
                ftp_data[uid]["is_ftp_login"] = 1
            if not ftp_data[uid]["ftp_cmd"] and has_cmd_val:
                ftp_data[uid]["ftp_cmd"] = has_cmd_val

    return ftp_data


def cleanup_zeek_logs(work_dir: str) -> None:
    """
    Xoa thu muc Zeek logs trung gian.

    Args:
        work_dir: Thu muc lam viec chua thu muc zeek_logs.
    """
    zeek_log_dir = os.path.join(work_dir, ZEEK_LOG_DIR)
    if os.path.isdir(zeek_log_dir):
        shutil.rmtree(zeek_log_dir, ignore_errors=True)
        logger.info("Da xoa thu muc Zeek logs: %s", zeek_log_dir)
