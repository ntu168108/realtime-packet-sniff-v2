"""Consumer service: Kafka -> tmpfs pcap -> process_pcap -> per-family sink.

The consumer reads pcap-segment blobs from Kafka, writes each one to /dev/shm,
runs the Extraction/Classification pipeline via a `runner` callable, and pushes
the resulting per-family CSVs to a `sink` (Phase 3: ClickHouseSink, Phase 2:
in-memory or file count sink).

Public API:
    process_segment(blob, runner, sink) -> dict
    default_runner(pcap_path) -> dict        # used by main(), not by tests
    main()                                   # Kafka loop
"""
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import load_config
from .pcap_segment import parse_segment

logger = logging.getLogger(__name__)


class _SegmentAdapter:
    """LoggerAdapter that injects `segment_id` into every record's `extra` dict.

    Used to correlate per-segment Kafka messages in the journal without
    repeating the segment_id on every log line.
    """

    def __init__(self, base_logger, extra: dict):
        self._log = base_logger
        self._extra = extra

    def info(self, msg, *args, **kwargs):
        self._log.info(msg, *args, extra=self._extra, **kwargs)

    def error(self, msg, *args, **kwargs):
        self._log.error(msg, *args, extra=self._extra, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self._log.warning(msg, *args, extra=self._extra, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self._log.debug(msg, *args, extra=self._extra, **kwargs)


# Where to drop the temporary pcap. /dev/shm is ram-backed; fall back to
# tempfile if unavailable (e.g. on macOS or restricted containers).
SHM_DIR = Path("/dev/shm")
if not (SHM_DIR.exists() and os.access(str(SHM_DIR), os.W_OK)):
    SHM_DIR = Path(tempfile.gettempdir())


# Circuit breaker chống DoS: segment vượt số gói này bị coi là flood và BỎ QUA
# bước trích xuất nặng (Argus/Zeek/pandas nạp cả CSV vào RAM → OOM cả host).
# Chốt chặn cuối phòng khi segment lớn lọt qua trước khi DosGuard kịp cắt tải.
# Override qua env EC_MAX_PKTS_PER_SEGMENT.
MAX_PKTS_PER_SEGMENT = int(os.environ.get("EC_MAX_PKTS_PER_SEGMENT", "150000"))


# Where to find the Extraction-and-classification repo.
# Resolution order:
#   1. NB15_EC env var (operator override for prod)
#   2. <repo>/Extraction-and-classification (the repo's own sibling dir)
#   3. ~/sniff/Extraction-and-classification (legacy prod path)
_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_EC_CANDIDATES = [
    _REPO_ROOT / "Extraction-and-classification",
    Path(os.path.expanduser("~/sniff/Extraction-and-classification")),
]


def _default_ec() -> Path:
    for cand in _DEFAULT_EC_CANDIDATES:
        if cand.is_dir():
            return cand
    # Fall back to the first candidate so logs/error messages show a real path.
    return _DEFAULT_EC_CANDIDATES[0]


EC = Path(os.environ.get("NB15_EC") or str(_default_ec()))

# Family key -> directory containing the per-family filtered CSV.
FAMILY_DIRS = {
    "dos": "Filter_DoS_feature",
    "exploits": "Filter_Exploits_feature",
    "fuzzers": "Filter_Fuzzers_feature",
    "generic": "Filter_Generic_feature",
    "analysis": "Filter_Analysis_feature",
    "reconnaissance": "Filter_Reconnaissance_feature",
    "shellcode": "Filter_Shellcode_feature",
}


def default_runner(pcap_path):
    """Run auto_pipeline on a pcap, return {family: csv_path}.

    Looks for per-family outputs in EC/CSV/CSV_Full_feature/ (where filters
    actually write them given the file-input mode of the filter CLI).

    Fast-path: if all 7 per-family CSVs already exist for this segment's
    stem, skip auto_pipeline (Argus+Zeek run takes minutes; we only need
    the resulting CSVs for the sink).
    """
    base = Path(pcap_path).stem
    full_feature_dir = EC / "CSV" / "CSV_Full_feature"

    def _collect_outputs() -> dict:
        out = {}
        for fam in FAMILY_DIRS:
            cands = []
            fam_dir = EC / "CSV" / FAMILY_DIRS[fam]
            for p in fam_dir.glob(f"*_{fam}_features.csv"):
                # For fam="dos": the pipeline writes "{base}_dos_features.csv" as
                # the dos-family-filtered output. There is NO "_dos_features_dos_features.csv"
                # for family=dos (it would be the dos-of-dos filter run, which the
                # pipeline does not produce). So accept the bare "_dos_features.csv".
                # For fam != "dos": the file is named "{base}_dos_features_{fam}_features.csv".
                # Disambiguate: take the file whose name ends with the family marker
                # before ".csv", i.e. accept "*_{fam}_features.csv" only when there
                # is an additional underscore-separated segment before the family
                # marker (other than the "_dos_features" base). Simpler rule:
                # accept "*_{fam}_features.csv" except when fam == "dos" and the
                # file name ends exactly with "_dos_features.csv" — BUT this is
                # actually the dos family output. So we ALWAYS accept the match
                # for fam=="dos" when the name ends with "_dos_features.csv".
                name = p.name
                # CHỈ nhận output CỦA CHÍNH segment này (neo theo stem pcap).
                # Nếu không neo, glob "*_{fam}_features.csv" sẽ nhặt cả file mẫu
                # sample_*_features.csv (hoặc output segment khác) nằm chung thư
                # mục → fast-path bên dưới luôn đủ 7 file → auto_pipeline KHÔNG
                # bao giờ chạy trên pcap thật. Đây là gốc rễ của "flow giả".
                if not name.startswith(base + "_"):
                    continue
                if fam == "dos" and name.endswith("_dos_features.csv"):
                    cands.append(p)
                elif fam != "dos" and name.endswith(f"_{fam}_features.csv"):
                    cands.append(p)
            cands = sorted(cands)
            if cands:
                out[fam] = str(cands[-1])
        return out

    existing = _collect_outputs()
    if len(existing) == len(FAMILY_DIRS):
        logger.info("runner: reusing %d existing per-family CSVs for %s",
                    len(existing), base)
        return existing

    env = dict(
        os.environ,
        NB15_WORKSPACE_ROOT=str(EC),
        NB15_DATA_ROOT=str(EC),
        NB15_OUTPUT_DIR=str(full_feature_dir),
    )
    subprocess.run(
        [sys.executable, str(EC / "MODULE_AUTO" / "auto_pipeline.py"), pcap_path],
        cwd=str(EC),
        env=env,
        check=True,
        timeout=1800,
    )
    return _collect_outputs()


def process_segment(blob, runner, sink):
    """Parse one segment blob, run pipeline, push results to sink.

    Returns:
        dict with keys: segment_id, n_flows_by_family, status.
        status is "success" or "failed". Never raises.

    Also writes one audit row into pipeline_runs (via sink.insert_run) when
    the sink supports it; missing insert_run is silently ignored so test
    stubs keep working.
    """
    sid = None
    pcap_path = None
    n_by_family = {}
    started_at = datetime.now(timezone.utc)
    t0 = time.monotonic()
    error_msg = ""
    status = "success"
    try:
        meta, pcap_bytes = parse_segment(blob)
        sid = meta["segment_id"]

        # Circuit breaker: segment quá lớn (dấu hiệu DoS flood) → KHÔNG ghi pcap
        # ra /dev/shm, KHÔNG chạy Argus/Zeek/pandas. Ghi nhận trực tiếp là DoS
        # để tránh cạn RAM/OOM cả máy. Vẫn ghi 1 dòng audit ở finally.
        n_pkts = int(meta.get("n_pkts", 0))
        if n_pkts > MAX_PKTS_PER_SEGMENT:
            logger.warning(
                "[segment=%s] n_pkts=%d > cap=%d → SHED DoS: bỏ trích xuất nặng",
                sid, n_pkts, MAX_PKTS_PER_SEGMENT)
            n_by_family = {"dos": n_pkts}
            status = "dos_shed"
            return {"segment_id": sid, "n_flows_by_family": n_by_family,
                    "status": status}

        # Sanitize segment_id for filesystem use.
        safe = "".join(c for c in sid if c.isalnum() or c in "-_") or "seg"
        pcap_path = str(SHM_DIR / f"{safe}.pcap")
        with open(pcap_path, "wb") as f:
            f.write(pcap_bytes)

        fam_csv = runner(pcap_path)
        for fam, csv_path in fam_csv.items():
            n_by_family[fam] = sink.insert_family(fam, csv_path, meta)
    except Exception as exc:  # noqa: BLE001 - must never raise to Kafka loop
        logger.exception("process_segment failed for sid=%s: %s", sid, exc)
        n_by_family = {"error": str(exc)}
        status = "failed"
        error_msg = str(exc)
    finally:
        if pcap_path is not None:
            try:
                os.remove(pcap_path)
            except OSError:
                pass

        # Audit write: best-effort; do not let it change the return status.
        # We always emit one row — even if parsing failed and sid is unknown
        # (use a synthetic placeholder so the failure is visible in the
        # pipeline-health panel).
        finished_at = datetime.now(timezone.utc)
        duration_sec = float(time.monotonic() - t0)
        total_flows = sum(int(v) for v in n_by_family.values()
                          if isinstance(v, (int, float)))
        per_family_keys = (
            "dos", "exploits", "fuzzers", "generic",
            "analysis", "reconnaissance", "shellcode",
        )
        audit_sid = sid if sid is not None else f"unparseable-{uuid.uuid4().hex[:8]}"
        run_payload = {
            "run_id": uuid.uuid4(),
            "segment_id": audit_sid,
            "started_at": started_at,
            "finished_at": finished_at,
            "total_flows": total_flows,
            "duration_sec": duration_sec,
            "status": status,
            "error_msg": error_msg,
        }
        for fam in per_family_keys:
            v = n_by_family.get(fam, 0)
            run_payload[fam] = int(v) if isinstance(v, (int, float)) else 0
        insert_run = getattr(sink, "insert_run", None)
        if callable(insert_run):
            try:
                insert_run(run_payload)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "insert_run failed for sid=%s (continuing)", audit_sid)

    return {"segment_id": sid, "n_flows_by_family": n_by_family, "status": status}


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    cfg = load_config()

    from .clickhouse_sink import ClickHouseSink
    sink = ClickHouseSink(cfg["clickhouse"])

    from kafka import KafkaConsumer

    consumer = KafkaConsumer(
        cfg["kafka"]["topic"],
        bootstrap_servers=cfg["kafka"]["bootstrap"],
        enable_auto_commit=False,
        auto_offset_reset="earliest",
        group_id="ec-consumer",
        max_partition_fetch_bytes=cfg["kafka"]["segment_max_bytes"] + (1 << 20),
    )

    # Heartbeat counters + intervals (override via env).
    hb_segments = int(os.environ.get("EC_HEARTBEAT_EVERY_N", "10"))
    hb_seconds = float(os.environ.get("EC_HEARTBEAT_EVERY_SEC", "60"))
    n_processed = 0
    n_failed = 0
    last_segment_id: Optional[str] = None
    t_last_hb = time.monotonic()

    logger.info(
        "consumer starting | bootstrap=%s topic=%s group=ec-consumer "
        "heartbeat_every_n=%d heartbeat_every_sec=%.0f",
        cfg["kafka"]["bootstrap"], cfg["kafka"]["topic"], hb_segments, hb_seconds,
    )

    def _emit_heartbeat(force: bool = False) -> None:
        nonlocal t_last_hb
        now_mono = time.monotonic()
        if not force and (now_mono - t_last_hb) < hb_seconds:
            return
        logger.info(
            "heartbeat processed=%d failed=%d last_segment_id=%s uptime_sec=%.1f",
            n_processed, n_failed, last_segment_id or "-", now_mono,
        )
        t_last_hb = now_mono

    try:
        for msg in consumer:
            try:
                meta_preview, _ = parse_segment(msg.value)
                cur_sid = meta_preview.get("segment_id", "?")
            except Exception:
                cur_sid = "?"
            _SegmentAdapter(logger, {"segment_id": cur_sid}).info(
                "received message offset=%d partition=%d size=%d",
                msg.offset, msg.partition, len(msg.value),
            )

            summ = process_segment(msg.value, default_runner, sink)
            n_processed += 1
            last_segment_id = summ.get("segment_id") or last_segment_id
            if summ["status"] == "failed":
                n_failed += 1
                _SegmentAdapter(logger, {"segment_id": cur_sid}).error(
                    "segment processing FAILED: %s", summ,
                )
            else:
                # "success" hoặc "dos_shed" đều là đã xử lý xong → commit offset
                # để KHÔNG lặp lại. (dos_shed mà không commit sẽ bị đọc lại vô
                # hạn = tự làm nghẽn chính mình.)
                _SegmentAdapter(logger, {"segment_id": cur_sid}).info(
                    "segment %s flows=%s",
                    summ["status"], summ.get("n_flows_by_family", {}),
                )
                consumer.commit()

            if summ["status"] != "failed" and n_processed % hb_segments == 0:
                _emit_heartbeat(force=True)
            else:
                _emit_heartbeat(force=False)
    except KeyboardInterrupt:
        logger.info("consumer: KeyboardInterrupt, exiting")
    finally:
        _emit_heartbeat(force=True)
        try:
            consumer.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()