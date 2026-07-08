"""ClickHouseSink: batch insert per-family CSVs into flows_<family> tables.

Public API:
    ClickHouseSink(cfg).insert_family(family, csv_path, meta) -> int

The sink is intentionally type-aware: it casts every pandas cell to the
ClickHouse type declared in `schema.CSV_COLUMN_TYPES` so a string IP column
is sent as a Python `str` (matching the `String` column) instead of an
`object` that clickhouse-driver would refuse or coerce silently.

NaN handling: empty numeric cells become `0`; empty string cells become `""`.
`ts` is sourced from the `ltime` column (Unix seconds in UNSW-NB15) when
present and > 0; otherwise from `now()` (UTC).
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pandas as pd

from .schema import AUDIT_COLUMNS, CSV_COLUMNS, CSV_COLUMN_TYPES

logger = logging.getLogger(__name__)


_AUDIT_NAMES = [n for n, _ in AUDIT_COLUMNS]
# Names of the columns we actually insert (audit + every CSV feature).
_INSERT_COLUMNS = _AUDIT_NAMES + CSV_COLUMNS


def _cast_cell(value: Any, ch_type: str) -> Any:
    """Convert a single pandas cell to a Python value compatible with `ch_type`.

    Never returns None — ClickHouse's strict type checking rejects None for
    non-Nullable columns.
    """
    t = ch_type.lower()
    is_float = t.startswith("float")
    is_num = t.startswith("int") or t.startswith("uint") or is_float

    # NaN / None / missing -> type-appropriate default
    if value is None or (isinstance(value, float) and value != value):
        return 0.0 if is_float else (0 if is_num else "")
    try:
        if pd.isna(value):
            return 0.0 if is_float else (0 if is_num else "")
    except (TypeError, ValueError):
        pass

    if is_num:
        try:
            return float(value) if is_float else int(value)
        except (TypeError, ValueError):
            return 0.0 if is_float else 0
    return str(value)


def _resolve_ts(row: pd.Series, now: datetime, segment_fallback: float | None = None) -> datetime:
    """Resolve the audit `ts` for a row.

    UNSW-NB15 `ltime` is Unix seconds; treat values > 0 as real epochs.
    Otherwise use `segment_fallback` (segment-level t_start from meta) so rows
    from the same segment share a real timestamp instead of collapsing onto
    the single `now()` value used as the last-resort default.
    """
    if "ltime" in row.index:
        try:
            lt = row["ltime"]
            if pd.notna(lt) and float(lt) > 0:
                return datetime.fromtimestamp(float(lt), tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            pass
    if segment_fallback and segment_fallback > 0:
        return datetime.fromtimestamp(segment_fallback, tz=timezone.utc)
    return now


class ClickHouseSink:
    """Batch insert per-family flows_<family> CSV rows into ClickHouse.

    Args:
        cfg: dict with keys `host`, `port`, `database`, `batch_size`,
             optionally `user` and `password` for authenticated servers.
        client: optional injectable clickhouse_driver.Client (for tests).
    """

    def __init__(self, cfg: Dict[str, Any], client: Optional[Any] = None) -> None:
        self.database: str = cfg["database"]
        self.batch_size: int = int(cfg.get("batch_size", 10000))
        if client is not None:
            self.client = client
        else:
            from clickhouse_driver import Client  # type: ignore

            client_kwargs: Dict[str, Any] = {
                "host": cfg["host"],
                "port": cfg["port"],
                "database": self.database,
            }
            # Auth is optional — empty user/password works on default dev install.
            if cfg.get("user"):
                client_kwargs["user"] = cfg["user"]
            if cfg.get("password"):
                client_kwargs["password"] = cfg["password"]
            self.client = Client(**client_kwargs)

    # ------------------------------------------------------------------
    def insert_family(self, family: str, csv_path: str, meta: Dict[str, Any]) -> int:
        """Insert one per-family CSV into flows_<family>.

        Args:
            family: one of FAMILIES.
            csv_path: path to *_features.csv for this family.
            meta: dict with `segment_id`, `interface`, and optionally
                `t_window` / `pcap_file` (segment-level audit context).

        Returns:
            number of rows inserted (0 if CSV is empty / missing).
        """
        try:
            df = pd.read_csv(csv_path, low_memory=False)
        except FileNotFoundError:
            logger.warning("CSV not found for family=%s: %s", family, csv_path)
            return 0
        except pd.errors.EmptyDataError:
            return 0

        if df.empty:
            return 0

        now = datetime.now(timezone.utc)
        segment_fallback = meta.get("t_start")

        # Column-name list for the INSERT statement (in stable order).
        colnames = list(_INSERT_COLUMNS)
        # The DDL declares backtick-quoted names; build the quoted list once.
        quoted = ", ".join(f"`{c}`" for c in colnames)
        sql = f"INSERT INTO {self.database}.flows_{family} ({quoted}) VALUES"

        # Build rows.
        rows: List[List[Any]] = []
        for _, r in df.iterrows():
            ts = _resolve_ts(r, now, segment_fallback)
            subtype = ""
            if "predicted_class" in r.index and pd.notna(r.get("predicted_class")):
                subtype = str(r["predicted_class"]).strip()
            # "Normal" (case-insensitive) is the only benign label; everything
            # else is an attack. Empty subtype = unknown, treat as benign.
            is_attack = 0 if subtype.lower() == "normal" else 1 if subtype else 0
            audit_values = [
                ts,
                str(meta.get("segment_id", "")),
                str(family),
                subtype,
                is_attack,
                str(meta.get("interface", "")),
                str(meta.get("t_window", "")),
                str(meta.get("pcap_file", "")),
            ]
            feat_values = [
                _cast_cell(r[c] if c in r.index else float("nan"),
                           CSV_COLUMN_TYPES[c])
                for c in CSV_COLUMNS
            ]
            rows.append(audit_values + feat_values)

        total = 0
        for i in range(0, len(rows), self.batch_size):
            batch = rows[i : i + self.batch_size]
            self.client.execute(sql, batch)
            total += len(batch)

        logger.info(
            "insert_family family=%s csv=%s rows=%d segment_id=%s",
            family,
            csv_path,
            total,
            meta.get("segment_id", ""),
        )
        return total

    # ------------------------------------------------------------------
    def insert_run(self, run: Dict[str, Any]) -> None:
        """Insert one row into pipeline_runs for this segment processing run.

        Args:
            run: dict with keys matching the pipeline_runs DDL:
                - segment_id (str)
                - started_at (datetime, UTC)
                - finished_at (datetime, UTC)
                - total_flows (int)
                - per-family counts: dos/exploits/fuzzers/generic/analysis/
                  reconnaissance/shellcode (int)
                - duration_sec (float)
                - status (str): one of "running", "success", "failed"
                - error_msg (str, optional)
                - run_id (str/UUID, optional) — auto-generated if missing
        """
        # Normalize per-family counts: any missing family is 0.
        per_family_keys = (
            "dos",
            "exploits",
            "fuzzers",
            "generic",
            "analysis",
            "reconnaissance",
            "shellcode",
        )
        per_family = {k: int(run.get(k, 0) or 0) for k in per_family_keys}

        run_id = run.get("run_id") or uuid.uuid4()
        started_at = run.get("started_at")
        finished_at = run.get("finished_at")
        if started_at is None:
            started_at = datetime.now(timezone.utc)
        if finished_at is None:
            finished_at = datetime.now(timezone.utc)

        row = [
            run_id,
            str(run.get("segment_id", "")),
            started_at,
            finished_at,
            int(run.get("total_flows", 0) or 0),
            per_family["dos"],
            per_family["exploits"],
            per_family["fuzzers"],
            per_family["generic"],
            per_family["analysis"],
            per_family["reconnaissance"],
            per_family["shellcode"],
            float(run.get("duration_sec", 0.0) or 0.0),
            str(run.get("status", "success")),
            str(run.get("error_msg", "") or ""),
        ]

        sql = (
            f"INSERT INTO {self.database}.pipeline_runs "
            "(run_id, segment_id, started_at, finished_at, total_flows, "
            "dos, exploits, fuzzers, generic, analysis, reconnaissance, "
            "shellcode, duration_sec, status, error_msg) VALUES"
        )
        self.client.execute(sql, [row])
        logger.info(
            "insert_run segment_id=%s status=%s total_flows=%d duration_sec=%.2f",
            row[1],
            row[13],
            row[4],
            row[12],
        )
