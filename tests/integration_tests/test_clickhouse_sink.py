"""Unit tests for integration.clickhouse_sink.ClickHouseSink.

Uses a FakeClient that records every `execute` call so we can assert:
  - The right table is targeted (flows_<family>).
  - The right number of rows is inserted.
  - Types in the inserted rows match schema.CSV_COLUMN_TYPES for each column
    (Python int for Int64, float for Float64, str for String).
  - NaN values become 0 / '' sensibly.
  - IP/proto columns are emitted as Python str (not float / None).
"""
from datetime import datetime

import pandas as pd

from integration.clickhouse_sink import ClickHouseSink, _cast_cell


class FakeClient:
    def __init__(self) -> None:
        self.execs: list = []

    def execute(self, sql, rows=None):
        self.execs.append({"sql": sql, "rows": rows or []})
        return []


def _make_sink() -> tuple:
    """7 tests repeat this setup verbatim — shared helper."""
    fake = FakeClient()
    sink = ClickHouseSink(
        {"host": "h", "port": 9000, "database": "network_ids", "batch_size": 10},
        client=fake,
    )
    return sink, fake


def test_cast_cell_nan_int():
    import math

    assert _cast_cell(float("nan"), "Int64") == 0
    assert _cast_cell(float("nan"), "UInt8") == 0
    assert _cast_cell(float("nan"), "Float64") == 0.0


def test_cast_cell_string():
    assert _cast_cell("10.0.0.5", "String") == "10.0.0.5"
    assert _cast_cell("udp", "LowCardinality(String)") == "udp"


def test_cast_cell_numeric():
    assert _cast_cell(53, "Int64") == 53
    assert _cast_cell(1.23, "Float64") == 1.23
    assert _cast_cell("42", "Int64") == 42  # coercion works


def test_sink_batches_and_emits_typed_rows(tmp_path):
    csv = tmp_path / "x_dos_features.csv"
    df = pd.DataFrame(
        {
            "src_mac": ["aa:bb:cc:dd:ee:ff"] * 3,
            "dst_mac": ["11:22:33:44:55:66"] * 3,
            "srcip": ["10.0.0.5", "10.0.0.5", "10.0.0.6"],
            "dstip": ["10.0.0.9", "10.0.0.9", "10.0.0.9"],
            "sport": [1000, 1001, 1002],
            "dport": [53, 53, 80],
            "proto": ["udp", "udp", "tcp"],
            "service": ["-", "-", "http"],
            "state": ["SHR", "SHR", "FIN"],
            "dur": [0.0, 0.1, 0.2],
            "spkts": [1, 2, 3],
            "dpkts": [4, 5, 6],
            "sbytes": [100, 200, 300],
            "dbytes": [400, 500, 600],
            "sttl": [64, 64, 64],
            "dttl": [64, 64, 64],
            "smean": [50, 100, 150],
            "dmean": [200, 250, 300],
            "ltime": [1700000000, 1700000001, 1700000002],
            "predicted_class": ["", "", "Attack"],
        }
    )
    df.to_csv(csv, index=False)

    sink, fake = _make_sink()
    n = sink.insert_family(
        "dos",
        str(csv),
        {
            "segment_id": "S1",
            "interface": "ens33",
            "t_window": "60s",
            "pcap_file": "p1",
        },
    )
    assert n == 3
    assert len(fake.execs) == 1
    call = fake.execs[0]
    sql = call["sql"]
    rows = call["rows"]
    assert "INSERT INTO network_ids.flows_dos" in sql

    # Inspect column ordering inside the SQL: audit + CSV_COLUMNS
    from integration.schema import AUDIT_COLUMNS, CSV_COLUMNS, CSV_COLUMN_TYPES

    expected_names = [n for n, _ in AUDIT_COLUMNS] + CSV_COLUMNS
    for name in expected_names:
        assert f"`{name}`" in sql, f"missing column in INSERT: {name}"

    # Row shape: each row should be len(expected_names) values
    assert all(len(r) == len(expected_names) for r in rows)

    # Find indexes for type-critical columns
    idx = {n: i for i, n in enumerate(expected_names)}

    # IP/proto columns must be Python strings (not floats / None)
    for r in rows:
        assert isinstance(r[idx["srcip"]], str), f"srcip not str: {r[idx['srcip']]!r}"
        assert isinstance(r[idx["dstip"]], str), f"dstip not str: {r[idx['dstip']]!r}"
        assert isinstance(r[idx["proto"]], str), f"proto not str: {r[idx['proto']]!r}"
        assert isinstance(r[idx["state"]], str)
        assert isinstance(r[idx["service"]], str)

    # sport / dport are Int64 in schema -> python int
    for r in rows:
        assert isinstance(r[idx["sport"]], int)
        assert isinstance(r[idx["dport"]], int)
        # dur is Float64 -> python float
        assert isinstance(r[idx["dur"]], float)

    # is_attack derived from predicted_class: row 2 has 'Attack' -> is_attack == 1
    assert rows[0][idx["is_attack"]] == 0
    assert rows[2][idx["is_attack"]] == 1

    # audit family filled in
    assert all(r[idx["attack_family"]] == "dos" for r in rows)
    assert all(r[idx["segment_id"]] == "S1" for r in rows)
    assert all(r[idx["interface"]] == "ens33" for r in rows)

    # ts should be a datetime when ltime > 0
    assert all(isinstance(r[idx["ts"]], datetime) for r in rows)


def test_sink_handles_missing_columns(tmp_path):
    """A CSV that lacks columns from CSV_COLUMNS must not crash."""
    csv = tmp_path / "x_dos_features.csv"
    df = pd.DataFrame({"srcip": ["10.0.0.1"], "dstip": ["10.0.0.2"], "sport": [80]})
    df.to_csv(csv, index=False)
    sink, fake = _make_sink()
    n = sink.insert_family("dos", str(csv), {"segment_id": "S2"})
    assert n == 1
    assert len(fake.execs) == 1


def test_sink_empty_csv_returns_zero(tmp_path):
    csv = tmp_path / "empty.csv"
    csv.write_text("srcip,dstip\n")  # header only
    sink, fake = _make_sink()
    n = sink.insert_family("dos", str(csv), {"segment_id": "S3"})
    assert n == 0
    assert fake.execs == []  # no insert attempted


def test_sink_batches_large_csv(tmp_path):
    csv = tmp_path / "big.csv"
    df = pd.DataFrame(
        {"srcip": ["10.0.0.1"] * 25, "dstip": ["10.0.0.2"] * 25, "sport": list(range(25))}
    )
    df.to_csv(csv, index=False)
    sink, fake = _make_sink()
    n = sink.insert_family("dos", str(csv), {"segment_id": "S4"})
    assert n == 25
    # 25 rows / batch=10 -> 3 batches
    assert len(fake.execs) == 3
    assert len(fake.execs[0]["rows"]) == 10
    assert len(fake.execs[1]["rows"]) == 10
    assert len(fake.execs[2]["rows"]) == 5


def test_sink_rejects_placeholder_fake_flows(tmp_path):
    """The quality guard still drops the 'flow giả' signature — a broadcast
    src MAC (impossible as a source) and all-zero-volume rows — while keeping
    a genuine flow that shares the same CSV. Absence of a src_mac column must
    NOT, by itself, get a row dropped (see test_sink_handles_missing_columns)."""
    csv = tmp_path / "mix_dos_features.csv"
    df = pd.DataFrame(
        {
            "src_mac": ["ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:01"],
            "srcip": ["10.0.0.5", "192.168.106.60", "10.0.0.5"],
            "dstip": ["10.0.0.9", "192.168.101.135", "10.0.0.9"],
            "sport": [1000, 40000, 1001],
            "dport": [53, 80, 53],
            "proto": ["udp", "tcp", "udp"],
            "spkts": [0, 10, 0],
            "dpkts": [0, 12, 0],
            "sbytes": [0, 800, 0],
            "dbytes": [0, 900, 0],
            "dur": [0.0, 1.5, 0.0],
        }
    )
    df.to_csv(csv, index=False)
    sink, fake = _make_sink()
    n = sink.insert_family("dos", str(csv), {"segment_id": "S6"})
    # row0: broadcast-src-MAC -> dropped; row2: all-zero volume -> dropped;
    # row1: real flow -> kept.
    assert n == 1
    assert len(fake.execs) == 1
    assert len(fake.execs[0]["rows"]) == 1


def test_sink_missing_file_returns_zero(tmp_path):
    sink, fake = _make_sink()
    n = sink.insert_family("dos", str(tmp_path / "no.csv"), {"segment_id": "S5"})
    assert n == 0
    assert fake.execs == []


def test_insert_run_writes_one_pipeline_runs_row():
    """insert_run should issue exactly one INSERT into pipeline_runs
    with the per-family counts, total_flows, duration_sec, status fields
    from the run dict."""
    import uuid as _uuid

    sink, fake = _make_sink()
    rid = _uuid.uuid4()
    started = datetime(2026, 6, 21, 10, 0, 0)
    finished = datetime(2026, 6, 21, 10, 1, 30)
    sink.insert_run(
        {
            "run_id": rid,
            "segment_id": "SEG-AUDIT-1",
            "started_at": started,
            "finished_at": finished,
            "total_flows": 100,
            "dos": 10,
            "exploits": 20,
            "fuzzers": 30,
            "generic": 5,
            "analysis": 0,
            "reconnaissance": 35,
            "shellcode": 0,
            "duration_sec": 90.5,
            "status": "success",
            "error_msg": "",
        }
    )
    assert len(fake.execs) == 1
    call = fake.execs[0]
    sql = call["sql"]
    rows = call["rows"]
    assert "INSERT INTO network_ids.pipeline_runs" in sql
    assert "run_id" in sql and "segment_id" in sql and "status" in sql
    assert len(rows) == 1
    row = rows[0]
    # row layout matches DDL: run_id, segment_id, started_at, finished_at,
    # total_flows, dos, exploits, fuzzers, generic, analysis,
    # reconnaissance, shellcode, duration_sec, status, error_msg
    assert row[0] == rid
    assert row[1] == "SEG-AUDIT-1"
    assert row[2] == started
    assert row[3] == finished
    assert row[4] == 100
    assert row[5] == 10  # dos
    assert row[6] == 20  # exploits
    assert row[7] == 30  # fuzzers
    assert row[8] == 5   # generic
    assert row[9] == 0   # analysis
    assert row[10] == 35  # reconnaissance
    assert row[11] == 0   # shellcode
    assert abs(row[12] - 90.5) < 1e-6
    assert row[13] == "success"
    assert row[14] == ""


def test_insert_run_auto_generates_run_id_and_defaults():
    """insert_run without run_id/timestamps must still emit a valid row."""
    sink, fake = _make_sink()
    sink.insert_run(
        {
            "segment_id": "SEG-AUDIT-2",
            "total_flows": 0,
            "status": "failed",
            "error_msg": "boom",
        }
    )
    assert len(fake.execs) == 1
    row = fake.execs[0]["rows"][0]
    # run_id is auto-generated UUID
    import uuid as _uuid

    assert isinstance(row[0], _uuid.UUID)
    assert row[1] == "SEG-AUDIT-2"
    # started_at / finished_at populated as datetimes
    assert isinstance(row[2], datetime)
    assert isinstance(row[3], datetime)
    # per-family defaults to 0
    for i in range(5, 12):
        assert row[i] == 0
    assert row[13] == "failed"
    assert row[14] == "boom"
