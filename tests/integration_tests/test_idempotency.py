"""Phase 6 Task 6.2 — idempotency proof for ClickHouseSink.

The ReplacingMergeTree dedup key is
  (segment_id, srcip, dstip, sport, dport, proto, ts)
so re-inserting rows with the same (5-tuple, ts) collapses them via
OPTIMIZE FINAL. We exercise this end-to-end:
  1. Build a synthetic dos_features CSV with N unique tuples (all ltime>0
     and offset sub-second so each row has a unique DateTime64(3) ts).
  2. Insert via ClickHouseSink once, OPTIMIZE FINAL → baseline = N.
  3. Insert the same CSV 3 more times.
  4. OPTIMIZE FINAL → count(FINAL) MUST equal baseline.

Requires: ClickHouse reachable at localhost:9000, network_ids database,
the network_ids.flows_dos table already created by sql/clickhouse_init.sql.
"""
import csv as csvmod
import os
import tempfile
import time
from pathlib import Path

import pytest

from integration.clickhouse_sink import ClickHouseSink


SCHEMA_HEADER = [
    "srcip","dstip","sport","dport","proto","service","state","dur","spkts","dpkts",
    "sbytes","dbytes","sttl","dttl","smean","dmean","trans_depth","response_body_len",
    "is_ftp_login","rate","sloss","dloss","sload","dload","swin","dwin","stcpb","dtcpb",
    "sjit","djit","stime","ltime","sinpkt","dinpkt","tcprtt","synack","ackdat",
    "is_sm_ips_ports","ct_state_ttl","ct_dst_ltm","ct_src_ltm","ct_srv_dst","ct_srv_src",
    "ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm","ct_flw_http_mthd","ct_ftp_cmd",
    "src_mac","dst_mac","predicted_class",
]


@pytest.fixture(scope="module")
def ch_client():
    clickhouse_driver = pytest.importorskip(
        "clickhouse_driver",
        reason="clickhouse_driver not installed — skip live ClickHouse tests",
    )
    client = clickhouse_driver.Client(host="localhost", port=9000,
                                      database="network_ids")
    yield client
    client.disconnect()


@pytest.fixture
def fresh_sid(ch_client):
    """Provide a fresh unique segment_id and clean up after the test."""
    sid = f"idem-test-{int(time.time()*1000)}"
    yield sid
    # best-effort cleanup
    try:
        ch_client.execute(
            "ALTER TABLE network_ids.flows_dos DELETE WHERE segment_id=%(s)s",
            {"s": sid})
    except Exception:
        pass


def _make_csv(path: Path, n: int, t_start: float) -> None:
    with open(path, "w", newline="") as f:
        w = csvmod.writer(f)
        w.writerow(SCHEMA_HEADER)
        for i in range(n):
            # ltime > 0 and distinct sub-second offsets → unique DateTime64(3) ts
            ltime = t_start + i * 0.001
            w.writerow([
                f"10.0.0.{(i%253)+1}", "10.0.0.9", 1000+i, 53, "udp",
                "-", "SHR", "0.0", 0, 0, 0, 0, 64, 64, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, ltime, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                "00:00:00:00:00:00","00:00:00:00:00:00","",
            ])


def _count_final(ch_client, sid: str) -> int:
    return int(ch_client.execute(
        "SELECT count() FROM network_ids.flows_dos FINAL WHERE segment_id=%(s)s",
        {"s": sid})[0][0])


def _count_unmerged(ch_client, sid: str) -> int:
    return int(ch_client.execute(
        "SELECT count() FROM network_ids.flows_dos WHERE segment_id=%(s)s",
        {"s": sid})[0][0])


def test_reprocess_same_segment_id_does_not_multiply_rows(ch_client, fresh_sid, tmp_path):
    """Insert same N-row CSV 4 times. After OPTIMIZE FINAL, count must = N."""
    sid = fresh_sid
    n = 200
    t_start = time.time()  # TTL-safe (must be within last 14 days)

    csv_path = tmp_path / f"{sid}_dos_features.csv"
    _make_csv(csv_path, n, t_start)

    sink = ClickHouseSink(
        {"host": "localhost", "port": 9000, "database": "network_ids",
         "batch_size": 10000})
    meta = {"segment_id": sid, "interface": "ens33", "t_window": "idempotency",
            "pcap_file": "/tmp/idem.pcap", "t_start": t_start}

    # Baseline insert.
    sink.insert_family("dos", str(csv_path), meta)
    ch_client.execute("OPTIMIZE TABLE network_ids.flows_dos FINAL")
    time.sleep(1)
    baseline = _count_final(ch_client, sid)
    assert baseline == n, f"baseline FINAL should be {n}, got {baseline}"

    # Re-process same segment 3 more times (simulating process_segment re-runs
    # on the same Kafka blob).
    for _ in range(3):
        sink.insert_family("dos", str(csv_path), meta)

    unmerged = _count_unmerged(ch_client, sid)
    assert unmerged == 4 * n, (
        f"unmerged count should reflect all 4 inserts: expected {4*n}, got {unmerged}"
    )

    ch_client.execute("OPTIMIZE TABLE network_ids.flows_dos FINAL")
    time.sleep(2)
    after = _count_final(ch_client, sid)

    assert after == baseline, (
        f"idempotency BROKEN: after 3 re-inserts + OPTIMIZE FINAL, "
        f"count went from {baseline} to {after} (delta {after-baseline}). "
        f"ReplacingMergeTree should have collapsed duplicates."
    )
