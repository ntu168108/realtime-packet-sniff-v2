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

import pandas as pd
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
    # Thư viện có mặt KHÔNG có nghĩa là có server: trên CI runner không chạy
    # ClickHouse thì `Client(...)` vẫn tạo được nhưng truy vấn đầu tiên mới nổ.
    # Kiểm tra kết nối ở đây để test SKIP gọn thay vì ERROR — nhờ đó không cần
    # `--ignore` cả file trong workflow.
    try:
        client.execute("SELECT 1")
    except Exception as exc:  # noqa: BLE001 - mọi lỗi kết nối/DB đều là "không có server"
        client.disconnect()
        pytest.skip(f"ClickHouse không truy cập được tại localhost:9000 ({exc})")
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
    """Sinh CSV dos_features tổng hợp cho phép thử idempotency.

    Các dòng phải TRÔNG NHƯ FLOW THẬT, nếu không `ClickHouseSink` loại sạch
    chúng ở guard `_is_placeholder_row()` và test đo idempotency trên 0 dòng.
    Cụ thể phải tránh HAI chữ ký "flow giả" mà guard bắt (xem
    `test_sink_rejects_placeholder_fake_flows`):

      1. `src_mac` = broadcast/all-zero (`ff:ff:..` / `00:00:..`);
      2. TOÀN BỘ cột volume (`spkts/dpkts/sbytes/dbytes/dur`) = 0.

    Ghi theo DICT thay vì danh sách positional: bản trước dùng 51 giá trị
    positional nhưng chỉ cấp 49, nên hai chuỗi MAC âm thầm rơi vào
    `ct_flw_http_mthd`/`ct_ftp_cmd`, còn `src_mac`/`dst_mac`/`predicted_class`
    thì sai/thiếu hẳn. Khoá theo tên cột làm lỗi lệch cột đó không thể tái diễn.
    """
    base = {c: 0 for c in SCHEMA_HEADER}
    base.update({
        "dstip": "10.0.0.9", "dport": 53, "proto": "udp",
        "service": "dns", "state": "CON",
        "sttl": 64, "dttl": 64,
        # Volume KHÁC 0 -> không khớp chữ ký "flow rỗng" của guard.
        "dur": 0.002, "spkts": 2, "dpkts": 2,
        "sbytes": 140, "dbytes": 180, "smean": 70, "dmean": 90,
        "rate": 1000.0,
        # MAC nguồn/đích hợp lệ -> không khớp chữ ký broadcast của guard.
        "src_mac": "bc:24:11:f2:84:5b", "dst_mac": "bc:24:11:d1:2a:a1",
        "predicted_class": "Normal",
    })
    with open(path, "w", newline="") as f:
        w = csvmod.writer(f)
        w.writerow(SCHEMA_HEADER)
        for i in range(n):
            row = dict(base)
            # 5-tuple duy nhất theo sport, và ltime > 0 với offset dưới giây
            # riêng biệt -> mỗi dòng một ts DateTime64(3) duy nhất. Cả hai đều
            # cần thiết: khoá dedup của ReplacingMergeTree là
            # (segment_id, srcip, dstip, sport, dport, proto, ts).
            row["srcip"] = f"10.0.0.{(i % 253) + 1}"
            row["sport"] = 1000 + i
            row["ltime"] = t_start + i * 0.001
            w.writerow([row[c] for c in SCHEMA_HEADER])


def _count_final(ch_client, sid: str) -> int:
    return int(ch_client.execute(
        "SELECT count() FROM network_ids.flows_dos FINAL WHERE segment_id=%(s)s",
        {"s": sid})[0][0])


def _count_unmerged(ch_client, sid: str) -> int:
    return int(ch_client.execute(
        "SELECT count() FROM network_ids.flows_dos WHERE segment_id=%(s)s",
        {"s": sid})[0][0])


def test_fixture_rows_are_not_rejected_by_sink_guard(tmp_path):
    """Bảo vệ chính fixture: mọi dòng phải qua được guard, và không lệch cột.

    Đây là thứ đã làm test idempotency fail âm thầm: fixture sinh flow có volume
    toàn 0 nên `_is_placeholder_row()` loại sạch 200/200 dòng, và phép đo
    idempotency chạy trên 0 dòng. Test này fail NGAY tại fixture thay vì để lỗi
    lộ ra dưới dạng "baseline should be 200, got 0" ở test dưới.
    """
    import csv as _csv

    from integration.clickhouse_sink import _is_placeholder_row

    path = tmp_path / "guardcheck_dos_features.csv"
    _make_csv(path, 5, time.time())
    rows = list(_csv.DictReader(open(path)))

    assert len(rows) == 5
    for i, row in enumerate(rows):
        # Không lệch cột: mọi cột trong header phải có giá trị (DictReader gán
        # None cho cột thiếu khi dòng ngắn hơn header).
        missing = [k for k, v in row.items() if v is None]
        assert not missing, f"dòng {i} thiếu giá trị cho cột: {missing}"
        assert row["src_mac"] == "bc:24:11:f2:84:5b"
        assert row["predicted_class"] == "Normal"
        assert not _is_placeholder_row(pd.Series(row)), \
            f"dòng {i} bị guard coi là flow giả -> test idempotency sẽ đo trên 0 dòng"

    # ts phải duy nhất từng dòng, nếu không ReplacingMergeTree gộp mất dòng và
    # baseline < n vì lý do KHÁC (không phải guard).
    assert len({r["ltime"] for r in rows}) == 5
    assert len({r["sport"] for r in rows}) == 5


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
