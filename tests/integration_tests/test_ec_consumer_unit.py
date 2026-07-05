"""Unit tests for integration.ec_consumer.process_segment.

process_segment(blob, runner, sink) -> dict:
    - parses blob -> pcap
    - writes pcap to /dev/shm/<segment_id>.pcap
    - calls runner(pcap_path) -> {family: csv_path}
    - calls sink.insert_family(family, csv_path, meta) per family
    - returns {"segment_id", "n_flows_by_family", "status"}
    - on any exception, returns status="failed" (does NOT raise)
    - removes the temp pcap at the end
"""
import os

from integration.pcap_segment import build_segment
from integration.ec_consumer import process_segment


def _blob(seg_id="S1", n_pkts=2):
    pkts = [(1000 + i, 0, b"x" * 10) for i in range(n_pkts)]
    meta = {"segment_id": seg_id, "interface": "ens33", "n_pkts": n_pkts}
    return build_segment(pkts, meta)


def test_process_segment_invokes_runner_and_sink(tmp_path, monkeypatch):
    # Redirect /dev/shm to tmp_path so we don't actually write to tmpfs.
    shm = tmp_path / "shm"
    shm.mkdir()
    # We can't redirect /dev/shm easily; use a segment_id we can control.
    blob = _blob(seg_id="UNITSEG1")
    calls = {"runner": [], "sink": []}

    def runner(pcap_path):
        calls["runner"].append(pcap_path)
        assert os.path.exists(pcap_path), f"temp pcap not written: {pcap_path}"
        return {"dos": "/tmp/dos.csv", "exploits": "/tmp/exploits.csv"}

    class Sink:
        def insert_family(self, fam, csv, meta):
            calls["sink"].append((fam, csv, meta["segment_id"]))
            return 7  # pretend we inserted 7 rows

    summ = process_segment(blob, runner, Sink())
    assert summ["segment_id"] == "UNITSEG1"
    assert summ["status"] == "success"
    assert summ["n_flows_by_family"] == {"dos": 7, "exploits": 7}
    assert calls["sink"] == [
        ("dos", "/tmp/dos.csv", "UNITSEG1"),
        ("exploits", "/tmp/exploits.csv", "UNITSEG1"),
    ]
    # temp pcap removed
    assert not os.path.exists("/dev/shm/UNITSEG1.pcap")


def test_process_segment_corrupt_blob_returns_failed_not_raises():
    """process_segment(b'garbage', ...) must return status='failed', not raise."""
    calls = {"runner": [], "sink": []}

    def runner(pcap_path):
        calls["runner"].append(pcap_path)
        return {}

    class Sink:
        def insert_family(self, fam, csv, meta):
            calls["sink"].append((fam, csv, meta["segment_id"]))

    summ = process_segment(b"\x00garbage\xff\xfe", runner, Sink())
    assert summ["status"] == "failed"
    # runner not invoked (parse failed first)
    assert calls["runner"] == []
    assert calls["sink"] == []


def test_process_segment_truncated_pcap_returns_failed_not_raises():
    """A blob whose pcap body is truncated mid-record must yield
    status='failed' (runner or sink raises); process_segment must not
    propagate the exception to the caller."""
    runs = []
    # Build a valid-looking segment then truncate the pcap body to 8 bytes —
    # shorter than the 24-byte pcap global header, so even Zeek/Argus can't
    # parse it.
    blob = _blob(seg_id="TRUNC-SEG-1")
    # Manually parse, truncate the pcap body, and re-pack.
    import struct as _s
    from integration.pcap_segment import build_segment, parse_segment
    meta, pcap_bytes = parse_segment(blob)
    truncated = pcap_bytes[:8]  # truncate mid-global-header
    header = b'{"segment_id":"TRUNC-SEG-1","interface":"ens33","n_pkts":1}'
    new_blob = _s.pack(">I", len(header)) + header + truncated

    def runner(pcap_path):
        # If we reach here, the runner will fail (or the file is too short).
        # Simulate downstream failure.
        raise RuntimeError("pcap too short for Argus/Zeek")

    class Sink:
        def insert_family(self, fam, csv, meta):
            return 0

        def insert_run(self, run):
            runs.append(run)

    summ = process_segment(new_blob, runner, Sink())
    assert summ["status"] == "failed"
    assert summ["segment_id"] == "TRUNC-SEG-1"
    # An audit run was still recorded with the failure details.
    assert len(runs) == 1
    assert runs[0]["status"] == "failed"
    assert runs[0]["error_msg"]  # non-empty
    # The temp pcap must have been removed even though processing failed.
    assert not os.path.exists("/dev/shm/TRUNC-SEG-1.pcap")


def test_process_segment_records_audit_run_on_success():
    """process_segment should call sink.insert_run exactly once per
    successful segment with the segment_id and status='success'."""
    blob = _blob(seg_id="AUDIT-SEG-1")
    runs = []

    def runner(pcap_path):
        return {"dos": "/tmp/dos.csv"}

    class Sink:
        def insert_family(self, fam, csv, meta):
            return 5

        def insert_run(self, run):
            runs.append(run)

    summ = process_segment(blob, runner, Sink())
    assert summ["status"] == "success"
    assert len(runs) == 1
    run = runs[0]
    assert run["segment_id"] == "AUDIT-SEG-1"
    assert run["status"] == "success"
    # dos family had 5 rows from insert_family
    assert run["dos"] == 5
    assert run["total_flows"] == 5
    # duration_sec is a positive float
    assert isinstance(run["duration_sec"], float)
    assert run["duration_sec"] >= 0


def test_process_segment_records_audit_run_on_failure():
    """process_segment on a parse failure must still call insert_run once
    with status='failed' and an error_msg; must not raise."""
    runs = []

    def runner(pcap_path):
        return {}

    class Sink:
        def insert_family(self, fam, csv, meta):
            return 0

        def insert_run(self, run):
            runs.append(run)

    summ = process_segment(b"\x00garbage", runner, Sink())
    assert summ["status"] == "failed"
    assert len(runs) == 1
    assert runs[0]["status"] == "failed"
    assert runs[0]["error_msg"]  # non-empty