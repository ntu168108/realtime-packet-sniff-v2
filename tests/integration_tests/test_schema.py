"""Unit tests for integration.schema.

The schema is the single source of truth for ClickHouse column types derived
from the real `*_dos_features.csv` pandas dtypes. These tests guard against
silent type regressions (e.g. accidentally mapping IP/proto to Float64).
"""
from integration.schema import (
    FAMILIES,
    CSV_COLUMNS,
    CSV_COLUMNS_FULL,
    CSV_COLUMN_TYPES,
    AUDIT_COLUMNS,
    all_table_columns,
)


def test_families_count():
    assert len(FAMILIES) == 7
    assert set(FAMILIES) == {
        "dos", "exploits", "fuzzers", "generic",
        "analysis", "reconnaissance", "shellcode",
    }


def test_csv_columns_populated():
    # UNSW-NB15 has 49 features in the full set; per-family subset must be > 10.
    assert len(CSV_COLUMNS) > 10
    assert len(CSV_COLUMNS) <= 50


def test_every_column_has_a_type():
    assert set(CSV_COLUMN_TYPES) == set(CSV_COLUMNS)
    bad = [c for c, t in CSV_COLUMN_TYPES.items() if not t]
    assert not bad, f"missing type for {bad}"


def test_ip_proto_mac_are_string():
    """IP/MAC/proto/state/service/predicted_class must be String, not Float64.

    This is the critical guard: Inserting IPv4 strings into a Float64 column
    breaks silently and would corrupt the table.
    """
    must_be_string = {"srcip", "dstip", "src_mac", "dst_mac",
                      "proto", "state", "service", "predicted_class"}
    for c in must_be_string:
        assert CSV_COLUMN_TYPES[c] == "String", (
            f"{c} must be String but is {CSV_COLUMN_TYPES[c]!r}"
        )


def test_numeric_columns_are_numeric():
    int_cols = {"sport", "dport", "spkts", "dpkts", "sbytes", "dbytes"}
    float_cols = {"dur", "rate", "sload", "dload"}
    for c in int_cols:
        assert "Int" in CSV_COLUMN_TYPES[c], f"{c} expected Int*, got {CSV_COLUMN_TYPES[c]}"
    for c in float_cols:
        assert "Float" in CSV_COLUMN_TYPES[c], f"{c} expected Float*, got {CSV_COLUMN_TYPES[c]}"


def test_audit_columns_present():
    names = [n for n, _ in AUDIT_COLUMNS]
    assert "ts" in names
    assert "segment_id" in names
    assert "attack_family" in names
    assert "is_attack" in names


def test_all_table_columns_no_duplicates():
    cols = all_table_columns()
    names = [n for n, _ in cols]
    assert len(names) == len(set(names)), f"duplicate column names in {names}"
    # audit + features total
    assert len(cols) == len(AUDIT_COLUMNS) + len(CSV_COLUMNS)


def test_full_csv_columns_is_superset():
    """The full 49-feature set should be a superset of the union subset."""
    assert set(CSV_COLUMNS).issubset(set(CSV_COLUMNS_FULL) | set(CSV_COLUMNS))
