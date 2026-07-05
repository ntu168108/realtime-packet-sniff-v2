"""Unit tests for baseline_filter core engine."""
import json
from pathlib import Path

import pytest

from baseline_filter import load_signature


def test_load_signature_dos_returns_valid_dict():
    """load_signature('DoS') returns dict with class_name='DoS' and signature rules."""
    sig = load_signature("DoS")
    assert sig["class_name"] == "DoS"
    assert "keep_columns" in sig
    assert "signature" in sig
    assert "decisive" in sig["signature"]
    assert "support" in sig["signature"]
    assert len(sig["signature"]["decisive"]) > 0
    assert "scoring" in sig


def test_load_signature_filenames_are_lowercase():
    """load_signature accepts class name with capital letters (filenames are lowercase)."""
    # 'DoS' should match 'dos.json' via case-insensitive lookup
    sig = load_signature("DoS")
    assert sig["class_name"] == "DoS"


def test_load_signature_missing_raises():
    """load_signature for unknown class raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_signature("NonexistentClass")


def test_load_all_7_signatures():
    """All 7 wrapper-mapped classes can be loaded."""
    expected = ["DoS", "Generic", "Exploits", "Fuzzers", "Analysis", "Reconnaissance", "Shellcode"]
    for cls in expected:
        sig = load_signature(cls)
        assert sig["class_name"] == cls


def test_load_backdoors_and_worms():
    """Backdoors and Worms signatures are also loadable (extended coverage).

    Skipped when the corresponding JSON signatures are not present in the
    repo (the 7 family wrappers are wired up in auto_pipeline.py; Backdoors/
    Worms support exists in baseline_nb15_classifier.json but the per-class
    signature JSON files were not extracted from that source). When those
    files land, this test will run automatically.
    """
    import pytest
    from pathlib import Path
    sig_dir = Path(__file__).resolve().parent.parent / "signatures"
    have_backdoors = (sig_dir / "backdoors.json").is_file()
    have_worms = (sig_dir / "worms.json").is_file()
    if not (have_backdoors and have_worms):
        pytest.skip(
            "backdoors.json / worms.json signatures not yet extracted "
            "from baseline_nb15_classifier.json"
        )
    for cls in ["Backdoors", "Worms"]:
        sig = load_signature(cls)
        assert sig["class_name"] == cls
        assert len(sig["signature"]["decisive"]) > 0
        assert len(sig["signature"]["support"]) > 0


def test_load_all_9_signatures():
    """All 9 classes from baseline_nb15_classifier.json can be loaded.

    Skipped when Backdoors/Worms signatures are not yet extracted.
    """
    import pytest
    from pathlib import Path
    sig_dir = Path(__file__).resolve().parent.parent / "signatures"
    have_backdoors = (sig_dir / "backdoors.json").is_file()
    have_worms = (sig_dir / "worms.json").is_file()
    if not (have_backdoors and have_worms):
        pytest.skip(
            "backdoors.json / worms.json signatures not yet extracted "
            "from baseline_nb15_classifier.json"
        )
    expected = [
        "DoS", "Generic", "Exploits", "Fuzzers",
        "Analysis", "Reconnaissance", "Shellcode",
        "Backdoors", "Worms",
    ]
    for cls in expected:
        sig = load_signature(cls)
        assert sig["class_name"] == cls


def test_evaluate_rule_all_operators():
    """evaluate_rule handles >=, <=, >, <, == correctly."""
    from baseline_filter import evaluate_rule

    # >=
    assert evaluate_rule({"op": ">=", "threshold": 10}, 15) is True
    assert evaluate_rule({"op": ">=", "threshold": 10}, 10) is True
    assert evaluate_rule({"op": ">=", "threshold": 10}, 5) is False

    # <=
    assert evaluate_rule({"op": "<=", "threshold": 10}, 5) is True
    assert evaluate_rule({"op": "<=", "threshold": 10}, 10) is True
    assert evaluate_rule({"op": "<=", "threshold": 10}, 15) is False

    # >
    assert evaluate_rule({"op": ">", "threshold": 10}, 15) is True
    assert evaluate_rule({"op": ">", "threshold": 10}, 10) is False

    # <
    assert evaluate_rule({"op": "<", "threshold": 10}, 5) is True
    assert evaluate_rule({"op": "<", "threshold": 10}, 10) is False

    # ==
    assert evaluate_rule({"op": "==", "threshold": 5}, 5) is True
    assert evaluate_rule({"op": "==", "threshold": 5}, 4) is False


def test_evaluate_rule_unknown_op_raises():
    """Unknown op raises ValueError."""
    from baseline_filter import evaluate_rule
    with pytest.raises(ValueError):
        evaluate_rule({"op": "!=", "threshold": 10}, 5)


def test_score_adds_columns():
    """score() adds <class>_score and predicted_class columns."""
    import pandas as pd
    from baseline_filter import score, load_signature

    sig = load_signature("DoS")
    df = pd.DataFrame({
        "sttl": [254, 31],
        "dttl": [0, 29],
        "ct_state_ttl": [5, 0],
        "swin": [0, 255],
        "sload": [80000000.0, 559000.0],
        "rate": [200000.0, 3461.0],
        "sloss": [0, 4],
        "dpkts": [0, 18],
        "sbytes": [200, 1684],
        "smean": [100, 73],
        "ct_flw_http_mthd": [1, 0],
        "dloss": [0, 5],
        "proto": ["tcp", "tcp"],
        "state": ["INT", "FIN"],
        "service": ["-", "https"],
    })

    result = score(df, sig)

    assert "dos_score" in result.columns
    assert "predicted_class" in result.columns
    assert len(result) == 2
    assert result.iloc[0]["dos_score"] > 0
    assert result.iloc[0]["predicted_class"] == "DoS"
    assert result.iloc[1]["dos_score"] == 0
    assert result.iloc[1]["predicted_class"] == "Normal"


def test_score_below_min_decisive_returns_zero():
    """If row hits < min_decisive_required decisive rules, score=0."""
    import pandas as pd
    from baseline_filter import score, load_signature

    sig = load_signature("DoS")
    df = pd.DataFrame({
        "sttl": [254],
        "dttl": [29],
        "ct_state_ttl": [0],
        "swin": [255],
        "sload": [559000.0],
        "rate": [3461.0],
        "sloss": [0],
        "dpkts": [18],
        "sbytes": [1684],
        "smean": [73],
        "ct_flw_http_mthd": [0],
        "dloss": [5],
    })

    result = score(df, sig)
    assert result.iloc[0]["dos_score"] == 0
    assert result.iloc[0]["predicted_class"] == "Normal"


def test_score_skips_missing_features():
    """score() gracefully skips rules whose feature is missing from DataFrame."""
    import pandas as pd
    from baseline_filter import score, load_signature

    sig = load_signature("DoS")
    df = pd.DataFrame({
        "sttl": [254, 254],
        "dttl": [0, 0],
        "ct_state_ttl": [5, 5],
        "swin": [0, 0],
        # sload missing
        "rate": [200000.0, 200000.0],
        "sloss": [0, 0],
        "dpkts": [0, 0],
        "sbytes": [200, 200],
        "smean": [100, 100],
        "ct_flw_http_mthd": [1, 1],
        "dloss": [0, 0],
    })

    result = score(df, sig)
    assert "dos_score" in result.columns
    assert result.iloc[0]["predicted_class"] == "DoS"


def test_filter_columns_keeps_only_listed():
    """filter_columns drops columns not in keep_columns."""
    import pandas as pd
    from baseline_filter import filter_columns

    df = pd.DataFrame({
        "sttl": [1, 2],
        "dttl": [3, 4],
        "noise_col": [5, 6],
    })
    result = filter_columns(df, ["sttl", "dttl"])
    assert list(result.columns) == ["sttl", "dttl"]


def test_filter_columns_case_insensitive():
    """filter_columns matches case-insensitively (CSV often lowercase)."""
    import pandas as pd
    from baseline_filter import filter_columns

    df = pd.DataFrame({"STTL": [1], "dttl": [2]})
    result = filter_columns(df, ["sttl", "dttl"])
    assert set(result.columns) == {"STTL", "dttl"}


def test_filter_columns_missing_skipped():
    """filter_columns skips columns not in df, doesn't crash."""
    import pandas as pd
    from baseline_filter import filter_columns

    df = pd.DataFrame({"sttl": [1]})
    result = filter_columns(df, ["sttl", "missing_feature"])
    assert list(result.columns) == ["sttl"]


def test_filter_columns_preserves_order_from_keep_list():
    """filter_columns returns columns in the order they appear in keep_columns."""
    import pandas as pd
    from baseline_filter import filter_columns

    df = pd.DataFrame({"a": [1], "b": [2], "c": [3]})
    result = filter_columns(df, ["c", "a", "b"])
    # Order should follow keep_columns, not df
    assert list(result.columns) == ["c", "a", "b"]


def test_filter_columns_empty_keep_returns_empty():
    """filter_columns with empty keep list returns empty DataFrame (same rows)."""
    import pandas as pd
    from baseline_filter import filter_columns

    df = pd.DataFrame({"a": [1, 2], "b": [3, 4]})
    result = filter_columns(df, [])
    assert list(result.columns) == []
    assert len(result) == 2


def test_normalize_categoricals_strip_lowercase():
    """normalize_categoricals: strip whitespace + lowercase."""
    import pandas as pd
    from baseline_filter import normalize_categoricals

    df = pd.DataFrame({
        "proto": [" TCP ", "udp", "ARP"],
        "state": ["FIN", "INT ", "con"],
    })
    result = normalize_categoricals(df, ["proto", "state"])
    assert result["proto"].tolist() == ["tcp", "udp", "arp"]
    assert result["state"].tolist() == ["fin", "int", "con"]


def test_normalize_categoricals_missing_column_ok():
    """normalize_categoricals: missing column skipped without error."""
    import pandas as pd
    from baseline_filter import normalize_categoricals

    df = pd.DataFrame({"proto": ["TCP"]})
    result = normalize_categoricals(df, ["proto", "service"])
    assert result["proto"].tolist() == ["tcp"]


def test_downcast_integers_int16_when_possible():
    """downcast_integers: int64 → int16 when range fits."""
    import numpy as np
    import pandas as pd
    from baseline_filter import downcast_integers

    df = pd.DataFrame({"sport": pd.array([80, 443, 8080], dtype="int64")})
    result = downcast_integers(df, ["sport"])
    assert result["sport"].dtype == np.int16


def test_downcast_integers_keeps_int64_for_large():
    """downcast_integers: keep int64 if range exceeds int32."""
    import numpy as np
    import pandas as pd
    from baseline_filter import downcast_integers

    df = pd.DataFrame({"sport": pd.array([80, 443, 5_000_000_000], dtype="int64")})
    result = downcast_integers(df, ["sport"])
    assert result["sport"].dtype == np.int64


def test_downcast_integers_skip_nan_column():
    """downcast_integers: skip columns with NaN."""
    import pandas as pd
    from baseline_filter import downcast_integers

    df = pd.DataFrame({"sport": pd.array([80, None, 443], dtype="Int64")})
    result = downcast_integers(df, ["sport"])
    # Should not crash; dtype may stay Int64 or float
    assert len(result) == 3


def test_copy_http_log_creates_destination(tmp_path):
    """copy_http_log: copies <base>_http.log from input to output."""
    import shutil
    from baseline_filter import copy_http_log

    in_dir = tmp_path / "in"
    out_dir = tmp_path / "out"
    in_dir.mkdir()
    out_dir.mkdir()
    src = in_dir / "test_http.log"
    src.write_text("# some http log content")

    copy_http_log(in_dir, out_dir, "test")

    dest = out_dir / "test_http.log"
    assert dest.exists()
    assert dest.read_text() == "# some http log content"


def test_copy_http_log_no_source_ok(tmp_path):
    """copy_http_log: missing source file is silent no-op."""
    from baseline_filter import copy_http_log

    in_dir = tmp_path / "in"
    out_dir = tmp_path / "out"
    in_dir.mkdir()
    out_dir.mkdir()

    # Should not crash
    copy_http_log(in_dir, out_dir, "test")
    assert not (out_dir / "test_http.log").exists()


def test_run_end_to_end(tmp_path):
    """run() reads CSV, scores, writes output CSV."""
    import shutil
    from baseline_filter import run

    src = Path("MODULE_PHANLOAI/tests/fixtures/sample_dos_features.csv")
    in_csv = tmp_path / "sample.csv"
    shutil.copy(src, in_csv)
    out_csv = tmp_path / "out.csv"

    result_df = run("DoS", str(in_csv), str(out_csv))

    assert out_csv.is_file()
    assert "dos_score" in result_df.columns
    assert "predicted_class" in result_df.columns
    dos_count = (result_df["predicted_class"] == "DoS").sum()
    normal_count = (result_df["predicted_class"] == "Normal").sum()
    assert dos_count > 0, "Should classify some DoS rows"
    assert normal_count > 0, "Should classify some Normal rows"


def test_run_output_path_default(tmp_path):
    """run() auto-derives output path if output_path=None."""
    import shutil
    from baseline_filter import run

    src = Path("MODULE_PHANLOAI/tests/fixtures/sample_dos_features.csv")
    in_csv = tmp_path / "sample.csv"
    shutil.copy(src, in_csv)

    # No output_path → should auto-create sample_dos_features.csv next to input
    run("DoS", str(in_csv))

    expected = in_csv.parent / "sample_dos_features.csv"
    assert expected.is_file()


def test_run_invalid_class_raises(tmp_path):
    """run() with invalid class_name raises FileNotFoundError."""
    from baseline_filter import run
    import shutil

    src = Path("MODULE_PHANLOAI/tests/fixtures/sample_dos_features.csv")
    in_csv = tmp_path / "sample.csv"
    shutil.copy(src, in_csv)

    with pytest.raises(FileNotFoundError):
        run("InvalidClass", str(in_csv))


def test_run_missing_input_raises():
    """run() with missing input file raises FileNotFoundError."""
    from baseline_filter import run

    with pytest.raises(FileNotFoundError):
        run("DoS", "/tmp/does_not_exist.csv")


def test_run_copies_http_log(tmp_path):
    """run() copies <base>_http.log from input_dir to output_dir."""
    import shutil
    from baseline_filter import run

    src = Path("MODULE_PHANLOAI/tests/fixtures/sample_dos_features.csv")
    in_csv = tmp_path / "sample.csv"
    shutil.copy(src, in_csv)
    # Create a fake http log next to input
    (tmp_path / "sample_http.log").write_text("# http log data")

    out_csv = tmp_path / "out.csv"
    run("DoS", str(in_csv), str(out_csv))

    copied = tmp_path / "sample_http.log"
    assert copied.exists()
    assert copied.read_text() == "# http log data"
