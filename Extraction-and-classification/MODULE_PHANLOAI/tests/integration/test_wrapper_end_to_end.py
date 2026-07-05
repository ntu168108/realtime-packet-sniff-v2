"""Integration tests: full wrapper CLI invocations."""
import shutil
import subprocess
import sys
from pathlib import Path

import pandas as pd

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "sample_dos_features.csv"
PHANLOAI_DIR = Path(__file__).resolve().parent.parent.parent

WRAPPERS = [
    ("DoS", "dos"),
    ("Generic", "generic"),
    ("Exploits", "exploits"),
    ("Fuzzers", "fuzzers"),
    ("Analysis", "analysis"),
    ("Reconnaissance", "reconnaissance"),
    ("Shellcode", "shellcode"),
]


def _run_wrapper(class_name: str, lower: str, in_csv: Path, out_csv: Path) -> subprocess.CompletedProcess:
    """Invoke <lower>_feature_filter.py via subprocess."""
    wrapper = PHANLOAI_DIR / f"{lower}_feature_filter.py"
    return subprocess.run(
        [sys.executable, str(wrapper), str(in_csv), "-o", str(out_csv)],
        capture_output=True,
        text=True,
        cwd=str(PHANLOAI_DIR.parent),
    )


def test_dos_wrapper_end_to_end(tmp_path):
    """dos_feature_filter.py runs successfully on fixture."""
    # Copy fixture to tmp_path with a different name so wrapper doesn't skip it
    in_csv = tmp_path / "input.csv"
    shutil.copy(FIXTURE, in_csv)
    out_csv = tmp_path / "out.csv"

    result = _run_wrapper("DoS", "dos", in_csv, out_csv)

    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert out_csv.is_file()

    df = pd.read_csv(out_csv)
    assert "dos_score" in df.columns
    assert "predicted_class" in df.columns


def test_generic_wrapper_end_to_end(tmp_path):
    """generic_feature_filter.py runs on fixture."""
    in_csv = tmp_path / "input.csv"
    shutil.copy(FIXTURE, in_csv)
    out_csv = tmp_path / "out.csv"

    result = _run_wrapper("Generic", "generic", in_csv, out_csv)

    assert result.returncode == 0, f"stderr={result.stderr}"
    assert out_csv.is_file()

    df = pd.read_csv(out_csv)
    assert "generic_score" in df.columns
    assert "predicted_class" in df.columns


def test_all_wrappers_smoke_test(tmp_path):
    """All wrappers (currently 9) run without errors on fixture."""
    assert len(WRAPPERS) >= 7, "Expected at least 7 wrappers (Backdoors/Worms added later)"
    for cls, lower in WRAPPERS:
        in_csv = tmp_path / f"in_{lower}.csv"
        shutil.copy(FIXTURE, in_csv)
        out_csv = tmp_path / f"out_{lower}.csv"

        result = _run_wrapper(cls, lower, in_csv, out_csv)

        assert result.returncode == 0, f"{cls} failed: {result.stderr}"
        assert out_csv.is_file(), f"{cls} did not produce output"

        df = pd.read_csv(out_csv)
        assert f"{lower}_score" in df.columns, f"{cls} missing {lower}_score column"
        assert "predicted_class" in df.columns, f"{cls} missing predicted_class"


def test_wrapper_with_directory_input(tmp_path):
    """Wrapper processes directory of CSVs (batch mode)."""
    in_dir = tmp_path / "in"
    out_dir = tmp_path / "out"
    in_dir.mkdir()

    # Create 2 fake CSV files (copies of fixture with different names)
    shutil.copy(FIXTURE, in_dir / "sample1.csv")
    shutil.copy(FIXTURE, in_dir / "sample2.csv")

    result = _run_wrapper("DoS", "dos", in_dir, out_dir)

    assert result.returncode == 0, f"stderr={result.stderr}"
    # Should produce 2 output files
    assert (out_dir / "sample1_dos_features.csv").is_file()
    assert (out_dir / "sample2_dos_features.csv").is_file()


def test_wrapper_help_works(tmp_path):
    """Wrapper --help exits 0 and shows description."""
    wrapper = PHANLOAI_DIR / "dos_feature_filter.py"
    result = subprocess.run(
        [sys.executable, str(wrapper), "--help"],
        capture_output=True,
        text=True,
        cwd=str(PHANLOAI_DIR.parent),
    )
    assert result.returncode == 0
    assert "Filter + classify DoS attacks" in result.stdout
