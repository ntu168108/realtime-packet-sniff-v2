"""Test: MODULE_PHANLOAI/family_filter.py uses Path(__file__) not Windows path.

The 7 <family>_feature_filter.py scripts were consolidated into one
parameterized family_filter.py. Tests now check that one file is present
and uses portable paths.
"""
import os
import re

EC = os.environ.get(
    "NB15_EC",
    os.path.expanduser("~/sniff/Extraction-and-classification"),
)
_REPO_EC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "Extraction-and-classification")
)
if not os.path.isdir(EC):
    EC = _REPO_EC

FAMILY_FILTER = "family_filter.py"
FAMILY_CLASSES = [
    "Generic", "DoS", "Exploits", "Fuzzers",
    "Analysis", "Reconnaissance", "Shellcode",
]


def _read() -> str:
    with open(os.path.join(EC, "MODULE_PHANLOAI", FAMILY_FILTER),
              encoding="utf-8", errors="ignore") as f:
        return f.read()


def test_no_windows_paths_in_family_filter():
    src = _read()
    assert not re.search(r"r[\"']D:\\\\", src), "windows path còn trong family_filter.py"


def test_family_filter_uses_portable_paths():
    src = _read()
    assert "Path(__file__)" in src, "chưa dùng Path(__file__) trong family_filter.py"


def test_default_dirs_point_into_EC_repo():
    src = _read()
    assert "_project_root" in src or "_PROJECT_ROOT" in src, \
        "default_output_dir not portable"


def test_all_seven_filters_covered():
    """The single file must declare the 7 family classes as a CLI option."""
    assert os.path.isfile(os.path.join(EC, "MODULE_PHANLOAI", FAMILY_FILTER)), \
        f"missing {FAMILY_FILTER}"
    src = _read()
    for cls in FAMILY_CLASSES:
        assert cls in src, f"family {cls} not referenced in {FAMILY_FILTER}"