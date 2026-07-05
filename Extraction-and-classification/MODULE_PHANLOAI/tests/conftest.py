"""Pytest config: add MODULE_PHANLOAI to sys.path."""
import sys
from pathlib import Path

_PHANLOAI_DIR = Path(__file__).resolve().parent.parent
if str(_PHANLOAI_DIR) not in sys.path:
    sys.path.insert(0, str(_PHANLOAI_DIR))
