"""conftest for sniff-web backend tests.

Adds sniff-web/ to sys.path so `from web_server import ...` works when pytest
is invoked from the repo root. Task 4 will introduce sniff-web/__init__.py
and a proper sniff_web.web_server package; this conftest is the bridge until
then.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SNIFF_WEB_DIR = os.path.abspath(os.path.join(_HERE, "..", ".."))

if _SNIFF_WEB_DIR not in sys.path:
    sys.path.insert(0, _SNIFF_WEB_DIR)
