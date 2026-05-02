from __future__ import annotations

import sys
from pathlib import Path


SRC_DIRECTORY = Path(__file__).resolve().parent / "src"
if SRC_DIRECTORY.exists():
    src_path = str(SRC_DIRECTORY)
    if src_path not in sys.path:
        sys.path.insert(0, src_path)