"""Runtime configuration for the SysML DocGen service."""

from __future__ import annotations

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
OUTPUT_DIR = Path(os.environ.get("SYSML_OUTPUT_DIR", ROOT / "outputs"))
STATIC_DIR = ROOT / "static"
FRONTEND_DIST_DIR = Path(os.environ.get("SYSML_FRONTEND_DIST", ROOT / "frontend" / "dist"))
MAX_MODEL_BYTES = int(os.environ.get("SYSML_MAX_MODEL_BYTES", str(10 * 1024 * 1024)))
