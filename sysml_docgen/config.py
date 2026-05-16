"""Runtime configuration for the SysML DocGen service."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
OUTPUT_DIR = Path(os.environ.get("SYSML_OUTPUT_DIR", ROOT / "outputs"))
STATIC_DIR = ROOT / "static"
FRONTEND_DIST_DIR = Path(os.environ.get("SYSML_FRONTEND_DIST", ROOT / "frontend" / "dist"))
MAX_MODEL_BYTES = int(os.environ.get("SYSML_MAX_MODEL_BYTES", str(10 * 1024 * 1024)))

def find_executable(name: str, env_var: str, extra_paths: list[Path]) -> str:
    env_path = os.environ.get(env_var, "").strip()
    if env_path:
        return env_path
    found = shutil.which(name)
    if found:
        return found
    for path in extra_paths:
        if path.exists():
            return str(path)
    return ""


PANDOC_PATH = find_executable("pandoc", "SYSML_PANDOC_PATH", [])
QUARTO_PATH = find_executable(
    "quarto",
    "SYSML_QUARTO_PATH",
    [
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Quarto" / "bin" / "quarto.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Quarto" / "bin" / "quarto.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Quarto" / "bin" / "quarto.exe",
    ],
)


def default_pdf_engine() -> str:
    if QUARTO_PATH:
        return "quarto"
    if PANDOC_PATH:
        return "pandoc"
    if shutil.which("wkhtmltopdf"):
        return "wkhtmltopdf"
    return "builtin-fallback"


PDF_ENGINE = os.environ.get("SYSML_PDF_ENGINE") or default_pdf_engine()
DOCX_REFERENCE = os.environ.get("SYSML_DOCX_REFERENCE", "")

# ── Themes ──────────────────────────────────────────────────────────

THEME_PRESETS: dict[str, dict[str, str]] = {
    "default": {
        "label": "默认浅色",
        "bg": "#ffffff",
        "fg": "#1e293b",
        "muted": "#64748b",
        "border": "#e2e8f0",
        "accent": "#0f766e",
        "accent-fg": "#f0fdfa",
        "heading": "#0f172a",
        "code-bg": "#f1f5f9",
        "table-stripe": "#f8fafc",
        "table-header-bg": "#f0fdfa",
        "table-header-fg": "#134e4a",
        "link": "#0f766e",
        "page-bg": "#f1f5f9",
    },
    "dark": {
        "label": "深色",
        "bg": "#0f172a",
        "fg": "#e2e8f0",
        "muted": "#94a3b8",
        "border": "#334155",
        "accent": "#5eead4",
        "accent-fg": "#134e4a",
        "heading": "#f1f5f9",
        "code-bg": "#1e293b",
        "table-stripe": "#1e293b",
        "table-header-bg": "#134e4a",
        "table-header-fg": "#ccfbf1",
        "link": "#5eead4",
        "page-bg": "#020617",
    },
    "ink": {
        "label": "水墨",
        "bg": "#faf9f6",
        "fg": "#292524",
        "muted": "#78716c",
        "border": "#d6d3d1",
        "accent": "#44403c",
        "accent-fg": "#f5f5f4",
        "heading": "#1c1917",
        "code-bg": "#f5f5f4",
        "table-stripe": "#f5f5f4",
        "table-header-bg": "#e7e5e4",
        "table-header-fg": "#1c1917",
        "link": "#78716c",
        "page-bg": "#f5f5f4",
    },
    "ocean": {
        "label": "海洋蓝",
        "bg": "#ffffff",
        "fg": "#1e3a5f",
        "muted": "#5b7a9a",
        "border": "#d0dde8",
        "accent": "#1e6fa0",
        "accent-fg": "#e8f4fd",
        "heading": "#0c4a6e",
        "code-bg": "#f0f6fc",
        "table-stripe": "#f7fafd",
        "table-header-bg": "#e0f0fa",
        "table-header-fg": "#0c4a6e",
        "link": "#1e6fa0",
        "page-bg": "#eef4f8",
    },
    "forest": {
        "label": "森林绿",
        "bg": "#ffffff",
        "fg": "#1a2e1a",
        "muted": "#5c7a5c",
        "border": "#c8d8c8",
        "accent": "#2d6a4f",
        "accent-fg": "#d8f3dc",
        "heading": "#1b4332",
        "code-bg": "#f0f7f0",
        "table-stripe": "#f6faf6",
        "table-header-bg": "#d8f3dc",
        "table-header-fg": "#1b4332",
        "link": "#2d6a4f",
        "page-bg": "#eef5ee",
    },
}

DEFAULT_THEME = os.environ.get("SYSML_THEME", "default")

# ── Fonts ───────────────────────────────────────────────────────────

FONT_PRESETS: dict[str, dict[str, str]] = {
    "system": {"label": "系统默认", "family": '"Segoe UI", "Microsoft YaHei", system-ui, -apple-system, sans-serif'},
    "yahei": {"label": "微软雅黑", "family": '"Microsoft YaHei", "微软雅黑", sans-serif'},
    "song": {"label": "宋体", "family": '"SimSun", "宋体", "Noto Serif CJK SC", serif'},
    "hei": {"label": "黑体", "family": '"SimHei", "黑体", "Noto Sans CJK SC", sans-serif'},
    "kai": {"label": "楷体", "family": '"KaiTi", "楷体", "Noto Sans CJK SC", serif'},
    "mono": {"label": "等宽编程", "family": '"Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace'},
    "helvetica": {"label": "Helvetica (英文)", "family": '"Helvetica Neue", Helvetica, Arial, sans-serif'},
}

DEFAULT_FONT = os.environ.get("SYSML_FONT", "system")


def discover_system_fonts() -> dict[str, str]:
    """Return CJK-capable fonts found on the system."""
    found: dict[str, str] = {}
    font_dirs = []
    if os.name == "nt":
        font_dirs = [Path(os.environ.get("WINDIR", "C:\\Windows")) / "Fonts"]
    else:
        font_dirs = [
            Path("/usr/share/fonts"),
            Path("/usr/local/share/fonts"),
            Path.home() / ".fonts",
        ]
    cjk_checks = {
        "Microsoft YaHei": "msyh.ttc",
        "SimSun": "simsun.ttc",
        "SimHei": "simhei.ttf",
        "KaiTi": "kaiti.ttf",
        "Noto Sans CJK SC": "NotoSansCJKsc-Regular.otf",
        "Noto Serif CJK SC": "NotoSerifCJKsc-Regular.otf",
    }
    for fd in font_dirs:
        if not fd.exists():
            continue
        for name, filename in cjk_checks.items():
            if name in found:
                continue
            for path in fd.rglob(filename):
                found[name] = str(path)
                break
    return found


SYSTEM_CJK_FONTS = discover_system_fonts()
