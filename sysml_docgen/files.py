"""File lifecycle helpers for generated DocGen artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import OUTPUT_DIR


ALLOWED_SUFFIXES = {".html", ".md", ".pdf", ".docx"}


def list_output_files(output_dir: Path = OUTPUT_DIR) -> list[dict[str, Any]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    files = []
    for path in sorted(output_dir.iterdir(), key=lambda item: item.stat().st_mtime, reverse=True):
        if not path.is_file() or path.suffix.lower() not in ALLOWED_SUFFIXES:
            continue
        stat = path.stat()
        files.append(
            {
                "name": path.name,
                "path": str(path),
                "format": path.suffix.lstrip("."),
                "bytes": stat.st_size,
                "updated_at": stat.st_mtime,
            }
        )
    return files


def resolve_output_file(filename: str, output_dir: Path = OUTPUT_DIR) -> Path:
    path = (output_dir / filename).resolve()
    root = output_dir.resolve()
    if root not in path.parents or path.suffix.lower() not in ALLOWED_SUFFIXES or not path.exists():
        raise FileNotFoundError(filename)
    return path


def delete_output_file(filename: str, output_dir: Path = OUTPUT_DIR) -> None:
    resolve_output_file(filename, output_dir).unlink()
