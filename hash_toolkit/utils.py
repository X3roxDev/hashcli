"""Shared utility functions."""

from __future__ import annotations

import datetime as dt
import logging
import os
import platform
from pathlib import Path


def setup_logging(level: int = logging.INFO) -> None:
    """Configure application logging once."""

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""

    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_for_filename() -> str:
    """Return a local timestamp suitable for export filenames."""

    return dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")


def stat_modified_iso(path: Path) -> str:
    """Return a file modification timestamp in local ISO format."""

    return dt.datetime.fromtimestamp(path.stat().st_mtime).replace(microsecond=0).isoformat()


def format_bytes(size: int) -> str:
    """Format a byte count using binary units."""

    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if value < 1024 or unit == "PB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def format_speed(bytes_per_second: float) -> str:
    """Format a throughput value."""

    return f"{format_bytes(int(bytes_per_second))}/s" if bytes_per_second > 0 else "0 B/s"


def normalize_relative_path(path: Path) -> str:
    """Normalize a relative path for deterministic manifests and folder hashes."""

    return path.as_posix()


def is_hidden(path: Path) -> bool:
    """Return whether a path appears hidden on the current platform."""

    if any(part.startswith(".") for part in path.parts if part not in (".", "..")):
        return True
    if platform.system() != "Windows":
        return False
    try:
        import ctypes

        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        return attrs != -1 and bool(attrs & 2)
    except Exception:
        return False


def safe_manifest_path(base: Path, manifest_name: str) -> Path:
    """Resolve a manifest entry path while preventing path traversal."""

    candidate = (base / manifest_name).resolve()
    base_resolved = base.resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError(f"Manifest path escapes root: {manifest_name}") from exc
    return candidate


def file_identity(path: Path) -> tuple[int, int] | None:
    """Return a stable-ish file identity for symlink-loop protection when available."""

    try:
        stat = path.stat()
    except OSError:
        return None
    inode = getattr(stat, "st_ino", 0)
    device = getattr(stat, "st_dev", 0)
    return (int(device), int(inode))


def platform_metadata() -> dict[str, str]:
    """Return operating system metadata for exports."""

    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "python": platform.python_version(),
    }


def parse_size_filter(value: str | None) -> int | None:
    """Parse file size filters such as 10MB or 2048."""

    if value is None:
        return None
    text = value.strip().lower()
    if not text:
        return None
    units = {"b": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}
    for suffix, multiplier in sorted(units.items(), key=lambda item: len(item[0]), reverse=True):
        if text.endswith(suffix):
            number = text[: -len(suffix)].strip()
            return int(float(number) * multiplier)
    return int(text)


def ensure_parent(path: Path) -> None:
    """Create a target file's parent directory when needed."""

    path.parent.mkdir(parents=True, exist_ok=True)


def is_broken_symlink(path: Path) -> bool:
    """Return whether a path is a symlink whose target cannot be resolved."""

    return path.is_symlink() and not path.exists()
