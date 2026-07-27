"""Streaming file hashing functions."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from .algorithms import create_hasher, parse_algorithms
from .config import DEFAULT_CHUNK_SIZE
from .models import HashResult
from .utils import stat_modified_iso

ProgressCallback = Callable[[int, int], None]


class FileChangedError(OSError):
    """Raised when a file changes during hashing."""


def hash_file(
    path: str | Path,
    *,
    algorithm: str | None = None,
    algorithms: str | list[str] | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: ProgressCallback | None = None,
    blake3_digest_length: int | None = None,
) -> list[HashResult]:
    """Hash a file with one streaming pass for all requested algorithms."""

    file_path = Path(path).expanduser()
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not file_path.is_file():
        raise IsADirectoryError(f"Not a file: {file_path}")

    selected = _coerce_algorithms(algorithm, algorithms)
    before = file_path.stat()
    hashers = {name: create_hasher(name, blake3_digest_length=blake3_digest_length) for name in selected}
    processed = 0
    started = time.perf_counter()

    with file_path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            processed += len(chunk)
            for hasher in hashers.values():
                hasher.update(chunk)
            if progress_callback:
                progress_callback(processed, before.st_size)

    duration = max(time.perf_counter() - started, 0.0)
    after = file_path.stat()
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise FileChangedError(f"File changed during hashing: {file_path}")

    speed = processed / duration if duration > 0 else float(processed)
    modified = stat_modified_iso(file_path)
    return [
        HashResult(
            source_type="file",
            name=file_path.name,
            path=str(file_path.resolve()),
            size=before.st_size,
            algorithm=name,
            hash_value=hasher.hexdigest(),
            duration_seconds=duration,
            speed_bytes_per_second=speed,
            modified_at=modified,
        )
        for name, hasher in hashers.items()
    ]


def hash_file_map(
    path: str | Path,
    *,
    algorithm: str | None = None,
    algorithms: str | list[str] | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    blake3_digest_length: int | None = None,
) -> dict[str, str]:
    """Hash a file and return an algorithm-to-hex mapping."""

    return {
        result.algorithm: result.hash_value
        for result in hash_file(
            path,
            algorithm=algorithm,
            algorithms=algorithms,
            chunk_size=chunk_size,
            blake3_digest_length=blake3_digest_length,
        )
    }


def _coerce_algorithms(algorithm: str | None, algorithms: str | list[str] | None) -> list[str]:
    if isinstance(algorithms, list):
        return parse_algorithms(algorithms=",".join(algorithms))
    if isinstance(algorithms, str):
        return parse_algorithms(algorithms=algorithms)
    return parse_algorithms(algorithm=algorithm)
