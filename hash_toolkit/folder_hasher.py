"""Folder scanning and deterministic folder hashing."""

from __future__ import annotations

import concurrent.futures
import os
import time
from pathlib import Path
from typing import Callable, Iterable

from .algorithms import create_hasher, parse_algorithms
from .config import DEFAULT_ALGORITHM, DEFAULT_CHUNK_SIZE, DEFAULT_WORKERS
from .file_hasher import hash_file_map
from .models import FolderFileResult, FolderScanResult
from .utils import file_identity, is_broken_symlink, is_hidden, normalize_relative_path, stat_modified_iso


def scan_folder(
    root: str | Path,
    *,
    algorithm: str | None = None,
    algorithms: str | list[str] | None = None,
    include_hidden: bool = False,
    follow_symlinks: bool = False,
    ignore_extensions: Iterable[str] | None = None,
    ignore_folders: Iterable[str] | None = None,
    min_size: int | None = None,
    max_size: int | None = None,
    workers: int = DEFAULT_WORKERS,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    sort_by: str = "path",
    blake3_digest_length: int | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> FolderScanResult:
    """Recursively scan a folder and hash all included files."""

    folder = Path(root).expanduser()
    if not folder.exists():
        raise FileNotFoundError(f"Folder not found: {folder}")
    if not folder.is_dir():
        raise NotADirectoryError(f"Not a folder: {folder}")

    selected = _coerce_algorithms(algorithm, algorithms)
    started = time.perf_counter()
    files = list(
        iter_scan_files(
            folder,
            include_hidden=include_hidden,
            follow_symlinks=follow_symlinks,
            ignore_extensions=ignore_extensions,
            ignore_folders=ignore_folders,
            min_size=min_size,
            max_size=max_size,
        )
    )

    results: list[FolderFileResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {
            executor.submit(
                _hash_folder_file,
                folder,
                file_path,
                selected,
                chunk_size,
                blake3_digest_length,
            ): file_path
            for file_path in files
        }
        try:
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
                if progress_callback:
                    progress_callback(len(results), len(files))
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            raise

    results = _sort_results(results, sort_by)
    folder_hash_algorithm = selected[0] if selected else DEFAULT_ALGORITHM
    folder_hash = calculate_folder_hash(results, folder_hash_algorithm, blake3_digest_length=blake3_digest_length)
    duration = max(time.perf_counter() - started, 0.0)
    errors = [f"{item.relative_path}: {item.error}" for item in results if item.error]
    return FolderScanResult(
        root=str(folder.resolve()),
        algorithms=selected,
        files=results,
        folder_hash_algorithm=folder_hash_algorithm,
        folder_hash=folder_hash,
        duration_seconds=duration,
        total_files=len(results),
        total_size=sum(item.size for item in results if item.status == "completed"),
        errors=errors,
    )


def iter_scan_files(
    root: Path,
    *,
    include_hidden: bool = False,
    follow_symlinks: bool = False,
    ignore_extensions: Iterable[str] | None = None,
    ignore_folders: Iterable[str] | None = None,
    min_size: int | None = None,
    max_size: int | None = None,
) -> Iterable[Path]:
    """Yield files matching folder scan filters."""

    ignored_extensions = {_normalize_extension(item) for item in (ignore_extensions or []) if item}
    ignored_folders = {item.lower() for item in (ignore_folders or []) if item}
    seen_dirs: set[tuple[int, int]] = set()

    for current, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        current_path = Path(current)
        identity = file_identity(current_path)
        if identity:
            if identity in seen_dirs:
                dirnames[:] = []
                continue
            seen_dirs.add(identity)

        kept_dirs: list[str] = []
        for dirname in dirnames:
            child = current_path / dirname
            if dirname.lower() in ignored_folders:
                continue
            if not include_hidden and is_hidden(child):
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in filenames:
            file_path = current_path / filename
            if is_broken_symlink(file_path):
                continue
            if not follow_symlinks and file_path.is_symlink():
                continue
            if not include_hidden and is_hidden(file_path):
                continue
            if _normalize_extension(file_path.suffix) in ignored_extensions:
                continue
            try:
                size = file_path.stat().st_size
            except OSError:
                yield file_path
                continue
            if min_size is not None and size < min_size:
                continue
            if max_size is not None and size > max_size:
                continue
            yield file_path


def calculate_folder_hash(files: list[FolderFileResult], algorithm: str, *, blake3_digest_length: int | None = None) -> str:
    """Calculate a deterministic folder hash from paths and file hashes."""

    hasher = create_hasher(algorithm, blake3_digest_length=blake3_digest_length)
    for item in sorted(files, key=lambda result: result.relative_path.lower()):
        if item.status != "completed":
            continue
        digest = item.hashes.get(algorithm)
        if digest is None:
            continue
        hasher.update(item.relative_path.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(digest.lower().encode("ascii"))
        hasher.update(b"\n")
    return hasher.hexdigest()


def _hash_folder_file(
    root: Path,
    file_path: Path,
    algorithms: list[str],
    chunk_size: int,
    blake3_digest_length: int | None,
) -> FolderFileResult:
    try:
        relative = normalize_relative_path(file_path.relative_to(root))
    except ValueError:
        relative = file_path.name
    try:
        stat = file_path.stat()
        hashes = hash_file_map(
            file_path,
            algorithms=algorithms,
            chunk_size=chunk_size,
            blake3_digest_length=blake3_digest_length,
        )
        return FolderFileResult(
            relative_path=relative,
            size=stat.st_size,
            modified_at=stat_modified_iso(file_path),
            hashes=hashes,
        )
    except PermissionError as exc:
        return FolderFileResult(relative_path=relative, size=0, modified_at=None, status="permission denied", error=str(exc))
    except OSError as exc:
        return FolderFileResult(relative_path=relative, size=0, modified_at=None, status="error", error=str(exc))
    except Exception as exc:
        return FolderFileResult(relative_path=relative, size=0, modified_at=None, status="error", error=str(exc))


def _coerce_algorithms(algorithm: str | None, algorithms: str | list[str] | None) -> list[str]:
    if isinstance(algorithms, list):
        return parse_algorithms(algorithms=",".join(algorithms))
    if isinstance(algorithms, str):
        return parse_algorithms(algorithms=algorithms)
    return parse_algorithms(algorithm=algorithm)


def _normalize_extension(extension: str) -> str:
    return extension.lower() if extension.startswith(".") else f".{extension.lower()}"


def _sort_results(results: list[FolderFileResult], sort_by: str) -> list[FolderFileResult]:
    if sort_by == "size":
        return sorted(results, key=lambda item: (item.size, item.relative_path.lower()))
    if sort_by == "hash":
        return sorted(results, key=lambda item: (next(iter(item.hashes.values()), ""), item.relative_path.lower()))
    return sorted(results, key=lambda item: item.relative_path.lower())
