"""Duplicate file detection."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from .file_hasher import hash_file
from .folder_hasher import iter_scan_files
from .models import DuplicateGroup


def find_duplicates(
    root: str | Path,
    *,
    algorithm: str = "sha256",
    include_hidden: bool = False,
    follow_symlinks: bool = False,
) -> list[DuplicateGroup]:
    """Find duplicate files by grouping by size before hashing candidates."""

    folder = Path(root).expanduser()
    if not folder.exists():
        raise FileNotFoundError(f"Folder not found: {folder}")
    by_size: dict[int, list[Path]] = defaultdict(list)
    for file_path in iter_scan_files(folder, include_hidden=include_hidden, follow_symlinks=follow_symlinks):
        try:
            by_size[file_path.stat().st_size].append(file_path)
        except OSError:
            continue

    groups: list[DuplicateGroup] = []
    for size, paths in by_size.items():
        if len(paths) < 2:
            continue
        by_hash: dict[str, list[str]] = defaultdict(list)
        for file_path in paths:
            try:
                digest = hash_file(file_path, algorithm=algorithm)[0].hash_value
                by_hash[digest.lower()].append(str(file_path.resolve()))
            except OSError:
                continue
        for digest, duplicates in by_hash.items():
            if len(duplicates) > 1:
                groups.append(DuplicateGroup(digest, algorithm, sorted(duplicates), size))
    return sorted(groups, key=lambda group: (-group.recoverable_size, group.files[0]))
