"""Hash comparison helpers."""

from __future__ import annotations

from pathlib import Path

from .algorithms import normalize_hash, parse_algorithms
from .file_hasher import hash_file
from .folder_hasher import scan_folder
from .manifests import load_manifest_file
from .models import ComparisonResult
from .text_hasher import hash_text


def compare_hash_values(left_hash: str, right_hash: str, *, algorithm: str) -> ComparisonResult:
    """Compare two hexadecimal hash values case-insensitively."""

    return ComparisonResult(
        comparison_type="hash",
        left_name="left",
        right_name="right",
        algorithm=parse_algorithms(algorithm=algorithm)[0],
        left_hash=left_hash,
        right_hash=right_hash,
        match=normalize_hash(left_hash) == normalize_hash(right_hash),
    )


def compare_files(
    left: str | Path,
    right: str | Path,
    *,
    algorithm: str = "sha256",
    chunk_size: int = 1024 * 1024,
) -> ComparisonResult:
    """Compare two files with a selected algorithm."""

    selected = parse_algorithms(algorithm=algorithm)[0]
    left_result = hash_file(left, algorithm=selected, chunk_size=chunk_size)[0]
    right_result = hash_file(right, algorithm=selected, chunk_size=chunk_size)[0]
    return ComparisonResult(
        comparison_type="file",
        left_name=left_result.name,
        right_name=right_result.name,
        algorithm=selected,
        left_hash=left_result.hash_value,
        right_hash=right_result.hash_value,
        match=normalize_hash(left_result.hash_value) == normalize_hash(right_result.hash_value),
        left_size=left_result.size,
        right_size=right_result.size,
    )


def compare_texts(left: str, right: str, *, algorithm: str = "sha256", encoding: str = "utf-8") -> ComparisonResult:
    """Compare two text values with a selected algorithm."""

    selected = parse_algorithms(algorithm=algorithm)[0]
    left_result = hash_text(left, algorithm=selected, encoding=encoding)[0]
    right_result = hash_text(right, algorithm=selected, encoding=encoding)[0]
    return ComparisonResult(
        comparison_type="text",
        left_name="<left text>",
        right_name="<right text>",
        algorithm=selected,
        left_hash=left_result.hash_value,
        right_hash=right_result.hash_value,
        match=normalize_hash(left_result.hash_value) == normalize_hash(right_result.hash_value),
        left_size=left_result.size,
        right_size=right_result.size,
    )


def compare_file_with_hash(
    path: str | Path,
    expected_hash: str,
    *,
    algorithm: str = "sha256",
    chunk_size: int = 1024 * 1024,
) -> ComparisonResult:
    """Compare a calculated file hash with a known checksum."""

    selected = parse_algorithms(algorithm=algorithm)[0]
    result = hash_file(path, algorithm=selected, chunk_size=chunk_size)[0]
    return ComparisonResult(
        comparison_type="file-hash",
        left_name=result.name,
        right_name="<expected>",
        algorithm=selected,
        left_hash=result.hash_value,
        right_hash=expected_hash,
        match=normalize_hash(result.hash_value) == normalize_hash(expected_hash),
        left_size=result.size,
    )


def compare_folders(left: str | Path, right: str | Path, *, algorithm: str = "sha256") -> ComparisonResult:
    """Compare two folders using deterministic folder hashes."""

    selected = parse_algorithms(algorithm=algorithm)[0]
    left_scan = scan_folder(left, algorithm=selected)
    right_scan = scan_folder(right, algorithm=selected)
    return ComparisonResult(
        comparison_type="folder",
        left_name=str(left),
        right_name=str(right),
        algorithm=selected,
        left_hash=left_scan.folder_hash,
        right_hash=right_scan.folder_hash,
        match=normalize_hash(left_scan.folder_hash) == normalize_hash(right_scan.folder_hash),
        left_size=left_scan.total_size,
        right_size=right_scan.total_size,
        details={"left_files": left_scan.total_files, "right_files": right_scan.total_files},
    )


def compare_manifest_files(left: str | Path, right: str | Path) -> list[ComparisonResult]:
    """Compare two checksum manifest files by filename and expected digest."""

    left_entries = load_manifest_file(left)
    right_entries = load_manifest_file(right)
    right_by_key = {(entry.file_name, entry.algorithm): entry.expected_hash for entry in right_entries}
    results: list[ComparisonResult] = []
    for entry in left_entries:
        other = right_by_key.get((entry.file_name, entry.algorithm), "")
        results.append(
            ComparisonResult(
                comparison_type="manifest-entry",
                left_name=entry.file_name,
                right_name=entry.file_name,
                algorithm=entry.algorithm,
                left_hash=entry.expected_hash,
                right_hash=other,
                match=bool(other) and normalize_hash(entry.expected_hash) == normalize_hash(other),
            )
        )
    return results
