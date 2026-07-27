from __future__ import annotations

from hash_toolkit.algorithms import normalize_hash
from hash_toolkit.comparator import compare_file_with_hash, compare_files, compare_hash_values, compare_texts
from hash_toolkit.file_hasher import hash_file


def test_compare_files_match_and_mismatch(tmp_path) -> None:
    left = tmp_path / "left.bin"
    right = tmp_path / "right.bin"
    left.write_bytes(b"same")
    right.write_bytes(b"same")
    assert compare_files(left, right).match
    right.write_bytes(b"different")
    assert not compare_files(left, right).match


def test_hash_comparison_case_insensitive() -> None:
    assert compare_hash_values("ABCDEF", "abcdef", algorithm="sha256").match
    assert normalize_hash("ABC") == "abc"


def test_compare_file_with_known_hash(tmp_path) -> None:
    path = tmp_path / "file.txt"
    path.write_text("content", encoding="utf-8")
    expected = hash_file(path, algorithm="sha256")[0].hash_value.upper()
    assert compare_file_with_hash(path, expected, algorithm="sha256").match


def test_compare_texts() -> None:
    assert compare_texts("hello", "hello").match
    assert not compare_texts("hello", "world").match
