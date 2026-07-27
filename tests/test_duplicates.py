from __future__ import annotations

from hash_toolkit.duplicates import find_duplicates


def test_duplicate_detection(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("same", encoding="utf-8")
    (tmp_path / "b.txt").write_text("same", encoding="utf-8")
    (tmp_path / "c.txt").write_text("different", encoding="utf-8")
    groups = find_duplicates(tmp_path)
    assert len(groups) == 1
    assert groups[0].duplicate_count == 2
    assert groups[0].recoverable_size == len("same")
