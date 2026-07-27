from __future__ import annotations

from hash_toolkit.integrity import check_baseline, create_baseline


def test_integrity_baseline_detects_changes(tmp_path) -> None:
    (tmp_path / "kept.txt").write_text("same", encoding="utf-8")
    (tmp_path / "removed.txt").write_text("gone", encoding="utf-8")
    baseline = create_baseline(tmp_path, output=tmp_path / "baseline.json")
    (tmp_path / "kept.txt").write_text("changed", encoding="utf-8")
    (tmp_path / "removed.txt").unlink()
    (tmp_path / "added.txt").write_text("new", encoding="utf-8")
    report = check_baseline(tmp_path, baseline)
    assert any(item.relative_path == "added.txt" for item in report.added)
    assert any(item.relative_path == "removed.txt" for item in report.removed)
    assert any(item["relative_path"] == "kept.txt" for item in report.modified)


def test_integrity_detects_rename(tmp_path) -> None:
    (tmp_path / "old.txt").write_text("same", encoding="utf-8")
    baseline = create_baseline(tmp_path, output=tmp_path / "baseline.json")
    (tmp_path / "old.txt").rename(tmp_path / "new.txt")
    report = check_baseline(tmp_path, baseline)
    assert report.moved_or_renamed
    assert report.moved_or_renamed[0]["from"] == "old.txt"
    assert report.moved_or_renamed[0]["to"] == "new.txt"
