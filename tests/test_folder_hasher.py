from __future__ import annotations

from hash_toolkit.folder_hasher import scan_folder


def test_folder_hash_is_deterministic(tmp_path) -> None:
    (tmp_path / "b.txt").write_text("two", encoding="utf-8")
    (tmp_path / "a.txt").write_text("one", encoding="utf-8")
    first = scan_folder(tmp_path, algorithm="sha256", workers=1)
    second = scan_folder(tmp_path, algorithm="sha256", workers=2)
    assert first.folder_hash == second.folder_hash
    assert [item.relative_path for item in first.files] == ["a.txt", "b.txt"]


def test_folder_filters_hidden_and_extension(tmp_path) -> None:
    (tmp_path / "keep.txt").write_text("keep", encoding="utf-8")
    (tmp_path / ".hidden").write_text("hidden", encoding="utf-8")
    (tmp_path / "skip.log").write_text("skip", encoding="utf-8")
    scan = scan_folder(tmp_path, algorithm="sha256", ignore_extensions=[".log"])
    assert [item.relative_path for item in scan.files] == ["keep.txt"]
