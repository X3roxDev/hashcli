from __future__ import annotations

import hashlib

import pytest

from hash_toolkit.manifests import parse_manifest_text
from hash_toolkit.verifier import verify_manifest


def test_manifest_parsing_formats() -> None:
    digest = hashlib.sha256(b"abc").hexdigest()
    entries = parse_manifest_text(f"{digest}  file.bin\nSHA256(other.bin)= {digest}\nthird.bin:{digest}\n", default_algorithm="sha256")
    assert [entry.file_name for entry in entries] == ["file.bin", "other.bin", "third.bin"]


def test_verify_manifest_statuses(tmp_path) -> None:
    file_path = tmp_path / "file.bin"
    file_path.write_bytes(b"abc")
    digest = hashlib.sha256(b"abc").hexdigest()
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(f"{digest}  file.bin\n{'0' * 64}  missing.bin\n", encoding="utf-8")
    statuses = {item.file_name: item.status for item in verify_manifest(manifest)}
    assert statuses["file.bin"] == "verified"
    assert statuses["missing.bin"] == "missing file"


def test_verify_rejects_path_traversal(tmp_path) -> None:
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(f"{'0' * 64}  ../escape.bin\n", encoding="utf-8")
    result = verify_manifest(manifest)[0]
    assert result.status in {"invalid checksum", "error"}
    assert "escapes root" in (result.error or "")


def test_empty_manifest_invalid() -> None:
    with pytest.raises(ValueError):
        parse_manifest_text("")
