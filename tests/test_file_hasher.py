from __future__ import annotations

import hashlib

import pytest

from hash_toolkit.file_hasher import hash_file


def test_empty_file_hash(tmp_path) -> None:
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    result = hash_file(path, algorithm="sha256")[0]
    assert result.hash_value == hashlib.sha256(b"").hexdigest()
    assert result.size == 0


def test_multiple_algorithms_one_call(tmp_path) -> None:
    path = tmp_path / "data.bin"
    path.write_bytes(b"hello")
    results = hash_file(path, algorithms="md5,sha256,crc32", chunk_size=2)
    values = {item.algorithm: item.hash_value for item in results}
    assert values["md5"] == hashlib.md5(b"hello").hexdigest()
    assert values["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert values["crc32"] == "3610A686"


def test_large_file_streaming_with_small_chunks(tmp_path) -> None:
    payload = b"abc123" * 200_000
    path = tmp_path / "large.bin"
    path.write_bytes(payload)
    result = hash_file(path, algorithm="sha512", chunk_size=1024)[0]
    assert result.hash_value == hashlib.sha512(payload).hexdigest()


def test_missing_file_error(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        hash_file(tmp_path / "missing.bin")
