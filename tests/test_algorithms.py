from __future__ import annotations

import hashlib
import zlib

import pytest

from hash_toolkit.algorithms import ALGORITHMS, MissingDependencyError, create_hasher, expected_hex_length, is_valid_hex_hash, normalize_algorithm


def digest(algorithm: str, data: bytes) -> str:
    hasher = create_hasher(algorithm)
    hasher.update(data)
    return hasher.hexdigest()


def test_supported_hashlib_algorithms_known_vectors() -> None:
    data = b"abc"
    expected = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha224": hashlib.sha224(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha384": hashlib.sha384(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "sha3_224": hashlib.sha3_224(data).hexdigest(),
        "sha3_256": hashlib.sha3_256(data).hexdigest(),
        "sha3_384": hashlib.sha3_384(data).hexdigest(),
        "sha3_512": hashlib.sha3_512(data).hexdigest(),
        "blake2b": hashlib.blake2b(data).hexdigest(),
        "blake2s": hashlib.blake2s(data).hexdigest(),
    }
    for algorithm, expected_digest in expected.items():
        assert digest(algorithm, data) == expected_digest


def test_crc32_formatting() -> None:
    assert digest("crc32", b"123456789") == "CBF43926"
    assert digest("crc32", b"") == "00000000"
    assert digest("crc32", b"abc") == f"{zlib.crc32(b'abc') & 0xFFFFFFFF:08X}"


def test_blake3_output_if_installed() -> None:
    if "blake3" not in ALGORITHMS:
        pytest.skip("BLAKE3 is not registered")
    try:
        actual = digest("blake3", b"abc")
    except MissingDependencyError:
        pytest.skip("blake3 package is not installed")
    import blake3

    assert actual == blake3.blake3(b"abc").hexdigest()


def test_normalize_algorithm_aliases() -> None:
    assert normalize_algorithm("SHA-256") == "sha256"
    assert normalize_algorithm("sha3-512") == "sha3_512"
    assert normalize_algorithm("BLAKE-3") == "blake3"


def test_invalid_hash_validation() -> None:
    assert is_valid_hex_hash("a" * expected_hex_length("sha256"), "sha256")
    assert not is_valid_hex_hash("xyz", "sha256")
    assert not is_valid_hex_hash("a" * 8, "sha256")
