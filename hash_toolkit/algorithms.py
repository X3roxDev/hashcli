"""Hash algorithm registration and streaming hash adapters."""

from __future__ import annotations

import hashlib
import re
import zlib
from typing import Protocol

from .config import DEFAULT_ALGORITHM
from .models import AlgorithmSpec


class HashAdapter(Protocol):
    """Small protocol shared by hashlib, BLAKE3, and CRC32 adapters."""

    def update(self, data: bytes) -> None:
        """Update the digest with bytes."""

    def hexdigest(self) -> str:
        """Return the digest in hexadecimal format."""


class CRC32Hasher:
    """Streaming CRC32 checksum adapter."""

    def __init__(self) -> None:
        self._value = 0

    def update(self, data: bytes) -> None:
        """Update the checksum with bytes."""

        self._value = zlib.crc32(data, self._value)

    def hexdigest(self) -> str:
        """Return an eight-character uppercase CRC32 value."""

        return f"{self._value & 0xFFFFFFFF:08X}"


class MissingDependencyError(RuntimeError):
    """Raised when an optional hashing dependency is missing."""


ALGORITHMS: dict[str, AlgorithmSpec] = {
    "md5": AlgorithmSpec("md5", "MD5", "legacy/insecure", 16, "md5", description="Legacy; collision-prone."),
    "sha1": AlgorithmSpec("sha1", "SHA-1", "legacy/insecure", 20, "sha1", description="Legacy; collision-prone."),
    "sha224": AlgorithmSpec("sha224", "SHA-224", "cryptographic", 28, "sha224"),
    "sha256": AlgorithmSpec("sha256", "SHA-256", "cryptographic", 32, "sha256"),
    "sha384": AlgorithmSpec("sha384", "SHA-384", "cryptographic", 48, "sha384"),
    "sha512": AlgorithmSpec("sha512", "SHA-512", "cryptographic", 64, "sha512"),
    "sha3_224": AlgorithmSpec("sha3_224", "SHA3-224", "cryptographic", 28, "sha3_224"),
    "sha3_256": AlgorithmSpec("sha3_256", "SHA3-256", "cryptographic", 32, "sha3_256"),
    "sha3_384": AlgorithmSpec("sha3_384", "SHA3-384", "cryptographic", 48, "sha3_384"),
    "sha3_512": AlgorithmSpec("sha3_512", "SHA3-512", "cryptographic", 64, "sha3_512"),
    "blake2b": AlgorithmSpec("blake2b", "BLAKE2b", "cryptographic", 64, "blake2b"),
    "blake2s": AlgorithmSpec("blake2s", "BLAKE2s", "cryptographic", 32, "blake2s"),
    "blake3": AlgorithmSpec("blake3", "BLAKE3", "cryptographic", 32, None, "blake3"),
    "crc32": AlgorithmSpec("crc32", "CRC32", "non-cryptographic", 4, None, description="Accidental corruption detection only."),
}

ALIASES = {
    "sha-1": "sha1",
    "sha-224": "sha224",
    "sha-256": "sha256",
    "sha-384": "sha384",
    "sha-512": "sha512",
    "sha3-224": "sha3_224",
    "sha3-256": "sha3_256",
    "sha3-384": "sha3_384",
    "sha3-512": "sha3_512",
    "sha3_224": "sha3_224",
    "sha3_256": "sha3_256",
    "sha3_384": "sha3_384",
    "sha3_512": "sha3_512",
    "blake-2b": "blake2b",
    "blake-2s": "blake2s",
    "blake-3": "blake3",
}


def normalize_algorithm(name: str | None) -> str:
    """Normalize a user-supplied algorithm name."""

    if not name:
        return DEFAULT_ALGORITHM
    normalized = name.strip().lower().replace(" ", "").replace("/", "_")
    normalized = ALIASES.get(normalized, normalized.replace("-", ""))
    normalized = ALIASES.get(normalized, normalized)
    if normalized not in ALGORITHMS:
        supported = ", ".join(sorted(ALGORITHMS))
        raise ValueError(f"Unsupported algorithm '{name}'. Supported algorithms: {supported}")
    return normalized


def parse_algorithms(algorithm: str | None = None, algorithms: str | None = None) -> list[str]:
    """Parse one algorithm or a comma-separated algorithm list."""

    source = algorithms or algorithm or DEFAULT_ALGORITHM
    parsed = [normalize_algorithm(item) for item in source.split(",") if item.strip()]
    deduped: list[str] = []
    for item in parsed:
        if item not in deduped:
            deduped.append(item)
    return deduped or [DEFAULT_ALGORITHM]


def create_hasher(algorithm: str, *, blake3_digest_length: int | None = None) -> HashAdapter:
    """Create a streaming hasher for a supported algorithm."""

    normalized = normalize_algorithm(algorithm)
    if normalized == "crc32":
        return CRC32Hasher()
    if normalized == "blake3":
        try:
            import blake3  # type: ignore[import-not-found]
        except ModuleNotFoundError as exc:
            raise MissingDependencyError("BLAKE3 support requires: pip install blake3") from exc
        digest_length = blake3_digest_length or ALGORITHMS["blake3"].digest_size or 32

        class Blake3Adapter:
            def __init__(self) -> None:
                self._hasher = blake3.blake3()

            def update(self, data: bytes) -> None:
                self._hasher.update(data)

            def hexdigest(self) -> str:
                return self._hasher.hexdigest(length=digest_length)

        return Blake3Adapter()
    spec = ALGORITHMS[normalized]
    assert spec.hashlib_name is not None
    return hashlib.new(spec.hashlib_name)


def expected_hex_length(algorithm: str, *, blake3_digest_length: int | None = None) -> int:
    """Return expected hexadecimal length for an algorithm."""

    normalized = normalize_algorithm(algorithm)
    digest_size = blake3_digest_length if normalized == "blake3" and blake3_digest_length else ALGORITHMS[normalized].digest_size
    if digest_size is None:
        raise ValueError(f"Digest size is unknown for {algorithm}")
    return digest_size * 2


def normalize_hash(value: str) -> str:
    """Normalize a hexadecimal checksum for case-insensitive comparison."""

    return value.strip().lower()


def is_valid_hex_hash(value: str, algorithm: str | None = None) -> bool:
    """Return whether a checksum is hexadecimal and optionally the expected length."""

    normalized = normalize_hash(value)
    if not normalized or re.fullmatch(r"[0-9a-f]+", normalized) is None:
        return False
    if algorithm:
        try:
            return len(normalized) == expected_hex_length(algorithm)
        except ValueError:
            return False
    return True


def security_warning(algorithms: list[str]) -> str | None:
    """Return a warning for algorithms unsuitable for security decisions."""

    selected = {normalize_algorithm(item) for item in algorithms}
    weak = selected & {"md5", "sha1", "crc32"}
    if not weak:
        return None
    labels = ", ".join(ALGORITHMS[item].display_name for item in sorted(weak))
    return (
        f"{labels} should not be used for security-sensitive verification. "
        "Matching hashes do not prove a file is safe or malware-free."
    )
