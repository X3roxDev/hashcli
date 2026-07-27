"""Application configuration constants."""

from __future__ import annotations

from pathlib import Path

APP_NAME = "HashCLI"
VERSION = "1.0.0"
DEFAULT_ALGORITHM = "sha256"
DEFAULT_TEXT_ENCODING = "utf-8"
DEFAULT_CHUNK_SIZE = 1024 * 1024
DEFAULT_WORKERS = 4
MAX_MANIFEST_BYTES = 50 * 1024 * 1024
EXPORT_DIR = Path("exports")

SECURE_ALGORITHMS = {
    "sha256",
    "sha384",
    "sha512",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "blake2b",
    "blake2s",
    "blake3",
}
LEGACY_ALGORITHMS = {"md5", "sha1"}
NON_CRYPTOGRAPHIC_ALGORITHMS = {"crc32"}
