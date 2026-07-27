"""Checksum manifest parsing and writing."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .algorithms import ALGORITHMS, is_valid_hex_hash, normalize_algorithm
from .config import MAX_MANIFEST_BYTES


@dataclass(slots=True)
class ManifestEntry:
    """Parsed checksum manifest entry."""

    file_name: str
    expected_hash: str
    algorithm: str
    line_number: int


HASH_FIRST_RE = re.compile(r"^(?P<hash>[0-9A-Fa-f]{8,128})\s+\*?(?P<file>.+?)\s*$")
BSD_RE = re.compile(r"^(?P<alg>[A-Za-z0-9_-]+)\s*\((?P<file>.+?)\)\s*=\s*(?P<hash>[0-9A-Fa-f]+)\s*$")
COLON_RE = re.compile(r"^(?P<file>.+?)\s*:\s*(?P<hash>[0-9A-Fa-f]+)\s*$")


def load_manifest_file(path: str | Path, *, default_algorithm: str | None = None) -> list[ManifestEntry]:
    """Load a checksum manifest from text or JSON."""

    manifest_path = Path(path).expanduser()
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError(f"Manifest is too large: {manifest_path}")
    if manifest_path.suffix.lower() == ".json":
        return _load_json_manifest(manifest_path, default_algorithm=default_algorithm)
    return parse_manifest_text(manifest_path.read_text(encoding="utf-8", errors="replace"), default_algorithm=default_algorithm)


def parse_manifest_text(text: str, *, default_algorithm: str | None = None) -> list[ManifestEntry]:
    """Parse common checksum manifest formats."""

    entries: list[ManifestEntry] = []
    inferred_algorithm = normalize_algorithm(default_algorithm) if default_algorithm else None
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parsed = _parse_line(line, line_number, inferred_algorithm)
        if parsed:
            entries.append(parsed)
    if not entries:
        raise ValueError("No valid checksum entries found in manifest")
    return entries


def infer_algorithm_from_filename(path: Path) -> str | None:
    """Infer a checksum algorithm from a common manifest filename."""

    upper_name = path.name.upper()
    if "SHA256" in upper_name:
        return "sha256"
    if "SHA512" in upper_name:
        return "sha512"
    if "SHA1" in upper_name:
        return "sha1"
    if "MD5" in upper_name:
        return "md5"
    return None


def write_checksum_manifest(path: str | Path, rows: list[tuple[str, str]]) -> Path:
    """Write a traditional checksum manifest as '<hash>  <filename>' rows."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("".join(f"{digest}  {filename}\n" for digest, filename in rows), encoding="utf-8")
    return target


def _parse_line(line: str, line_number: int, default_algorithm: str | None) -> ManifestEntry | None:
    bsd = BSD_RE.match(line)
    if bsd:
        algorithm = normalize_algorithm(bsd.group("alg"))
        return ManifestEntry(bsd.group("file"), bsd.group("hash"), algorithm, line_number)

    colon = COLON_RE.match(line)
    if colon and default_algorithm:
        return ManifestEntry(colon.group("file"), colon.group("hash"), default_algorithm, line_number)

    first = HASH_FIRST_RE.match(line)
    if first:
        digest = first.group("hash")
        algorithm = default_algorithm or _infer_algorithm_from_hash_length(digest)
        if algorithm:
            return ManifestEntry(first.group("file"), digest, algorithm, line_number)
    return None


def _infer_algorithm_from_hash_length(digest: str) -> str | None:
    lengths = {
        8: "crc32",
        32: "md5",
        40: "sha1",
        56: "sha224",
        64: "sha256",
        96: "sha384",
        128: "sha512",
    }
    algorithm = lengths.get(len(digest.strip()))
    if algorithm and algorithm in ALGORITHMS and is_valid_hex_hash(digest, algorithm):
        return algorithm
    return algorithm


def _load_json_manifest(path: Path, *, default_algorithm: str | None) -> list[ManifestEntry]:
    data = json.loads(path.read_text(encoding="utf-8"))
    algorithm = normalize_algorithm(data.get("hash_algorithm") or data.get("algorithm") or default_algorithm or "sha256")
    files = data.get("files") or data.get("results") or []
    entries: list[ManifestEntry] = []
    for index, item in enumerate(files, start=1):
        if not isinstance(item, dict):
            continue
        name = item.get("relative_path") or item.get("file_name") or item.get("path")
        hashes = item.get("hashes") or {}
        digest = hashes.get(algorithm) if isinstance(hashes, dict) else None
        digest = digest or item.get("hash") or item.get("hash_value")
        if name and digest:
            entries.append(ManifestEntry(str(name), str(digest), algorithm, index))
    if not entries:
        raise ValueError(f"No usable checksum entries in JSON manifest: {path}")
    return entries
