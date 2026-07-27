"""Typed models used by the toolkit."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class AlgorithmSpec:
    """Metadata for a supported hashing algorithm."""

    name: str
    display_name: str
    category: str
    digest_size: int | None
    hashlib_name: str | None = None
    requires_package: str | None = None
    description: str = ""


@dataclass(slots=True)
class HashResult:
    """Hashing result for one file or text value and one algorithm."""

    source_type: str
    name: str
    path: str | None
    size: int
    algorithm: str
    hash_value: str
    duration_seconds: float
    speed_bytes_per_second: float
    modified_at: str | None
    status: str = "completed"
    error: str | None = None


@dataclass(slots=True)
class FolderFileResult:
    """Hashing result for a single file inside a folder scan."""

    relative_path: str
    size: int
    modified_at: str | None
    hashes: dict[str, str] = field(default_factory=dict)
    status: str = "completed"
    error: str | None = None


@dataclass(slots=True)
class FolderScanResult:
    """Complete folder scan output."""

    root: str
    algorithms: list[str]
    files: list[FolderFileResult]
    folder_hash_algorithm: str
    folder_hash: str
    duration_seconds: float
    total_files: int
    total_size: int
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ComparisonResult:
    """Result of comparing two hashes, files, folders, or texts."""

    comparison_type: str
    left_name: str
    right_name: str
    algorithm: str
    left_hash: str
    right_hash: str
    match: bool
    left_size: int | None = None
    right_size: int | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class VerificationResult:
    """Result of verifying one checksum manifest entry."""

    file_name: str
    file_path: str
    algorithm: str
    expected_hash: str
    actual_hash: str | None
    status: str
    error: str | None = None


@dataclass(slots=True)
class DuplicateGroup:
    """Group of duplicate files."""

    hash_value: str
    algorithm: str
    files: list[str]
    file_size: int

    @property
    def duplicate_count(self) -> int:
        """Return the number of files in the group."""

        return len(self.files)

    @property
    def recoverable_size(self) -> int:
        """Return disk space recoverable by keeping one file."""

        return max(0, len(self.files) - 1) * self.file_size


@dataclass(slots=True)
class IntegrityReport:
    """Baseline check report."""

    root: str
    algorithm: str
    added: list[FolderFileResult] = field(default_factory=list)
    removed: list[FolderFileResult] = field(default_factory=list)
    modified: list[dict[str, Any]] = field(default_factory=list)
    moved_or_renamed: list[dict[str, Any]] = field(default_factory=list)
    unchanged: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        """Return whether the report detected any change."""

        return bool(self.added or self.removed or self.modified or self.moved_or_renamed or self.errors)


def to_plain_data(value: Any) -> Any:
    """Convert dataclasses and nested containers into JSON-serializable data."""

    if hasattr(value, "__dataclass_fields__"):
        return {key: to_plain_data(item) for key, item in asdict(value).items()}
    if isinstance(value, list):
        return [to_plain_data(item) for item in value]
    if isinstance(value, tuple):
        return [to_plain_data(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_plain_data(item) for key, item in value.items()}
    return value
