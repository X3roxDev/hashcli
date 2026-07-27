"""Checksum verification."""

from __future__ import annotations

from pathlib import Path

from .algorithms import is_valid_hex_hash, normalize_hash
from .file_hasher import hash_file
from .manifests import infer_algorithm_from_filename, load_manifest_file
from .models import VerificationResult
from .utils import safe_manifest_path


def verify_manifest(
    manifest_path: str | Path,
    *,
    base_dir: str | Path | None = None,
    algorithm: str | None = None,
) -> list[VerificationResult]:
    """Verify files listed in a checksum manifest."""

    path = Path(manifest_path).expanduser()
    default_algorithm = algorithm or infer_algorithm_from_filename(path)
    entries = load_manifest_file(path, default_algorithm=default_algorithm)
    root = Path(base_dir).expanduser() if base_dir else path.parent
    results: list[VerificationResult] = []
    for entry in entries:
        try:
            if not is_valid_hex_hash(entry.expected_hash, entry.algorithm):
                results.append(
                    VerificationResult(
                        entry.file_name,
                        str(root / entry.file_name),
                        entry.algorithm,
                        entry.expected_hash,
                        None,
                        "invalid checksum",
                        "Hash is not valid hexadecimal or length does not match algorithm",
                    )
                )
                continue
            file_path = safe_manifest_path(root, entry.file_name)
            if not file_path.exists():
                results.append(
                    VerificationResult(entry.file_name, str(file_path), entry.algorithm, entry.expected_hash, None, "missing file")
                )
                continue
            actual = hash_file(file_path, algorithm=entry.algorithm)[0].hash_value
            results.append(
                VerificationResult(
                    entry.file_name,
                    str(file_path),
                    entry.algorithm,
                    entry.expected_hash,
                    actual,
                    "verified" if normalize_hash(actual) == normalize_hash(entry.expected_hash) else "mismatch",
                )
            )
        except PermissionError as exc:
            results.append(
                VerificationResult(entry.file_name, str(root / entry.file_name), entry.algorithm, entry.expected_hash, None, "permission denied", str(exc))
            )
        except ValueError as exc:
            results.append(
                VerificationResult(entry.file_name, str(root / entry.file_name), entry.algorithm, entry.expected_hash, None, "invalid checksum", str(exc))
            )
        except Exception as exc:
            results.append(
                VerificationResult(entry.file_name, str(root / entry.file_name), entry.algorithm, entry.expected_hash, None, "error", str(exc))
            )
    return results
