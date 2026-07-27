"""Text hashing functions."""

from __future__ import annotations

import time
from pathlib import Path

from .algorithms import create_hasher, normalize_hash, parse_algorithms
from .config import DEFAULT_TEXT_ENCODING
from .models import ComparisonResult, HashResult


def hash_text(
    text: str,
    *,
    algorithm: str | None = None,
    algorithms: str | list[str] | None = None,
    encoding: str = DEFAULT_TEXT_ENCODING,
    blake3_digest_length: int | None = None,
) -> list[HashResult]:
    """Hash text without storing it outside the returned result."""

    started = time.perf_counter()
    try:
        data = text.encode(encoding)
    except UnicodeEncodeError as exc:
        raise UnicodeEncodeError(exc.encoding, exc.object, exc.start, exc.end, f"Encoding failed: {exc.reason}") from exc
    selected = _coerce_algorithms(algorithm, algorithms)
    results: list[HashResult] = []
    for name in selected:
        hasher = create_hasher(name, blake3_digest_length=blake3_digest_length)
        hasher.update(data)
        duration = max(time.perf_counter() - started, 0.0)
        results.append(
            HashResult(
                source_type="text",
                name="<text>",
                path=None,
                size=len(data),
                algorithm=name,
                hash_value=hasher.hexdigest(),
                duration_seconds=duration,
                speed_bytes_per_second=(len(data) / duration if duration > 0 else float(len(data))),
                modified_at=None,
            )
        )
    return results


def hash_text_file(
    path: str | Path,
    *,
    algorithm: str | None = None,
    algorithms: str | list[str] | None = None,
    encoding: str = DEFAULT_TEXT_ENCODING,
    blake3_digest_length: int | None = None,
) -> list[HashResult]:
    """Read text from a file and hash it with the selected encoding."""

    text_path = Path(path).expanduser()
    return hash_text(
        text_path.read_text(encoding=encoding),
        algorithm=algorithm,
        algorithms=algorithms,
        encoding=encoding,
        blake3_digest_length=blake3_digest_length,
    )


def compare_text_with_hash(
    text: str,
    expected_hash: str,
    *,
    algorithm: str,
    encoding: str = DEFAULT_TEXT_ENCODING,
    blake3_digest_length: int | None = None,
) -> ComparisonResult:
    """Compare text against a known checksum."""

    result = hash_text(text, algorithm=algorithm, encoding=encoding, blake3_digest_length=blake3_digest_length)[0]
    return ComparisonResult(
        comparison_type="text-hash",
        left_name="<text>",
        right_name="<expected>",
        algorithm=result.algorithm,
        left_hash=result.hash_value,
        right_hash=expected_hash,
        match=normalize_hash(result.hash_value) == normalize_hash(expected_hash),
        left_size=result.size,
    )


def copy_to_clipboard(value: str) -> bool:
    """Copy text to the clipboard using tkinter when available."""

    try:
        import tkinter  # type: ignore[import-not-found]

        root = tkinter.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(value)
        root.update()
        root.destroy()
        return True
    except Exception:
        return False


def _coerce_algorithms(algorithm: str | None, algorithms: str | list[str] | None) -> list[str]:
    if isinstance(algorithms, list):
        return parse_algorithms(algorithms=",".join(algorithms))
    if isinstance(algorithms, str):
        return parse_algorithms(algorithms=algorithms)
    return parse_algorithms(algorithm=algorithm)
