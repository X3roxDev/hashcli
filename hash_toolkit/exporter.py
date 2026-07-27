"""Export helpers for JSON, CSV, TXT, and checksum manifests."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .config import APP_NAME, EXPORT_DIR, VERSION
from .models import to_plain_data
from .utils import platform_metadata, timestamp_for_filename, utc_now_iso


def export_results(
    data: Any,
    *,
    export_format: str,
    output: str | Path | None = None,
    algorithms: list[str] | None = None,
    scanned_path: str | None = None,
    prefix: str = "hash_report",
) -> Path:
    """Export result data to JSON, CSV, TXT, or checksum manifest format."""

    fmt = export_format.lower().strip()
    target = Path(output) if output else EXPORT_DIR / f"{prefix}_{timestamp_for_filename()}.{_extension_for(fmt)}"
    target.parent.mkdir(parents=True, exist_ok=True)
    plain = to_plain_data(data)
    if fmt == "json":
        payload = {
            "export_timestamp": utc_now_iso(),
            "application": APP_NAME,
            "version": VERSION,
            "operating_system": platform_metadata(),
            "selected_algorithms": algorithms or _infer_algorithms(plain),
            "scanned_path": scanned_path,
            "results": plain,
        }
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif fmt == "csv":
        _write_csv(target, plain)
    elif fmt == "txt":
        target.write_text(_to_text(plain), encoding="utf-8")
    elif fmt in {"manifest", "checksums", "checksum"}:
        target.write_text(_to_manifest(plain), encoding="utf-8")
    else:
        raise ValueError("Export format must be json, csv, txt, or manifest")
    return target


def _extension_for(fmt: str) -> str:
    return "txt" if fmt in {"manifest", "checksums", "checksum"} else fmt


def _write_csv(path: Path, plain: Any) -> None:
    rows = _flatten_rows(plain)
    with path.open("w", newline="", encoding="utf-8") as handle:
        if not rows:
            handle.write("")
            return
        fieldnames = sorted({key for row in rows for key in row})
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _flatten_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        rows: list[dict[str, Any]] = []
        for item in value:
            rows.extend(_flatten_rows(item))
        return rows
    if isinstance(value, dict):
        if "files" in value and isinstance(value["files"], list):
            return _flatten_rows(value["files"])
        flat: dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(item, dict):
                for child_key, child in item.items():
                    flat[f"{key}.{child_key}"] = child
            elif isinstance(item, list):
                flat[key] = json.dumps(item)
            else:
                flat[key] = item
        return [flat]
    return [{"value": value}]


def _to_text(value: Any) -> str:
    return json.dumps(value, indent=2)


def _to_manifest(value: Any) -> str:
    rows = _flatten_rows(value)
    lines: list[str] = []
    for row in rows:
        digest = row.get("hash_value") or row.get("hash") or row.get("hashes.sha256") or row.get("hashes.md5")
        name = row.get("path") or row.get("relative_path") or row.get("name") or row.get("file_name")
        if digest and name:
            lines.append(f"{digest}  {name}")
    return "\n".join(lines) + ("\n" if lines else "")


def _infer_algorithms(value: Any) -> list[str]:
    if isinstance(value, dict):
        if "algorithms" in value and isinstance(value["algorithms"], list):
            return [str(item) for item in value["algorithms"]]
        if "algorithm" in value:
            return [str(value["algorithm"])]
        for item in value.values():
            found = _infer_algorithms(item)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = _infer_algorithms(item)
            if found:
                return found
    return []
