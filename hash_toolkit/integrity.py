"""Integrity baseline creation and checking."""

from __future__ import annotations

import json
from pathlib import Path

from .config import VERSION
from .folder_hasher import scan_folder
from .models import FolderFileResult, IntegrityReport, to_plain_data
from .utils import utc_now_iso


def create_baseline(
    root: str | Path,
    *,
    output: str | Path | None = None,
    algorithm: str = "sha256",
) -> Path:
    """Create a JSON integrity baseline for a folder."""

    scan = scan_folder(root, algorithm=algorithm)
    payload = {
        "toolkit_version": VERSION,
        "created_at": utc_now_iso(),
        "root_folder": scan.root,
        "hash_algorithm": scan.folder_hash_algorithm,
        "file_count": scan.total_files,
        "total_size": scan.total_size,
        "folder_hash": scan.folder_hash,
        "files": [to_plain_data(item) for item in scan.files],
        "errors": scan.errors,
    }
    target = Path(output) if output else Path(root) / "baseline.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target


def check_baseline(root: str | Path, baseline_path: str | Path) -> IntegrityReport:
    """Compare a folder against a saved baseline."""

    baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    algorithm = baseline.get("hash_algorithm", "sha256")
    current_scan = scan_folder(root, algorithm=algorithm)
    old_files = {
        item["relative_path"]: FolderFileResult(
            relative_path=item["relative_path"],
            size=int(item.get("size", 0)),
            modified_at=item.get("modified_at"),
            hashes=dict(item.get("hashes", {})),
            status=item.get("status", "completed"),
            error=item.get("error"),
        )
        for item in baseline.get("files", [])
        if isinstance(item, dict) and "relative_path" in item
    }
    new_files = {item.relative_path: item for item in current_scan.files}
    report = IntegrityReport(root=str(Path(root).resolve()), algorithm=algorithm, errors=current_scan.errors)

    for path, old_item in old_files.items():
        new_item = new_files.get(path)
        if new_item is None:
            report.removed.append(old_item)
            continue
        if old_item.hashes.get(algorithm) != new_item.hashes.get(algorithm) or old_item.size != new_item.size:
            report.modified.append({"relative_path": path, "before": to_plain_data(old_item), "after": to_plain_data(new_item)})
        else:
            report.unchanged += 1

    for path, new_item in new_files.items():
        if path not in old_files:
            report.added.append(new_item)

    _detect_moves(report, algorithm)
    return report


def _detect_moves(report: IntegrityReport, algorithm: str) -> None:
    removed_by_hash = {item.hashes.get(algorithm): item for item in report.removed if item.hashes.get(algorithm)}
    still_added: list[FolderFileResult] = []
    moved_removed: set[str] = set()
    for added in report.added:
        digest = added.hashes.get(algorithm)
        removed = removed_by_hash.get(digest)
        if removed and removed.size == added.size:
            report.moved_or_renamed.append({"from": removed.relative_path, "to": added.relative_path, "hash": digest})
            moved_removed.add(removed.relative_path)
        else:
            still_added.append(added)
    report.added = still_added
    report.removed = [item for item in report.removed if item.relative_path not in moved_removed]
