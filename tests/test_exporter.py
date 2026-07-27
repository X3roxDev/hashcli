from __future__ import annotations

import json

from hash_toolkit.exporter import export_results
from hash_toolkit.text_hasher import hash_text


def test_json_export_generation(tmp_path) -> None:
    results = hash_text("hello", algorithm="sha256")
    target = export_results(results, export_format="json", output=tmp_path / "report.json", scanned_path="<text>")
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["application"] == "HashCLI"
    assert data["results"][0]["hash_value"] == results[0].hash_value


def test_manifest_export_generation(tmp_path) -> None:
    results = hash_text("hello", algorithm="sha256")
    target = export_results(results, export_format="manifest", output=tmp_path / "checksums.txt")
    text = target.read_text(encoding="utf-8")
    assert results[0].hash_value in text
