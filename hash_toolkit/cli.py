"""Command-line interface for HashCLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .algorithms import ALGORITHMS, parse_algorithms
from .comparator import compare_file_with_hash, compare_files
from .config import DEFAULT_ALGORITHM, DEFAULT_CHUNK_SIZE
from .duplicates import find_duplicates
from .exporter import export_results
from .file_hasher import hash_file
from .folder_hasher import scan_folder
from .integrity import check_baseline, create_baseline
from .text_hasher import copy_to_clipboard, hash_text, hash_text_file
from .ui import (
    console,
    interactive_menu,
    print_error,
    prompt_confirm,
    prompt_text,
    render_algorithms,
    render_comparison,
    render_duplicates,
    render_folder_scan,
    render_hash_results,
    render_integrity,
    render_verification,
    rich_count_progress,
    rich_file_progress,
)
from .utils import parse_size_filter
from .verifier import verify_manifest

try:
    import typer

    TYPER_AVAILABLE = True
except ModuleNotFoundError:
    typer = None  # type: ignore[assignment]
    TYPER_AVAILABLE = False


def main(argv: list[str] | None = None) -> None:
    """Run the CLI."""

    args = sys.argv[1:] if argv is None else argv
    if TYPER_AVAILABLE:
        if not args:
            run_interactive_menu()
            return
        try:
            _build_typer_app()(args=args, prog_name="hash_toolkit.py", standalone_mode=False)
        except SystemExit:
            raise
        except Exception as exc:
            print_error(str(exc))
            raise SystemExit(1) from exc
    else:
        _run_argparse(args)


def run_interactive_menu() -> None:
    """Launch the interactive terminal menu."""

    state: dict[str, Any] = {"last": None, "total": 0, "duration_total": 0.0, "weak": 0, "secure": 0, "errors": 0}

    def file_action() -> None:
        path = Path(prompt_text("File path"))
        algorithms = prompt_text("Algorithms", DEFAULT_ALGORITHM)
        progress, callback = rich_file_progress(path.stat().st_size) if path.exists() else (None, None)
        if progress:
            with progress:
                result = hash_file(path, algorithms=algorithms, progress_callback=callback)
        else:
            result = hash_file(path, algorithms=algorithms)
        state["last"] = result
        _record_interactive_stats(state, result)
        render_hash_results(result)

    def text_action() -> None:
        text = prompt_text("Text")
        algorithm = prompt_text("Algorithm", DEFAULT_ALGORITHM)
        encoding = prompt_text("Encoding", "utf-8")
        result = hash_text(text, algorithms=algorithm, encoding=encoding)
        state["last"] = result
        _record_interactive_stats(state, result)
        render_hash_results(result)
        if len(result) == 1 and prompt_confirm("Copy hash to clipboard?", False):
            copy_to_clipboard(result[0].hash_value)

    def folder_action() -> None:
        path = prompt_text("Folder path")
        algorithm = prompt_text("Algorithm", DEFAULT_ALGORITHM)
        progress, callback = rich_count_progress(1, "Hashing folder")
        if progress:
            with progress:
                result = scan_folder(path, algorithm=algorithm, progress_callback=callback)
        else:
            result = scan_folder(path, algorithm=algorithm)
        state["last"] = result
        _record_interactive_stats(state, result)
        render_folder_scan(result)

    def compare_files_action() -> None:
        result = compare_files(prompt_text("First file"), prompt_text("Second file"), algorithm=prompt_text("Algorithm", DEFAULT_ALGORITHM))
        state["last"] = result
        _record_interactive_stats(state, result)
        render_comparison(result)

    def compare_hash_action() -> None:
        result = compare_file_with_hash(prompt_text("File"), prompt_text("Expected hash"), algorithm=prompt_text("Algorithm", DEFAULT_ALGORITHM))
        state["last"] = result
        _record_interactive_stats(state, result)
        render_comparison(result)

    def verify_action() -> None:
        result = verify_manifest(prompt_text("Checksum manifest"))
        state["last"] = result
        _record_interactive_stats(state, result)
        render_verification(result)

    def duplicates_action() -> None:
        result = find_duplicates(prompt_text("Folder"), algorithm=prompt_text("Algorithm", DEFAULT_ALGORITHM))
        state["last"] = result
        _record_interactive_stats(state, result)
        render_duplicates(result)

    def baseline_create_action() -> None:
        output = create_baseline(prompt_text("Folder"), algorithm=prompt_text("Algorithm", DEFAULT_ALGORITHM))
        state["last"] = {"baseline": str(output)}
        _record_interactive_stats(state, state["last"])
        if console:
            console.print(f"Baseline written to {output}")
        else:
            print(f"Baseline written to {output}")

    def baseline_check_action() -> None:
        result = check_baseline(prompt_text("Folder"), prompt_text("Baseline JSON"))
        state["last"] = result
        _record_interactive_stats(state, result)
        render_integrity(result)

    def export_action() -> None:
        if state["last"] is None:
            print_error("No results are available to export in this session.")
            return
        target = export_results(state["last"], export_format=prompt_text("Format", "json"))
        if console:
            console.print(f"Exported to {target}")
        else:
            print(f"Exported to {target}")

    interactive_menu(
        {
            "file": file_action,
            "text": text_action,
            "folder": folder_action,
            "compare_files": compare_files_action,
            "compare_hash": compare_hash_action,
            "verify": verify_action,
            "duplicates": duplicates_action,
            "baseline_create": baseline_create_action,
            "baseline_check": baseline_check_action,
            "algorithms": render_algorithms,
            "export": export_action,
        },
        stats_provider=lambda: _interactive_stats_snapshot(state),
    )


def _record_interactive_stats(state: dict[str, Any], result: Any) -> None:
    state["total"] += 1
    algorithms = _extract_algorithms(result)
    state["weak"] += sum(1 for item in algorithms if item in {"md5", "sha1", "crc32"})
    state["secure"] += sum(1 for item in algorithms if ALGORITHMS.get(item) and ALGORITHMS[item].category == "cryptographic")
    state["errors"] += _extract_error_count(result)
    duration = _extract_duration(result)
    if duration:
        state["duration_total"] += duration


def _interactive_stats_snapshot(state: dict[str, Any]) -> dict[str, Any]:
    total = int(state.get("total", 0))
    duration_total = float(state.get("duration_total", 0.0))
    average = f"{duration_total / total:.3f}s" if total else "0"
    return {
        "total": total,
        "average": average,
        "weak": state.get("weak", 0),
        "errors": state.get("errors", 0),
        "secure": state.get("secure", 0),
    }


def _extract_algorithms(result: Any) -> list[str]:
    if isinstance(result, list):
        algorithms: list[str] = []
        for item in result:
            algorithms.extend(_extract_algorithms(item))
        return algorithms
    if isinstance(result, dict):
        value = result.get("algorithm") or result.get("folder_hash_algorithm")
        return [value] if isinstance(value, str) else []
    algorithm = getattr(result, "algorithm", None)
    if isinstance(algorithm, str):
        return [algorithm]
    algorithms = getattr(result, "algorithms", None)
    if isinstance(algorithms, list):
        return [item for item in algorithms if isinstance(item, str)]
    folder_algorithm = getattr(result, "folder_hash_algorithm", None)
    return [folder_algorithm] if isinstance(folder_algorithm, str) else []


def _extract_error_count(result: Any) -> int:
    if isinstance(result, list):
        return sum(_extract_error_count(item) for item in result)
    errors = getattr(result, "errors", None)
    if isinstance(errors, list):
        return len(errors)
    status = getattr(result, "status", None)
    if isinstance(status, str) and status.lower() not in {"completed", "verified"}:
        return 1
    error = getattr(result, "error", None)
    return 1 if error else 0


def _extract_duration(result: Any) -> float:
    if isinstance(result, list):
        durations = [_extract_duration(item) for item in result]
        return max(durations) if durations else 0.0
    for attribute in ("duration_seconds",):
        value = getattr(result, attribute, None)
        if isinstance(value, int | float):
            return float(value)
    return 0.0


def _build_typer_app() -> Any:
    app = typer.Typer(help="Professional cross-platform hash toolkit.", no_args_is_help=False)
    baseline_app = typer.Typer(help="Create and check integrity baselines.")
    app.add_typer(baseline_app, name="baseline")

    @app.command("file")
    def file_command(
        path: Path,
        algorithm: str = typer.Option(DEFAULT_ALGORITHM, "--algorithm", "-a"),
        algorithms: str | None = typer.Option(None, "--algorithms", "-A"),
        chunk_size: int = typer.Option(DEFAULT_CHUNK_SIZE, "--chunk-size"),
        blake3_digest_length: int | None = typer.Option(None, "--blake3-digest-length"),
        export: str | None = typer.Option(None, "--export"),
        output: Path | None = typer.Option(None, "--output"),
    ) -> None:
        selected = parse_algorithms(algorithm=algorithm, algorithms=algorithms)
        progress, callback = rich_file_progress(path.stat().st_size)
        with progress if progress else _null_context():
            results = hash_file(
                path,
                algorithms=selected,
                chunk_size=chunk_size,
                progress_callback=callback,
                blake3_digest_length=blake3_digest_length,
            )
        render_hash_results(results)
        _maybe_export(results, export, output, selected, str(path), "hash_report")

    @app.command("text")
    def text_command(
        text: str | None = typer.Argument(None),
        text_file: Path | None = typer.Option(None, "--text-file"),
        algorithm: str = typer.Option(DEFAULT_ALGORITHM, "--algorithm", "-a"),
        algorithms: str | None = typer.Option(None, "--algorithms", "-A"),
        encoding: str = typer.Option("utf-8", "--encoding"),
        expected_hash: str | None = typer.Option(None, "--expected-hash"),
        blake3_digest_length: int | None = typer.Option(None, "--blake3-digest-length"),
        copy: bool = typer.Option(False, "--copy"),
        export: str | None = typer.Option(None, "--export"),
        output: Path | None = typer.Option(None, "--output"),
    ) -> None:
        selected = parse_algorithms(algorithm=algorithm, algorithms=algorithms)
        results = (
            hash_text_file(text_file, algorithms=selected, encoding=encoding, blake3_digest_length=blake3_digest_length)
            if text_file
            else hash_text(text or "", algorithms=selected, encoding=encoding, blake3_digest_length=blake3_digest_length)
        )
        render_hash_results(results)
        if expected_hash and len(results) == 1:
            from .text_hasher import compare_text_with_hash

            comparison = compare_text_with_hash(text or "", expected_hash, algorithm=selected[0], encoding=encoding)
            render_comparison(comparison)
        if copy and len(results) == 1:
            copy_to_clipboard(results[0].hash_value)
        _maybe_export(results, export, output, selected, str(text_file or "<text>"), "hash_report")

    @app.command("folder")
    def folder_command(
        path: Path,
        algorithm: str = typer.Option(DEFAULT_ALGORITHM, "--algorithm", "-a"),
        algorithms: str | None = typer.Option(None, "--algorithms", "-A"),
        include_hidden: bool = typer.Option(False, "--include-hidden"),
        follow_symlinks: bool = typer.Option(False, "--follow-symlinks"),
        ignore_extensions: str | None = typer.Option(None, "--ignore-extensions"),
        ignore_folders: str | None = typer.Option(None, "--ignore-folders"),
        min_size: str | None = typer.Option(None, "--min-size"),
        max_size: str | None = typer.Option(None, "--max-size"),
        workers: int = typer.Option(4, "--workers", "-w"),
        sort_by: str = typer.Option("path", "--sort-by"),
        blake3_digest_length: int | None = typer.Option(None, "--blake3-digest-length"),
        export: str | None = typer.Option(None, "--export"),
        output: Path | None = typer.Option(None, "--output"),
    ) -> None:
        selected = parse_algorithms(algorithm=algorithm, algorithms=algorithms)
        progress, callback = rich_count_progress(1, "Hashing folder")
        with progress if progress else _null_context():
            result = scan_folder(
                path,
                algorithms=selected,
                include_hidden=include_hidden,
                follow_symlinks=follow_symlinks,
                ignore_extensions=_split_csv(ignore_extensions),
                ignore_folders=_split_csv(ignore_folders),
                min_size=parse_size_filter(min_size),
                max_size=parse_size_filter(max_size),
                workers=workers,
                sort_by=sort_by,
                blake3_digest_length=blake3_digest_length,
                progress_callback=callback,
            )
        render_folder_scan(result)
        _maybe_export(result, export, output, selected, str(path), "folder_manifest")

    @app.command("compare")
    def compare_command(
        left: Path,
        right: Path,
        algorithm: str = typer.Option(DEFAULT_ALGORITHM, "--algorithm", "-a"),
    ) -> None:
        render_comparison(compare_files(left, right, algorithm=algorithm))

    @app.command("compare-hash")
    def compare_hash_command(
        path: Path,
        expected_hash: str,
        algorithm: str = typer.Option(DEFAULT_ALGORITHM, "--algorithm", "-a"),
    ) -> None:
        render_comparison(compare_file_with_hash(path, expected_hash, algorithm=algorithm))

    @app.command("verify")
    def verify_command(
        manifest: Path,
        base_dir: Path | None = typer.Option(None, "--base-dir"),
        algorithm: str | None = typer.Option(None, "--algorithm", "-a"),
        export: str | None = typer.Option(None, "--export"),
        output: Path | None = typer.Option(None, "--output"),
    ) -> None:
        results = verify_manifest(manifest, base_dir=base_dir, algorithm=algorithm)
        render_verification(results)
        _maybe_export(results, export, output, [algorithm] if algorithm else [], str(manifest), "verification_report")

    @app.command("duplicates")
    def duplicates_command(
        path: Path,
        algorithm: str = typer.Option(DEFAULT_ALGORITHM, "--algorithm", "-a"),
        include_hidden: bool = typer.Option(False, "--include-hidden"),
        follow_symlinks: bool = typer.Option(False, "--follow-symlinks"),
        export: str | None = typer.Option(None, "--export"),
        output: Path | None = typer.Option(None, "--output"),
    ) -> None:
        groups = find_duplicates(path, algorithm=algorithm, include_hidden=include_hidden, follow_symlinks=follow_symlinks)
        render_duplicates(groups)
        _maybe_export(groups, export, output, [algorithm], str(path), "duplicate_report")

    @baseline_app.command("create")
    def baseline_create_command(
        path: Path,
        algorithm: str = typer.Option(DEFAULT_ALGORITHM, "--algorithm", "-a"),
        output: Path | None = typer.Option(None, "--output"),
    ) -> None:
        target = create_baseline(path, output=output, algorithm=algorithm)
        typer.echo(f"Baseline written to {target}")

    @baseline_app.command("check")
    def baseline_check_command(path: Path, baseline_json: Path) -> None:
        render_integrity(check_baseline(path, baseline_json))

    @app.command("algorithms")
    def algorithms_command() -> None:
        render_algorithms()

    return app


class _null_context:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_args: object) -> None:
        return None


def _maybe_export(data: Any, export_format: str | None, output: Path | None, algorithms: list[str], scanned_path: str, prefix: str) -> None:
    if not export_format:
        return
    target = export_results(data, export_format=export_format, output=output, algorithms=algorithms, scanned_path=scanned_path, prefix=prefix)
    if console:
        console.print(f"Exported to {target}")
    else:
        print(f"Exported to {target}")


def _split_csv(value: str | None) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()] if value else []


def _run_argparse(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description="Professional cross-platform hash toolkit.")
    sub = parser.add_subparsers(dest="command")
    file_parser = sub.add_parser("file")
    file_parser.add_argument("path")
    file_parser.add_argument("--algorithm", "-a", default=DEFAULT_ALGORITHM)
    file_parser.add_argument("--algorithms", "-A")
    text_parser = sub.add_parser("text")
    text_parser.add_argument("text", nargs="?")
    text_parser.add_argument("--algorithm", "-a", default=DEFAULT_ALGORITHM)
    folder_parser = sub.add_parser("folder")
    folder_parser.add_argument("path")
    folder_parser.add_argument("--algorithm", "-a", default=DEFAULT_ALGORITHM)
    compare_parser = sub.add_parser("compare")
    compare_parser.add_argument("left")
    compare_parser.add_argument("right")
    compare_parser.add_argument("--algorithm", "-a", default=DEFAULT_ALGORITHM)
    compare_hash_parser = sub.add_parser("compare-hash")
    compare_hash_parser.add_argument("path")
    compare_hash_parser.add_argument("expected_hash")
    compare_hash_parser.add_argument("--algorithm", "-a", default=DEFAULT_ALGORITHM)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("manifest")
    dup_parser = sub.add_parser("duplicates")
    dup_parser.add_argument("path")
    dup_parser.add_argument("--algorithm", "-a", default=DEFAULT_ALGORITHM)
    sub.add_parser("algorithms")
    if not argv:
        run_interactive_menu()
        return
    args = parser.parse_args(argv)
    try:
        if args.command == "file":
            render_hash_results(hash_file(args.path, algorithm=args.algorithm, algorithms=args.algorithms))
        elif args.command == "text":
            render_hash_results(hash_text(args.text or "", algorithm=args.algorithm))
        elif args.command == "folder":
            render_folder_scan(scan_folder(args.path, algorithm=args.algorithm))
        elif args.command == "compare":
            render_comparison(compare_files(args.left, args.right, algorithm=args.algorithm))
        elif args.command == "compare-hash":
            render_comparison(compare_file_with_hash(args.path, args.expected_hash, algorithm=args.algorithm))
        elif args.command == "verify":
            render_verification(verify_manifest(args.manifest))
        elif args.command == "duplicates":
            render_duplicates(find_duplicates(args.path, algorithm=args.algorithm))
        elif args.command == "algorithms":
            render_algorithms()
        else:
            parser.print_help()
    except Exception as exc:
        print_error(str(exc))
        raise SystemExit(1) from exc
