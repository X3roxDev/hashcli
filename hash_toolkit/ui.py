"""Terminal UI helpers built on Rich with plain-text fallback."""

from __future__ import annotations

from collections.abc import Callable
import sys
from typing import Any

from .algorithms import ALGORITHMS, security_warning
from .config import APP_NAME, DEFAULT_ALGORITHM, VERSION
from .models import ComparisonResult, DuplicateGroup, FolderScanResult, HashResult, IntegrityReport, VerificationResult
from .utils import format_bytes, format_speed

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeElapsedColumn
    from rich.prompt import Confirm, Prompt
    from rich.table import Table

    RICH_AVAILABLE = True
except ModuleNotFoundError:
    Console = None  # type: ignore[assignment]
    RICH_AVAILABLE = False


for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

console = Console(width=88, highlight=False, legacy_windows=False) if RICH_AVAILABLE else None

GITHUB_URL = "https://github.com/X3roxDev"
SEPARATOR = "=" * 76
HASH_TOOLKIT_BANNER = r"""
 ██░ ██  ▄▄▄        ██████  ██░ ██  ▄████▄   ██▓     ██▓
▓██░ ██▒▒████▄    ▒██    ▒ ▓██░ ██▒▒██▀ ▀█  ▓██▒    ▓██▒
▒██▀▀██░▒██  ▀█▄  ░ ▓██▄   ▒██▀▀██░▒▓█    ▄ ▒██░    ▒██▒
░▓█ ░██ ░██▄▄▄▄██   ▒   ██▒░▓█ ░██ ▒▓▓▄ ▄██▒▒██░    ░██░
░▓█▒░██▓ ▓█   ▓██▒▒██████▒▒░▓█▒░██▓▒ ▓███▀ ░░██████▒░██░
 ▒ ░░▒░▒ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░ ░▒ ▒  ░░ ▒░▓  ░░▓
 ▒ ░▒░ ░  ▒   ▒▒ ░░ ░▒  ░ ░ ▒ ░▒░ ░  ░  ▒   ░ ░ ▒  ░ ▒ ░
 ░  ░░ ░  ░   ▒   ░  ░  ░   ░  ░░ ░░          ░ ░    ▒ ░
 ░  ░  ░      ░  ░      ░   ░  ░  ░░ ░          ░  ░ ░
                                   ░
""".strip("\n")


def print_error(message: str) -> None:
    """Print a formatted error panel or plain error text."""

    if console:
        console.print(Panel(message, title="Error", border_style="white"))
    else:
        print(f"ERROR: {message}")


def print_warning(message: str | None) -> None:
    """Print a warning when one is present."""

    if not message:
        return
    if console:
        console.print(Panel(message, title="Security Warning", border_style="white"))
    else:
        print(f"WARNING: {message}")


def render_hash_results(results: list[HashResult]) -> None:
    """Render file or text hash results."""

    print_warning(security_warning([item.algorithm for item in results]))
    if console:
        table = Table(title="Hash Results", box=box.SIMPLE_HEAVY)
        for column in ("Source", "Size", "Algorithm", "Hash", "Duration", "Speed", "Modified", "Status"):
            table.add_column(column, overflow="fold")
        for item in results:
            table.add_row(
                item.path or item.name,
                format_bytes(item.size),
                ALGORITHMS[item.algorithm].display_name,
                item.hash_value,
                f"{item.duration_seconds:.4f}s",
                format_speed(item.speed_bytes_per_second),
                item.modified_at or "",
                item.status,
            )
        console.print(table)
    else:
        for item in results:
            print(f"{item.algorithm}: {item.hash_value}  {item.path or item.name}")


def render_folder_scan(scan: FolderScanResult) -> None:
    """Render a folder scan summary and file table."""

    print_warning(security_warning(scan.algorithms))
    if console:
        summary = (
            f"Root: {scan.root}\n"
            f"Files: {scan.total_files}\n"
            f"Size: {format_bytes(scan.total_size)}\n"
            f"Folder hash ({scan.folder_hash_algorithm}): {scan.folder_hash}\n"
            f"Duration: {scan.duration_seconds:.3f}s"
        )
        console.print(Panel(summary, title="Folder Scan Summary", border_style="white"))
        table = Table(box=box.SIMPLE)
        table.add_column("Relative Path", overflow="fold")
        table.add_column("Size", justify="right")
        table.add_column("Modified")
        table.add_column("Status")
        table.add_column("Hashes", overflow="fold")
        for item in scan.files:
            table.add_row(
                item.relative_path,
                format_bytes(item.size),
                item.modified_at or "",
                item.status,
                "\n".join(f"{alg}: {digest}" for alg, digest in item.hashes.items()),
            )
        console.print(table)
    else:
        print(f"Folder hash ({scan.folder_hash_algorithm}): {scan.folder_hash}")
        for item in scan.files:
            print(f"{item.relative_path}: {item.hashes}")


def render_comparison(result: ComparisonResult) -> None:
    """Render a comparison result."""

    status = "MATCH" if result.match else "MISMATCH"
    if console:
        table = Table(title=f"Comparison: {status}", box=box.SIMPLE_HEAVY)
        table.add_column("Field")
        table.add_column("Value", overflow="fold")
        table.add_row("Left", result.left_name)
        table.add_row("Right", result.right_name)
        table.add_row("Algorithm", ALGORITHMS[result.algorithm].display_name)
        if result.left_size is not None:
            table.add_row("Left size", format_bytes(result.left_size))
        if result.right_size is not None:
            table.add_row("Right size", format_bytes(result.right_size))
        table.add_row("Left hash", result.left_hash)
        table.add_row("Right hash", result.right_hash)
        table.add_row("Result", status)
        console.print(table)
    else:
        print(status)
        print(f"{result.left_hash}\n{result.right_hash}")


def render_verification(results: list[VerificationResult]) -> None:
    """Render checksum verification results."""

    if console:
        table = Table(title="Verification Results", box=box.SIMPLE_HEAVY)
        for column in ("File", "Algorithm", "Expected", "Actual", "Status", "Error"):
            table.add_column(column, overflow="fold")
        for item in results:
            table.add_row(item.file_name, item.algorithm, item.expected_hash, item.actual_hash or "", item.status, item.error or "")
        console.print(table)
    else:
        for item in results:
            print(f"{item.status}: {item.file_name}")


def render_duplicates(groups: list[DuplicateGroup]) -> None:
    """Render duplicate groups."""

    if console:
        total_recoverable = sum(group.recoverable_size for group in groups)
        console.print(Panel(f"Groups: {len(groups)}\nPotential recoverable space: {format_bytes(total_recoverable)}", title="Duplicate Summary"))
        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("Hash", overflow="fold")
        table.add_column("Count", justify="right")
        table.add_column("File size", justify="right")
        table.add_column("Recoverable", justify="right")
        table.add_column("Files", overflow="fold")
        for group in groups:
            table.add_row(
                group.hash_value,
                str(group.duplicate_count),
                format_bytes(group.file_size),
                format_bytes(group.recoverable_size),
                "\n".join(group.files),
            )
        console.print(table)
    else:
        for group in groups:
            print(f"{group.hash_value}: {group.files}")


def render_integrity(report: IntegrityReport) -> None:
    """Render an integrity report."""

    if console:
        summary = (
            f"Added: {len(report.added)}\n"
            f"Removed: {len(report.removed)}\n"
            f"Modified: {len(report.modified)}\n"
            f"Renamed or moved: {len(report.moved_or_renamed)}\n"
            f"Unchanged: {report.unchanged}\n"
            f"Errors: {len(report.errors)}"
        )
        console.print(Panel(summary, title="Integrity Report", border_style="white"))
    else:
        print(report)


def render_algorithms() -> None:
    """Render supported algorithms."""

    if console:
        table = Table(title="Supported Algorithms", box=box.SIMPLE_HEAVY)
        for column in ("Name", "Display", "Security Level", "Digest Bytes", "Dependency", "Notes"):
            table.add_column(column)
        for name, spec in ALGORITHMS.items():
            table.add_row(name, spec.display_name, spec.category, str(spec.digest_size or ""), spec.requires_package or "", spec.description)
        console.print(table)
    else:
        for name, spec in ALGORITHMS.items():
            print(f"{name:10} {spec.display_name:10} {spec.category}")


def rich_file_progress(total: int) -> tuple[Any, Callable[[int, int], None]]:
    """Create a Rich progress object and callback for file hashing."""

    if not RICH_AVAILABLE:
        return None, lambda _done, _total: None
    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )
    task_id = progress.add_task("Hashing", total=total)

    def update(done: int, _total: int) -> None:
        progress.update(task_id, completed=done)

    return progress, update


def rich_count_progress(total: int, description: str) -> tuple[Any, Callable[[int, int], None]]:
    """Create a Rich progress object and callback for counted tasks."""

    if not RICH_AVAILABLE:
        return None, lambda _done, _total: None
    progress = Progress(TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), TimeElapsedColumn(), console=console)
    task_id = progress.add_task(description, total=max(total, 1))

    def update(done: int, _total: int) -> None:
        progress.update(task_id, total=max(_total, 1), completed=done)

    return progress, update


def interactive_menu(actions: dict[str, Callable[[], Any]], stats_provider: Callable[[], dict[str, Any]] | None = None) -> None:
    """Open the keyboard-friendly interactive menu."""

    options = {
        "1": ("Hash a file", actions["file"]),
        "2": ("Hash text", actions["text"]),
        "3": ("Hash a folder", actions["folder"]),
        "4": ("Compare files", actions["compare_files"]),
        "5": ("Compare with known hash", actions["compare_hash"]),
        "6": ("Verify checksum manifest", actions["verify"]),
        "7": ("Find duplicate files", actions["duplicates"]),
        "8": ("Create integrity baseline", actions["baseline_create"]),
        "9": ("Check integrity baseline", actions["baseline_check"]),
        "10": ("View supported algorithms", actions["algorithms"]),
        "11": ("Export results", actions["export"]),
        "0": ("Exit", lambda: "exit"),
    }
    while True:
        if console:
            _reset_screen()
            console.print(HASH_TOOLKIT_BANNER, style="bold bright_white")
            console.print(f"[bold white]{APP_NAME}[/bold white] v{VERSION}")
            console.print(f"[bold white]GitHub:[/bold white] {GITHUB_URL}")
            console.print(SEPARATOR, style="dim white")
            _render_stats(stats_provider() if stats_provider else {})
            console.print()
            console.print("[white]Menu[/white]")
            for key, (label, _) in options.items():
                console.print(f" [{key}] {label}", style="white")
            console.print()
            console.print("[bold cyan]Select option>[/bold cyan] ", end="")
            choice = input().strip() or "0"
        else:
            _reset_screen()
            print(HASH_TOOLKIT_BANNER)
            print(APP_NAME)
            print(f"GitHub: {GITHUB_URL}")
            print(SEPARATOR)
            _print_plain_stats(stats_provider() if stats_provider else {})
            print()
            print("Menu")
            for key, (label, _) in options.items():
                print(f" [{key}] {label}")
            print()
            choice = input("\033[96mSelect option>\033[0m ").strip() or "0"
        action = options.get(choice)
        if action is None:
            print_error("Invalid menu selection")
            continue
        try:
            result = action[1]()
            if result == "exit":
                break
            if console:
                console.print()
                console.print("[dim]Press Enter to continue...[/dim]", end="")
                input()
            else:
                input("\nPress Enter to continue...")
        except KeyboardInterrupt:
            if console:
                console.print("\nCancelled.")
            else:
                print("\nCancelled.")
        except Exception as exc:
            print_error(str(exc))
            if console:
                console.print("[dim]Press Enter to continue...[/dim]", end="")
                input()
            else:
                input("Press Enter to continue...")


def prompt_text(label: str, default: str | None = None) -> str:
    """Prompt for text with Rich fallback."""

    if RICH_AVAILABLE:
        return Prompt.ask(label, default=default) if default is not None else Prompt.ask(label)
    suffix = f" [{default}]" if default else ""
    return input(f"{label}{suffix}: ") or (default or "")


def prompt_confirm(label: str, default: bool = False) -> bool:
    """Prompt for yes/no confirmation."""

    if RICH_AVAILABLE:
        return Confirm.ask(label, default=default)
    answer = input(f"{label} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not answer else answer.startswith("y")


def _render_stats(stats: dict[str, Any]) -> None:
    if not console:
        return
    console.print(
        "[green]Total:[/green] {total}  "
        "[green]Average:[/green] {average}  "
        "[yellow]Weak:[/yellow] {weak}  "
        "[red]Errors:[/red] {errors}  "
        "[cyan]Secure:[/cyan] {secure}".format(
            total=stats.get("total", 0),
            average=stats.get("average", "0"),
            weak=stats.get("weak", 0),
            errors=stats.get("errors", 0),
            secure=stats.get("secure", 0),
        )
    )


def _print_plain_stats(stats: dict[str, Any]) -> None:
    print(
        "Total: {total}  Average: {average}  Weak: {weak}  Errors: {errors}  Secure: {secure}".format(
            total=stats.get("total", 0),
            average=stats.get("average", "0"),
            weak=stats.get("weak", 0),
            errors=stats.get("errors", 0),
            secure=stats.get("secure", 0),
        )
    )


def _reset_screen() -> None:
    """Clear the visible terminal and return the cursor to the top-left corner."""

    sys.stdout.write("\033[2J\033[H\033[3J")
    sys.stdout.flush()
