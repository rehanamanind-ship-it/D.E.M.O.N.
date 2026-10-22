"""Rich terminal presentation helpers."""

from contextlib import contextmanager
from typing import Any, Iterator
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table

console = Console()


def print_banner() -> None:
    """Print the branded banner."""
    console.print("[bold red]D.E.M.O.N.[/bold red] [cyan]made by Rehan Aman[/cyan]")


def print_success(msg: str) -> None:
    """Print a success message."""
    console.print(f"[bold green]✓[/bold green] {msg}")


def print_error(msg: str) -> None:
    """Print an error message."""
    console.print(f"[bold red]✗[/bold red] {msg}", style="red")


def print_warning(msg: str) -> None:
    """Print a warning message."""
    console.print(f"[bold yellow]⚠[/bold yellow] {msg}")


def print_info(msg: str) -> None:
    """Print an informational message."""
    console.print(f"[cyan]{msg}[/cyan]")


def print_static_report(info: dict[str, Any]) -> None:
    """Render static analysis metadata."""
    table = Table(title="Static Report", box=None)
    table.add_column("Field")
    table.add_column("Value")
    for key in ("format", "entry", "sha256", "size", "entropy"):
        if key in info:
            table.add_row(key.title(), str(info[key]))
    table.add_row("Suspicious strings", ", ".join(info.get("suspicious_strings", [])) or "none")
    console.print(table)


def print_ai_verdict(verdict: str) -> None:
    """Render an AI verdict panel using its classification keyword."""
    lowered = verdict.lower()
    colour = "red" if "malicious" in lowered else "yellow" if "suspicious" in lowered else "green"
    console.print(Panel(verdict, title="AI Verdict", style=colour))


def print_models_table(rows: list[dict[str, Any]]) -> None:
    """Render available model rows."""
    table = Table(box=None)
    for column in ("Name", "Path", "Size", "Active?"):
        table.add_column(column)
    for row in rows:
        table.add_row(str(row["name"]), str(row["path"]), str(row["size"]), str(row["active"]))
    console.print(table)


def print_cache_table(rows: list[dict[str, Any]]) -> None:
    """Render cache rows."""
    table = Table(box=None)
    for column in ("SHA-256", "File size", "Model", "Timestamp"):
        table.add_column(column)
    for row in rows:
        table.add_row(*(str(row.get(key, "")) for key in ("sha256", "size", "model", "timestamp")))
    console.print(table)


@contextmanager
def make_spinner(label: str) -> Iterator[None]:
    """Display a progress spinner while a block runs."""
    with console.status(label):
        yield

