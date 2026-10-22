"""Shared utility helpers."""

import logging
from pathlib import Path
import sys

from . import __version__


def setup_logging() -> None:
    """Configure stderr and analyser.log logging."""
    logger = logging.getLogger("demon")
    if logger.handlers:
        return
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    for handler in (logging.FileHandler("analyser.log"), logging.StreamHandler(sys.stderr)):
        handler.setFormatter(formatter)
        logger.addHandler(handler)


def get_resource_path(rel: str) -> Path:
    """Resolve a resource path for source and frozen executions."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
    return base / rel


def fail(msg: str, code: int = 1) -> None:
    """Raise a Click-friendly user error with the requested exit code."""
    import click

    raise click.exceptions.Exit(code) if click.echo(f"\033[1;31m✗ {msg}\033[0m", err=True) else click.exceptions.Exit(code)


def version_text() -> str:
    """Return the concise version string."""
    return f"D.E.M.O.N. v{__version__} — made by Rehan Aman"

