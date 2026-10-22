"""Tests for static analysis helpers."""

from pathlib import Path
from demon.analysis import compute_entropy, extract_ascii_strings, detect_script


def test_entropy_and_strings() -> None:
    """Test entropy and printable strings."""
    assert compute_entropy(b"") == 0
    assert extract_ascii_strings(b"\0hello world\0") == ["hello world"]


def test_script_detection() -> None:
    """Test shell detection."""
    assert detect_script(Path("x.sh"), b"echo hi")["format"] == "shell"

