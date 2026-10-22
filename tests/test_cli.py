"""Tests for the Click entry point."""

from click.testing import CliRunner
from demon.cli import cli


def test_version() -> None:
    """Print the project version."""
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "D.E.M.O.N." in result.output


def test_analyse_help() -> None:
    """Expose analyse help."""
    result = CliRunner().invoke(cli, ["analyse", "--help"])
    assert result.exit_code == 0
    assert "--no-ai" in result.output

