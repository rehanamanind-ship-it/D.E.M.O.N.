"""Click command tree for D.E.M.O.N."""

from dataclasses import asdict
import json
from pathlib import Path
import shutil
import click

from . import __version__
from .ai import ai_analyse, download_model, load_model
from .analysis import analyse_file
from .cache import cache_dir, delete_cache
from .config import Config
from . import output
from .utils import setup_logging, version_text


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True)
@click.pass_context
def cli(ctx: click.Context, version: bool) -> None:
    """Analyse binaries and scripts with local AI."""
    setup_logging()
    if version:
        output.print_banner()
        click.echo(version_text())
    elif ctx.invoked_subcommand is None:
        output.print_banner()
        click.echo(ctx.get_help())


@cli.command()
@click.argument("file", type=click.Path(path_type=Path))
@click.option("--model", type=click.Path(path_type=Path))
@click.option("--no-ai", is_flag=True)
@click.option("--no-cache", is_flag=True)
@click.option("--json", "json_output", is_flag=True)
@click.option("--save", type=click.Path(path_type=Path))
def analyse(file: Path, model: Path | None, no_ai: bool, no_cache: bool, json_output: bool, save: Path | None) -> None:
    """Run static and optional AI analysis."""
    if not file.is_file():
        raise click.ClickException(f"File not found: {file}")
    config = Config.load()
    if model:
        config.default_model = str(model)
    with output.make_spinner("Analysing...") if not json_output else _null_context():
        result = analyse_file(file, config, not no_cache)
        if not no_ai:
            result["ai_verdict"] = ai_analyse(result["report"], config)
    if save:
        save.write_text(json.dumps(result, indent=2), encoding="utf-8")
    if json_output:
        click.echo(json.dumps(result))
    else:
        output.print_static_report(result["info"])
        if no_ai:
            output.print_warning("AI step skipped")
        else:
            output.print_ai_verdict(result["ai_verdict"] or "")


class _null_context:
    """Provide a no-op context manager for JSON mode."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, *_: object) -> None:
        return None


@cli.group()
def model() -> None:
    """Manage local GGUF models."""


@model.command("list")
def model_list() -> None:
    """List discovered models."""
    config = Config.load()
    paths = [Path(config.default_model)] if config.default_model else []
    paths += list(Path("models").glob("*.gguf")) + list((Path.home() / ".cache/demon/models").glob("*.gguf"))
    unique = {path.resolve(): path for path in paths if path.exists()}
    output.print_models_table([{"name": path.name, "path": path, "size": path.stat().st_size, "active": str(path) == config.default_model} for path in unique.values()])


@model.command("set")
@click.argument("path", type=click.Path(path_type=Path))
def model_set(path: Path) -> None:
    """Set the default GGUF model."""
    if not path.is_file() or path.suffix.lower() != ".gguf":
        raise click.ClickException("Model must exist and end in .gguf")
    config = Config.load()
    config.default_model = str(path)
    config.save()
    output.print_success(f"Default model set to {path}")


@model.command("current")
def model_current() -> None:
    """Print the active model path."""
    click.echo(Config.load().default_model)


@model.command("test")
def model_test() -> None:
    """Load the active model and run a smoke test."""
    config = Config.load()
    result = load_model(config.default_model, config)("Reply with the single word READY.", max_tokens=8)
    output.print_success("Loaded " + config.default_model)
    output.print_ai_verdict(result["choices"][0]["text"].strip())


@model.command("download")
@click.argument("repo_id")
def model_download(repo_id: str) -> None:
    """Download a GGUF model."""
    try:
        path = download_model(repo_id, Path("models"))
    except Exception as exc:
        raise click.ClickException(f"No network or download failed: {exc}") from exc
    output.print_success(f"Saved to {path}")


@cli.group()
def cache() -> None:
    """Manage analysis cache."""


@cache.command()
def status() -> None:
    """Show cache statistics."""
    files = list(cache_dir().glob("*.json"))
    click.echo(f"Cache directory: {cache_dir()}\nEntries: {len(files)}\nTotal size: {sum(file.stat().st_size for file in files)}")


@cache.command("list")
def cache_list() -> None:
    """List cache entries."""
    output.print_cache_table([{"sha256": file.stem[:12], "size": file.stat().st_size, "model": "", "timestamp": file.stat().st_mtime} for file in cache_dir().glob("*.json")])


@cache.command()
def clear() -> None:
    """Clear all cache entries after confirmation."""
    if click.confirm("Clear cache?"):
        for file in cache_dir().glob("*.json"):
            file.unlink()
        output.print_success("Cache cleared")


@cache.command("rm")
@click.argument("sha256")
def cache_rm(sha256: str) -> None:
    """Remove one cache entry."""
    if not delete_cache(sha256):
        raise click.ClickException("Cache entry not found")
    output.print_success("Cache entry removed")


@cli.group()
def config() -> None:
    """Manage configuration."""


@config.command()
def show() -> None:
    """Print configuration."""
    click.echo(json.dumps(asdict(Config.load()), indent=2))


@config.command()
@click.argument("key")
def get(key: str) -> None:
    """Print one configuration value."""
    value = asdict(Config.load()).get(key)
    if value is None:
        raise click.ClickException(f"Unknown key: {key}")
    click.echo(json.dumps(value) if isinstance(value, (dict, list)) else value)


@config.command()
@click.argument("key")
@click.argument("value")
def set(key: str, value: str) -> None:
    """Set one configuration value."""
    config_value = Config.load()
    try:
        config_value.set_value(key, value)
        config_value.save()
    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise click.ClickException(str(exc)) from exc
    output.print_success(f"Set {key}")

