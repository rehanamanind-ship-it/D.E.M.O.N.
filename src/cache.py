"""Cache static and AI analysis results."""

import hashlib
import json
from pathlib import Path
from typing import Any


def cache_dir() -> Path:
    """Return and create the cache directory."""
    path = Path.home() / ".cache" / "demon"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_cache_path(sha256: str) -> Path:
    """Return the cache file for a SHA-256 digest."""
    return cache_dir() / f"{sha256}.json"


def cache_result(sha256: str, report: str, info: dict[str, Any], ai_verdict: str | None) -> Path:
    """Write an analysis result to the cache."""
    path = get_cache_path(sha256)
    path.write_text(json.dumps({"report": report, "info": info, "ai_verdict": ai_verdict}, indent=2), encoding="utf-8")
    return path


def load_cache(sha256: str) -> dict[str, Any] | None:
    """Load a cached result when its JSON is valid."""
    path = get_cache_path(sha256)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def delete_cache(sha256: str) -> bool:
    """Delete one cache entry and report whether it existed."""
    path = get_cache_path(sha256)
    if not path.exists():
        return False
    path.unlink()
    return True


def file_sha256(path: Path) -> str:
    """Calculate a file's SHA-256 digest."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

