"""Manage persistent D.E.M.O.N. configuration."""

from dataclasses import asdict, dataclass, fields
import json
from pathlib import Path
from typing import Any


@dataclass
class Config:
    """Store analyser and model settings."""

    default_model: str = ""
    suspicious_keywords: list[str] | None = None
    max_strings: int = 200
    entropy_threshold: float = 7.2
    cache_enabled: bool = True
    ai_params: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        """Fill mutable settings with safe defaults."""
        if self.suspicious_keywords is None:
            self.suspicious_keywords = ["powershell", "cmd.exe", "invoke", "download", "http://", "https://", "base64"]
        if self.ai_params is None:
            self.ai_params = {"temperature": 0.2, "max_tokens": 256}

    @classmethod
    def path(cls) -> Path:
        """Return the user configuration path."""
        return Path.home() / ".config" / "demon" / "config.json"

    @classmethod
    def load(cls) -> "Config":
        """Load configuration or return defaults when it does not exist."""
        path = cls.path()
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid configuration: {path}") from exc
        known = {field.name for field in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})

    def save(self) -> None:
        """Persist configuration as readable JSON."""
        path = self.path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")

    def set_value(self, key: str, value: str) -> None:
        """Cast and set a named configuration field."""
        field_types = {field.name: field.type for field in fields(self)}
        if key not in field_types:
            raise KeyError(key)
        current = getattr(self, key)
        if isinstance(current, bool):
            cast: Any = value.lower() in {"1", "true", "yes", "on"}
            if value.lower() not in {"0", "1", "true", "false", "yes", "no", "on", "off"}:
                raise ValueError(f"Invalid boolean: {value}")
        elif isinstance(current, int):
            cast = int(value)
        elif isinstance(current, float):
            cast = float(value)
        elif isinstance(current, (list, dict)):
            cast = json.loads(value)
        else:
            cast = value
        setattr(self, key, cast)

