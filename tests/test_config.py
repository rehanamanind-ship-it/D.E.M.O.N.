"""Tests for configuration."""

from demon.config import Config


def test_defaults_and_round_trip(tmp_path, monkeypatch) -> None:
    """Test default values and persistence."""
    monkeypatch.setattr(Config, "path", classmethod(lambda cls: tmp_path / "config.json"))
    config = Config()
    config.default_model = "x.gguf"
    config.save()
    assert Config.load().default_model == "x.gguf"


def test_unknown_key() -> None:
    """Reject unknown configuration keys."""
    try:
        Config().set_value("missing", "x")
    except KeyError:
        return
    raise AssertionError("unknown key was accepted")

