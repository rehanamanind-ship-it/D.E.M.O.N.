"""Local GGUF model integration."""

from pathlib import Path
from typing import Any

_llama: Any = None


def load_model(path: str | Path, config: Any) -> Any:
    """Load and cache a llama-cpp-python model."""
    global _llama
    if _llama is None:
        from llama_cpp import Llama
        _llama = Llama(model_path=str(path), verbose=False)
    return _llama


def ai_analyse(report: str, config: Any) -> str:
    """Prompt the local model to classify an analysis report."""
    if not config.default_model:
        raise FileNotFoundError("No default model configured")
    model = load_model(config.default_model, config)
    prompt = f"Classify this file as malicious, suspicious, or benign and explain briefly.\n\n{report}"
    result = model(prompt, temperature=config.ai_params.get("temperature", 0.2), max_tokens=config.ai_params.get("max_tokens", 256))
    return result["choices"][0]["text"].strip()


def download_model(repo_id: str, dest_dir: Path) -> Path:
    """Download one GGUF model from Hugging Face."""
    from huggingface_hub import HfApi, hf_hub_download
    dest_dir.mkdir(parents=True, exist_ok=True)
    files = [item.rfilename for item in HfApi().list_repo_tree(repo_id, recursive=True) if item.rfilename.endswith(".gguf")]
    if not files:
        raise ValueError("No GGUF files found in repository")
    filename = files[0]
    downloaded = hf_hub_download(repo_id, filename, local_dir=str(dest_dir))
    return Path(downloaded)
