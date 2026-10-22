"""Static binary and script analysis."""

from pathlib import Path
import math
import re
from typing import Any

from .cache import cache_result, file_sha256, load_cache
from .config import Config


def compute_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for bytes."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts if count)


def extract_ascii_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Extract printable ASCII runs from bytes."""
    return [match.decode("ascii", "ignore") for match in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)]


def filter_suspicious(strings: list[str], keywords: list[str] | None) -> list[str]:
    """Return strings containing configured suspicious keywords."""
    lowered = [keyword.lower() for keyword in (keywords or [])]
    return [item for item in strings if any(keyword in item.lower() for keyword in lowered)]


def detect_script(path: Path, data: bytes) -> dict[str, Any] | None:
    """Detect common shell and script file types."""
    suffixes = {".sh": "shell", ".bash": "shell", ".ps1": "PowerShell", ".py": "Python", ".js": "JavaScript", ".vbs": "VBScript"}
    if path.suffix.lower() in suffixes or data.startswith(b"#!"):
        return {"format": suffixes.get(path.suffix.lower(), "script"), "entry": "script"}
    return None


def analyse_pe(data: bytes) -> dict[str, Any]:
    """Extract basic PE metadata."""
    info: dict[str, Any] = {"format": "PE", "entry": "unknown", "imports": [], "sections": []}
    if data[:2] != b"MZ":
        return info
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        info["entry"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        info["imports"] = [entry.dll.decode(errors="replace") for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
        info["sections"] = [{"name": section.Name.rstrip(b"\0").decode(errors="replace"), "entropy": section.get_entropy()} for section in pe.sections]
    except (ImportError, AttributeError, ValueError):
        info["entry"] = "unparsed"
    return info


def analyse_elf(data: bytes) -> dict[str, Any]:
    """Extract basic ELF metadata."""
    info: dict[str, Any] = {"format": "ELF", "entry": "unknown", "imports": [], "sections": []}
    try:
        from io import BytesIO
        from elftools.elf.elffile import ELFFile
        elf = ELFFile(BytesIO(data))
        info["entry"] = hex(elf.header["e_entry"])
        info["sections"] = [{"name": section.name, "entropy": compute_entropy(section.data())} for section in elf.iter_sections()]
    except (ImportError, ValueError, KeyError, EOFError):
        info["entry"] = "unparsed"
    return info


def analyse_macho(data: bytes) -> dict[str, Any]:
    """Extract basic Mach-O metadata."""
    return {"format": "Mach-O", "entry": "unknown", "imports": [], "sections": []}


def analyse_dotnet(data: bytes) -> dict[str, Any]:
    """Extract basic .NET metadata."""
    return {"format": ".NET", "entry": "CLR", "imports": [], "sections": []}


def static_analysis(path: Path, config: Config) -> tuple[str, dict[str, Any]]:
    """Analyse a file and return a text report plus structured metadata."""
    data = path.read_bytes()
    if data[:2] == b"MZ":
        info = analyse_pe(data)
    elif data[:4] == b"\x7fELF":
        info = analyse_elf(data)
    elif data[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        info = analyse_macho(data)
    elif b"BSJB" in data[:4096] or path.suffix.lower() in {".dll", ".exe"}:
        info = analyse_dotnet(data)
    else:
        info = detect_script(path, data) or {"format": "raw", "entry": "unknown", "imports": [], "sections": []}
    strings = extract_ascii_strings(data)
    info["sha256"] = file_sha256(path)
    info["strings"] = strings[: config.max_strings]
    info["suspicious_strings"] = filter_suspicious(info["strings"], config.suspicious_keywords)
    info["size"] = len(data)
    info["entropy"] = compute_entropy(data)
    report = f"Format: {info['format']}\nEntry: {info['entry']}\nSHA-256: {info['sha256']}\nSuspicious strings: {', '.join(info['suspicious_strings']) or 'none'}"
    return report, info


def analyse_file(file_path: Path, config: Config, use_cache: bool = True) -> dict[str, Any]:
    """Run static analysis and return a complete result dictionary."""
    sha256 = file_sha256(file_path)
    if use_cache and config.cache_enabled:
        cached = load_cache(sha256)
        if cached is not None:
            return cached
    report, info = static_analysis(file_path, config)
    result = {"report": report, "info": info, "ai_verdict": None}
    if use_cache and config.cache_enabled:
        cache_result(sha256, report, info, None)
    return result
