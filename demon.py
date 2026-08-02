#!/usr/bin/env python3
"""
ultimate_analyser.py - Cross‑platform EXE/script intent analyser with GGUF AI.
Refactored for DRY, separation of concerns, and ETC (Easy To Change).
"""

# ============================================================================
# IMPORTS
# ============================================================================
import os
import sys
import json
import hashlib
import struct
import threading
import logging
import time
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor

# ---------- GUI ----------
try:
    import tkinter as tk
    from tkinter import filedialog, scrolledtext, messagebox, ttk
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# ---------- Binary parsing ----------
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    HAS_ELFFILE = True
except ImportError:
    HAS_ELFFILE = False

try:
    from macholib.MachO import MachO
    from macholib.mach_o import LC_LOAD_DYLIB
    HAS_MACHOLIB = True
except ImportError:
    HAS_MACHOLIB = False

try:
    import dnfile
    HAS_DNFILE = True
except ImportError:
    HAS_DNFILE = False

# ---------- AI (GGUF) ----------
try:
    from llama_cpp import Llama
    HAS_LLAMA = True
except ImportError:
    HAS_LLAMA = False

# ============================================================================
# CONSTANTS & PATHS
# ============================================================================
APP_NAME = "Ultimate EXE Intent Analyser"
CONFIG_FILE = Path(__file__).parent / "config.json"
CACHE_DIR = Path(__file__).parent / "cache"
CACHE_DIR.mkdir(exist_ok=True)
LOG_FILE = Path(__file__).parent / "analyser.log"
ICON_FILE = get_resource_path("app_icon.ico")   # Place your icon file here

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================
@dataclass
class Config:
    """Holds persistent configuration for the application."""
    default_model: Optional[str] = None
    suspicious_keywords: List[str] = None
    max_strings: int = 30
    entropy_threshold: float = 7.0
    cache_enabled: bool = True
    ai_params: Dict[str, Any] = None

    def __post_init__(self):
        if self.suspicious_keywords is None:
            self.suspicious_keywords = [
                "http", "www.", "cmd", "powershell", "/etc/", "temp", "passwd",
                "CreateRemoteThread", "VirtualAlloc", "RegOpenKey", "WMI",
                "ShellExecute", "WinExec", "GetProcAddress", "LoadLibrary"
            ]
        if self.ai_params is None:
            self.ai_params = {
                "max_tokens": 150,
                "temperature": 0.3,
                "top_p": 0.9,
                "n_gpu_layers": -1,
                "verbose": False
            }

    @classmethod
    def load(cls) -> 'Config':
        """Load config from JSON file, or return defaults."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    return cls(**data)
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")
        return cls()

    def save(self) -> None:
        """Save config to JSON file."""
        with open(CONFIG_FILE, "w") as f:
            json.dump(asdict(self), f, indent=2)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
def get_resource_path(relative_path: str) -> Path:
    """
    Return absolute path to a resource (works for frozen executables).
    When bundled with Nuitka (--onefile), sys._MEIPASS contains the temp dir.
    """
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = Path(__file__).parent
    return base_path / relative_path


def compute_entropy(data: bytes) -> float:
    """Return Shannon entropy of the byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for f in freq:
        if f:
            p = f / length
            entropy -= p * (p.bit_length() - 1)  # log2(p)
    return entropy


def extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extract consecutive ASCII strings of at least min_len characters."""
    strings = []
    current = []
    for b in data:
        if 0x20 <= b <= 0x7E:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append(''.join(current))
            current = []
    return strings


def filter_suspicious(strings: List[str], keywords: List[str]) -> List[str]:
    """Return strings containing any keyword (case‑insensitive). Deduped and limited."""
    result = []
    for s in strings:
        lower = s.lower()
        if any(k.lower() in lower for k in keywords):
            result.append(s)
    return sorted(set(result))[:30]


# ============================================================================
# STATIC ANALYSIS – FORMAT‑SPECIFIC FUNCTIONS
# ============================================================================
def analyse_pe(data: bytes) -> Dict[str, Any]:
    """Analyse a PE file: entry, imports, sections, entropy."""
    info = {"format": "PE", "entry": None, "imports": [], "sections": [], "entropy": 0.0}
    if not HAS_PEFILE:
        try:
            e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
            if data[e_lfanew:e_lfanew+4] == b'PE\0\0':
                info["entry"] = struct.unpack("<I", data[e_lfanew+0x28:e_lfanew+0x2C])[0]
        except:
            pass
        return info

    try:
        pe = pefile.PE(data=data)
        info["entry"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        info["imports"].append(f"{dll}!{imp.name.decode('utf-8', errors='ignore')}")
        for section in pe.sections:
            sec_data = section.get_data()
            entropy = compute_entropy(sec_data)
            info["sections"].append({
                "name": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                "virtual_size": section.Misc_VirtualSize,
                "entropy": entropy
            })
            info["entropy"] = max(info["entropy"], entropy)
    except Exception as e:
        logger.error(f"PE analysis error: {e}")
    return info


def analyse_elf(data: bytes) -> Dict[str, Any]:
    """Analyse an ELF file: entry, imports, sections, entropy."""
    info = {"format": "ELF", "entry": None, "imports": [], "sections": [], "entropy": 0.0}
    if not HAS_ELFFILE:
        try:
            if data[4] == 2:  # 64-bit
                info["entry"] = struct.unpack("<Q", data[0x18:0x20])[0]
            else:
                info["entry"] = struct.unpack("<I", data[0x18:0x1C])[0]
        except:
            pass
        return info

    try:
        from io import BytesIO
        elffile = ELFFile(BytesIO(data))
        info["entry"] = elffile.header.e_entry
        for section in elffile.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == 'DT_NEEDED':
                        if hasattr(tag, 'needed'):
                            info["imports"].append(tag.needed.decode())
        for section in elffile.iter_sections():
            sec_data = section.data()
            entropy = compute_entropy(sec_data)
            info["sections"].append({
                "name": section.name,
                "size": section['sh_size'],
                "entropy": entropy
            })
            info["entropy"] = max(info["entropy"], entropy)
    except Exception as e:
        logger.error(f"ELF analysis error: {e}")
    return info


def analyse_macho(data: bytes) -> Dict[str, Any]:
    """Analyse a Mach‑O file: imports, entropy (entry point not trivial)."""
    info = {"format": "Mach-O", "entry": None, "imports": [], "sections": [], "entropy": 0.0}
    if not HAS_MACHOLIB:
        return info
    try:
        from io import BytesIO
        macho = MachO(BytesIO(data))
        for header in macho.headers:
            for cmd in header.commands:
                if cmd.cmd.cmd == LC_LOAD_DYLIB:
                    dylib = cmd.cmd.dylib.name.decode('utf-8', errors='ignore')
                    info["imports"].append(dylib)
    except Exception as e:
        logger.error(f"Mach-O analysis error: {e}")
    return info


def analyse_dotnet(data: bytes) -> Dict[str, Any]:
    """Analyse a .NET assembly (PE with CLR header)."""
    info = {"format": ".NET", "entry": None, "imports": [], "sections": [], "entropy": 0.0}
    if not HAS_DNFILE:
        return info
    try:
        with dnfile.from_bytes(data) as pe:
            info["entry"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            if hasattr(pe, 'net') and pe.net.metadata:
                info["imports"] = [f"Assembly: {pe.net.metadata.Assembly.Name}"]
    except Exception as e:
        logger.error(f".NET analysis error: {e}")
    return info


def detect_script(data: bytes) -> Optional[str]:
    """Detect shebang‑based scripts."""
    if data.startswith(b'#!'):
        line = data.split(b'\n')[0].decode('utf-8', errors='ignore')
        if 'python' in line:
            return 'Python'
        elif 'bash' in line or 'sh' in line:
            return 'Shell'
        elif 'perl' in line:
            return 'Perl'
        elif 'ruby' in line:
            return 'Ruby'
        elif 'node' in line:
            return 'JavaScript'
    return None


# ============================================================================
# MASTER STATIC ANALYSIS
# ============================================================================
def static_analysis(path: Path, config: Config) -> Tuple[str, Dict[str, Any]]:
    """
    Orchestrate format detection and analysis.
    Returns: (human‑readable report, structured info dict).
    """
    with open(path, "rb") as f:
        data = f.read()

    # Detect format
    info = {}
    format_name = "Unknown"
    if data[:2] == b'MZ':
        if data[0x40:0x44] == b'BSJB':
            format_name = ".NET"
            info = analyse_dotnet(data)
        else:
            format_name = "PE"
            info = analyse_pe(data)
    elif data[:4] == b'\x7fELF':
        format_name = "ELF"
        info = analyse_elf(data)
    elif data[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
        format_name = "Mach-O"
        info = analyse_macho(data)
    else:
        script_type = detect_script(data)
        if script_type:
            format_name = f"Script ({script_type})"
        else:
            format_name = "Data"

    # Extract and filter strings
    all_strings = extract_ascii_strings(data)
    suspicious = filter_suspicious(all_strings, config.suspicious_keywords)

    # Build report
    report_lines = [f"Format: {format_name}"]
    if info.get('entry') is not None:
        report_lines.append(f"Entry point: 0x{info['entry']:X}")

    if info.get('imports'):
        report_lines.append("\nImported symbols (first 30):")
        for imp in info['imports'][:30]:
            report_lines.append(f"  {imp}")

    if info.get('sections'):
        report_lines.append("\nSections (name, entropy):")
        for sec in info['sections'][:20]:
            report_lines.append(f"  {sec.get('name', '?')}: entropy = {sec.get('entropy', 0.0):.2f}")
        if info.get('entropy', 0.0) > config.entropy_threshold:
            report_lines.append("** High entropy detected – possible packing/encryption **")

    if suspicious:
        report_lines.append(f"\nSuspicious strings (found {len(suspicious)}):")
        for s in suspicious:
            report_lines.append(f"  {s}")
    else:
        report_lines.append("\nNo suspicious strings found.")

    report_str = "\n".join(report_lines)
    info['format'] = format_name
    info['suspicious_strings'] = suspicious
    info['all_strings_count'] = len(all_strings)
    info['file_size'] = len(data)
    info['sha256'] = hashlib.sha256(data).hexdigest()

    return report_str, info


# ============================================================================
# AI INTEGRATION (GGUF)
# ============================================================================
_llama = None   # global model instance

def load_model(model_path: str, config: Config) -> None:
    """Load GGUF model using llama-cpp-python."""
    global _llama
    if not HAS_LLAMA:
        logger.warning("llama-cpp-python not installed – AI disabled.")
        _llama = None
        return
    try:
        params = config.ai_params
        _llama = Llama(
            model_path=model_path,
            n_gpu_layers=params.get('n_gpu_layers', -1),
            verbose=params.get('verbose', False)
        )
        logger.info(f"Model loaded: {model_path}")
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        _llama = None


def ai_analyse(report: str, config: Config) -> str:
    """Run inference on the static report."""
    if _llama is None:
        if HAS_LLAMA:
            return "Error: Model not loaded. Please select a GGUF model."
        else:
            return "Error: llama-cpp-python not installed. Install with: pip install llama-cpp-python"

    prompt = (
        "You are a security analyst. Given the following static analysis report of a binary, "
        "determine the likely intent (malicious, benign, or suspicious). "
        "Provide a concise explanation, focusing on indicators like suspicious strings, imports, "
        "and entropy. Avoid generic statements.\n\n"
        f"Report:\n{report}\n\nIntent:"
    )
    try:
        response = _llama(
            prompt,
            max_tokens=config.ai_params.get('max_tokens', 150),
            temperature=config.ai_params.get('temperature', 0.3),
            top_p=config.ai_params.get('top_p', 0.9),
            stop=["\n\n"],
            echo=False
        )
        return response['choices'][0]['text'].strip()
    except Exception as e:
        logger.error(f"Inference error: {e}")
        return f"Inference failed: {e}"


# ============================================================================
# CACHING
# ============================================================================
def get_cache_path(sha256: str) -> Path:
    """Return the cache file path for a given SHA‑256."""
    return CACHE_DIR / f"{sha256}.json"


def cache_result(sha256: str, report: str, info: Dict[str, Any], ai_verdict: str) -> None:
    """Store analysis result in cache."""
    cache_path = get_cache_path(sha256)
    data = {
        "sha256": sha256,
        "report": report,
        "info": info,
        "ai_verdict": ai_verdict,
        "timestamp": time.time()
    }
    with open(cache_path, "w") as f:
        json.dump(data, f, indent=2)


def load_cache(sha256: str) -> Optional[Dict[str, Any]]:
    """Load cached result if it exists."""
    cache_path = get_cache_path(sha256)
    if cache_path.exists():
        try:
            with open(cache_path, "r") as f:
                return json.load(f)
        except:
            pass
    return None


# ============================================================================
# MASTER ANALYSIS PIPELINE
# ============================================================================
def analyse_file(file_path: Path, config: Config, use_cache: bool = True) -> Dict[str, Any]:
    """Orchestrate static analysis, AI inference, and caching."""
    sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
    if use_cache and config.cache_enabled:
        cached = load_cache(sha256)
        if cached:
            logger.info("Using cached result")
            return cached

    report_str, info = static_analysis(file_path, config)
    ai_verdict = ai_analyse(report_str, config)
    result = {
        "sha256": sha256,
        "report": report_str,
        "info": info,
        "ai_verdict": ai_verdict,
        "timestamp": time.time()
    }
    if config.cache_enabled:
        cache_result(sha256, report_str, info, ai_verdict)
    return result


# ============================================================================
# GUI APPLICATION
# ============================================================================
class AnalyserApp:
    """Main GUI application class."""

    def __init__(self, root: tk.Tk, config: Config):
        self.root = root
        self.config = config
        self.current_result = None

        self._setup_window()
        self._create_widgets()
        self._load_initial_model()

    # ---------- Window Setup ----------
    def _setup_window(self) -> None:
        """Configure the main window."""
        self.root.title(APP_NAME)
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        # Set icon
        if ICON_FILE.exists():
            try:
                self.root.iconbitmap(default=str(ICON_FILE))
            except:
                pass

    # ---------- Widget Creation ----------
    def _create_widgets(self) -> None:
        """Create all GUI widgets."""
        # Model selection frame
        model_frame = ttk.LabelFrame(self.root, text="AI Model", padding=5)
        model_frame.pack(fill="x", padx=5, pady=5)

        self.model_var = tk.StringVar(value=self.config.default_model or "No model selected")
        ttk.Label(model_frame, textvariable=self.model_var).pack(side="left", padx=5)
        ttk.Button(model_frame, text="Select GGUF", command=self.select_model).pack(side="left", padx=5)
        ttk.Button(model_frame, text="Reload", command=self.reload_model).pack(side="left", padx=5)

        # File selection frame
        file_frame = ttk.LabelFrame(self.root, text="Target File", padding=5)
        file_frame.pack(fill="x", padx=5, pady=5)

        self.file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_var, width=60).pack(side="left", padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side="left", padx=5)
        ttk.Button(file_frame, text="Analyse", command=self.start_analysis).pack(side="left", padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(fill="x", padx=5, pady=5)

        # Output text area
        output_frame = ttk.LabelFrame(self.root, text="Analysis Report", padding=5)
        output_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, font=("Courier", 10))
        self.output_text.pack(fill="both", expand=True)

        # Export/clear buttons
        export_frame = ttk.Frame(self.root)
        export_frame.pack(fill="x", padx=5, pady=5)
        ttk.Button(export_frame, text="Export JSON", command=self.export_json).pack(side="right", padx=5)
        ttk.Button(export_frame, text="Clear", command=self.clear_output).pack(side="right", padx=5)

    # ---------- Model Handling ----------
    def _load_initial_model(self) -> None:
        """Load the default model on startup."""
        if self.config.default_model and Path(self.config.default_model).exists():
            load_model(self.config.default_model, self.config)

    def select_model(self) -> None:
        """Open file dialog to select a GGUF model."""
        model_path = filedialog.askopenfilename(
            title="Select GGUF Model",
            filetypes=[("GGUF", "*.gguf"), ("All files", "*.*")]
        )
        if model_path:
            self.model_var.set(model_path)
            self.config.default_model = model_path
            self.config.save()
            self.reload_model()

    def reload_model(self) -> None:
        """Reload the currently selected model."""
        model_path = self.model_var.get()
        if Path(model_path).exists():
            load_model(model_path, self.config)
            self.log(f"Model loaded: {model_path}")
        else:
            self.log("Model file not found.")

    # ---------- File Selection ----------
    def browse_file(self) -> None:
        """Open file dialog to select a file for analysis."""
        file_path = filedialog.askopenfilename(title="Select file to analyse")
        if file_path:
            self.file_var.set(file_path)

    # ---------- Analysis ----------
    def start_analysis(self) -> None:
        """Start the analysis in a separate thread."""
        file_path = self.file_var.get()
        if not file_path or not Path(file_path).exists():
            messagebox.showerror("Error", "Please select a valid file.")
            return
        self.progress.start()
        self.output_text.delete(1.0, tk.END)
        self.current_result = None
        threading.Thread(target=self._run_analysis, args=(Path(file_path),), daemon=True).start()

    def _run_analysis(self, file_path: Path) -> None:
        """Run analysis (called in a thread)."""
        try:
            result = analyse_file(file_path, self.config)
            self.current_result = result
            self.root.after(0, self._display_result, result)
        except Exception as e:
            logger.exception("Analysis error")
            self.root.after(0, self._display_error, str(e))
        finally:
            self.root.after(0, self.progress.stop)

    def _display_result(self, result: Dict[str, Any]) -> None:
        """Display the analysis result in the GUI."""
        self.output_text.insert(tk.END, "=== Analysis Report ===\n\n")
        self.output_text.insert(tk.END, result['report'])
        self.output_text.insert(tk.END, "\n\n=== AI Verdict ===\n")
        self.output_text.insert(tk.END, result['ai_verdict'])
        self.output_text.insert(tk.END, f"\n\nSHA-256: {result['sha256']}")

    def _display_error(self, msg: str) -> None:
        """Display an error message."""
        self.output_text.insert(tk.END, f"ERROR: {msg}")

    def log(self, msg: str) -> None:
        """Add a log message to the output area."""
        self.output_text.insert(tk.END, f"\n[INFO] {msg}\n")
        self.output_text.see(tk.END)

    def clear_output(self) -> None:
        """Clear the output text area."""
        self.output_text.delete(1.0, tk.END)

    def export_json(self) -> None:
        """Export the current result as JSON."""
        if not self.current_result:
            messagebox.showinfo("Info", "No analysis result to export.")
            return
        save_path = filedialog.asksaveasfilename(
            title="Save JSON Report",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")]
        )
        if save_path:
            with open(save_path, "w") as f:
                json.dump(self.current_result, f, indent=2)
            self.log(f"Exported to {save_path}")


# ============================================================================
# CONSOLE MODE
# ============================================================================
def console_mode(config: Config) -> None:
    """Run the application in console (non‑GUI) mode."""
    print("=== EXE Intent Analyser (Console) ===")
    print("Type 'help' for commands.\n")
    if config.default_model:
        load_model(config.default_model, config)

    while True:
        cmd = input("> ").strip()
        if cmd in ("exit", "quit"):
            break
        elif cmd == "help":
            print("Commands:")
            print("  analyse <path>   – analyse a file")
            print("  model <path>     – set default model")
            print("  cache            – toggle cache on/off")
            print("  exit/quit        – exit")
        elif cmd.startswith("analyse "):
            path = Path(cmd[8:].strip())
            if not path.exists():
                print("File not found.")
                continue
            print("Analysing...")
            result = analyse_file(path, config)
            print("\n--- Report ---\n", result['report'])
            print("\n--- AI Verdict ---\n", result['ai_verdict'])
            print("\nSHA-256:", result['sha256'])
        elif cmd.startswith("model "):
            model_path = cmd[6:].strip()
            if Path(model_path).exists():
                config.default_model = model_path
                config.save()
                load_model(model_path, config)
                print(f"Model set to {model_path}")
            else:
                print("Model file not found.")
        elif cmd == "cache":
            config.cache_enabled = not config.cache_enabled
            config.save()
            print(f"Cache {'enabled' if config.cache_enabled else 'disabled'}")
        else:
            print("Unknown command. Type 'help'.")


# ============================================================================
# ENTRY POINT
# ============================================================================
def main() -> None:
    """Application entry point."""
    config = Config.load()
    if GUI_AVAILABLE and not os.environ.get("ANALYSER_CONSOLE"):
        root = tk.Tk()
        app = AnalyserApp(root, config)
        root.mainloop()
    else:
        console_mode(config)


if __name__ == "__main__":
    main()