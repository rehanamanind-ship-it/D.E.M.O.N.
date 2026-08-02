# 🧠 Ultimate EXE Intent Analyser

**Cross‑platform binary & script intent analyser** using static analysis and a **GGUF‑based large language model** (LLM).  
Detect suspicious patterns, imports, high entropy (packing), and get an AI‑powered verdict (malicious / benign / suspicious).

---

## ✨ Features

- **Multi‑format support** – PE (EXE/DLL), ELF, Mach‑O, .NET assemblies, and shebang‑based scripts (Python, Bash, Perl, Ruby, Node).
- **Static analysis** – extracts ASCII strings, imported symbols, section entropy, and flags suspicious keywords.
- **AI‑powered verdict** – uses a **GGUF** model (via `llama-cpp-python`) to interpret the static report and explain the intent.
- **GPU acceleration** – leverages `llama-cpp-python` with CUDA/OpenCL support for fast inference.
- **Caching** – SHA‑256‑based results cache to avoid re‑analysing the same file.
- **Graphical interface** – Tkinter GUI with file browser, live progress, and JSON export.
- **Console mode** – headless operation for servers or remote use.
- **Persistent configuration** – stores default model path, keywords, AI parameters, and cache settings in `config.json`.
- **Easy to extend** – modular design allows adding new binary formats or swapping the AI backend.

---

## 📦 Installation

### 1. Install Python 3.9 or later

### 2. Clone the repository
```bash
git clone https://github.com/yourusername/intent-analyser.git
cd intent-analyser

 Install Python dependencies
bash

pip install -r requirements.txt

    Note: llama-cpp-python may require a C++ compiler and CUDA (if you have a GPU).
    For CPU‑only, use pip install llama-cpp-python. For GPU, see the llama-cpp-python docs.

    4. (Optional) Install Tkinter (if not bundled with your Python)

    Windows/macOS: usually pre‑installed.

    Linux (Debian/Ubuntu):
    bash

    sudo apt install python3-tk

    Fedora/RHEL:
    bash

    sudo dnf install python3-tkinter


    🚀 Usage
GUI Mode (default)
bash

python ultimate_analyser.py

    Click Select GGUF to choose your model (e.g., mistral-7b-instruct-v0.2.Q4_K_M.gguf).

    Click Browse to pick a target file.

    Click Analyse – the report and AI verdict appear.

    Use Export JSON to save the full result.


    We need to produce a README.md and requirements.txt for the project. The user asked to add a nice README.md and a requirements.txt. We'll provide the content for both.

We need to include installation instructions, usage, features, dependencies, compilation notes (Nuitka), etc. For requirements.txt, we list the main dependencies: llama-cpp-python (maybe with platform-specific instructions), pefile, pyelftools, macholib, dnfile, and optionally tkinter (usually built-in but may need system package). We'll write a comprehensive README.

We'll output both files. Since the user requested to "add", we'll present them as separate code blocks.

Let's create a detailed README with sections: Title, Features, Installation (including optional dependencies), Usage (GUI and CLI), Compilation (Nuitka), Configuration, Customization, License.

Requirements.txt: we need to include the core packages. Also note that llama-cpp-python might have different binaries; we can simply list it.

We'll also mention that tkinter is required for GUI (usually included in Python standard library but on some Linux distros need python3-tk).

Let's proceed.

I’ll provide a polished README.md and a comprehensive requirements.txt for your project.
README.md
markdown

# 🧠 Ultimate EXE Intent Analyser

**Cross‑platform binary & script intent analyser** using static analysis and a **GGUF‑based large language model** (LLM).  
Detect suspicious patterns, imports, high entropy (packing), and get an AI‑powered verdict (malicious / benign / suspicious).

---

## ✨ Features

- **Multi‑format support** – PE (EXE/DLL), ELF, Mach‑O, .NET assemblies, and shebang‑based scripts (Python, Bash, Perl, Ruby, Node).
- **Static analysis** – extracts ASCII strings, imported symbols, section entropy, and flags suspicious keywords.
- **AI‑powered verdict** – uses a **GGUF** model (via `llama-cpp-python`) to interpret the static report and explain the intent.
- **GPU acceleration** – leverages `llama-cpp-python` with CUDA/OpenCL support for fast inference.
- **Caching** – SHA‑256‑based results cache to avoid re‑analysing the same file.
- **Graphical interface** – Tkinter GUI with file browser, live progress, and JSON export.
- **Console mode** – headless operation for servers or remote use.
- **Persistent configuration** – stores default model path, keywords, AI parameters, and cache settings in `config.json`.
- **Easy to extend** – modular design allows adding new binary formats or swapping the AI backend.

---

## 📦 Installation

### 1. Install Python 3.9 or later

### 2. Clone the repository
```bash
git clone https://github.com/yourusername/intent-analyser.git
cd intent-analyser

3. Install Python dependencies
bash

pip install -r requirements.txt

    Note: llama-cpp-python may require a C++ compiler and CUDA (if you have a GPU).
    For CPU‑only, use pip install llama-cpp-python. For GPU, see the llama-cpp-python docs.

4. (Optional) Install Tkinter (if not bundled with your Python)

    Windows/macOS: usually pre‑installed.

    Linux (Debian/Ubuntu):
    bash

    sudo apt install python3-tk

    Fedora/RHEL:
    bash

    sudo dnf install python3-tkinter

🚀 Usage
GUI Mode (default)
bash

python ultimate_analyser.py

    Click Select GGUF to choose your model (e.g., mistral-7b-instruct-v0.2.Q4_K_M.gguf).

    Click Browse to pick a target file.

    Click Analyse – the report and AI verdict appear.

    Use Export JSON to save the full result.

Console Mode

Set the environment variable ANALYSER_CONSOLE=1:
bash

ANALYSER_CONSOLE=1 python ultimate_analyser.py

Available commands:

    analyse <path> – analyse a file.

    model <path> – set the default GGUF model.

    cache – toggle caching on/off.

    help – show all commands.

    exit – quit.
