# D.E.M.O.N.
Test the .exe files and more to know the intent behind the the software.

//////////////////////////////-//////#\\\\\\-\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\  
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\-\\\\\\#//////-///////////////////////////////


ABOUT
-----
This tool analyses any executable (Windows .exe, Linux ELF, macOS Mach‑O)
or script file (.py, .sh, .js, etc.) and uses a local AI model to guess
the file's intent – e.g., ransomware, keylogger, trojan, coin miner,
legitimate installer, etc.

It runs completely offline and never sends your files to the internet.
The AI "brain" is a Python script (ai_brain.py) that either uses a
real language model (GGUF or ONNX) or a tiny built‑in dummy model.

The application itself is a fast, compiled Rust binary that handles
file dialogs, static analysis, and the menu system.

All you need are three files:
    main.rs         – Rust source code
    Cargo.toml      – Rust project configuration
    ai_brain.py     – Python AI engine (called by the Rust binary)


FEATURES
--------
  * Static analysis of PE, ELF, Mach‑O, and plain scripts
  * Detects suspicious strings (URLs, commands, paths)
  * Optional GGUF → ONNX model conversion
  * Fallback dummy ONNX model – the tool works even without a real AI
  * Native file dialogs (Windows Explorer, macOS Finder, Linux file picker)
  * Persistent configuration (remembers your last chosen model)


PREREQUISITES
-------------
1. Rust toolchain (install from https://rustup.rs)
2. Python 3.8 or newer
3. Python packages (install with pip):
   - Required for GGUF models:  pip install llama-cpp-python
   - Optional for ONNX models: pip install onnxruntime onnx
   - Optional for GGUF→ONNX conversion: pip install gguf2onnx

   Note: If you only use the dummy ONNX model, no extra Python packages
         are needed beyond the standard library + 'onnx' (for generation).


SETUP
-----
1. Create a new Rust project:
       cargo new exe_intent
       cd exe_intent

2. Replace the generated src/main.rs with the provided main.rs.
   Replace Cargo.toml with the provided one.

3. Copy ai_brain.py into the project root (same folder as Cargo.toml).

4. (Optional) If you have a GGUF model, place it somewhere accessible,
   e.g., a folder named "models/" – but you'll be asked to select it later.

5. Build the tool:
       cargo build --release

   The compiled binary will be in target/release/ (or target\release\ on Windows).

6. Copy ai_brain.py next to the binary:
       cp ai_brain.py target/release/       (Linux/macOS)
       copy ai_brain.py target\release\     (Windows)

   (You can also run the binary from the project root; just keep ai_brain.py
    in the same directory where you run the .exe.)


RUNNING FOR THE FIRST TIME
--------------------------
1. Execute the binary:
       ./target/release/exe_intent   (Linux/macOS)
       target\release\exe_intent.exe (Windows)

2. Since no model is configured, you'll see:
       No valid model configured. You can:
         1) Select an existing .gguf or .onnx file
         2) Generate a default dummy ONNX model (no real AI)
       Choice [1/2]:

   - Choose 1: A file dialog opens. Browse to your .gguf (or .onnx) model.
   - Choose 2: The tool creates a tiny dummy ONNX model (default_model.onnx)
               that always returns a placeholder message. This lets you test
               the tool immediately without any real AI model.

   After your first choice, the path is saved in config.json next to the
   binary. On subsequent runs, that model will be used automatically.


MENU OPTIONS
------------
Once a model is loaded, you get a menu:

   1. Analyse a file
      Opens a file dialog → pick any executable or script.
      Shows a static analysis report and then the AI's intent verdict.

   2. Change default model
      Opens a file dialog to select a different .gguf or .onnx file.
      Updates config.json.

   3. Convert GGUF to ONNX
      First asks for the input .gguf file, then where to save the .onnx.
      Requires the 'gguf2onnx' Python tool (pip install gguf2onnx).
      (The conversion may take several minutes.)

   4. Generate default dummy ONNX model
      (Re)creates the minimal ONNX model. Useful if you deleted the old one
      or want to switch to the dummy model.

   5. Exit


EXAMPLE SESSION
---------------
$ ./exe_intent
No valid model configured. You can:
  1) Select an existing .gguf or .onnx file
  2) Generate a default dummy ONNX model (no real AI)
Choice [1/2]: 2
Default model created at: /home/user/tools/default_model.onnx

=== EXE INTENT ANALYSER ===
1. Analyse a file
2. Change default model
3. Convert GGUF to ONNX
4. Generate default dummy ONNX model
5. Exit
Current model: /home/user/tools/default_model.onnx
1
[File dialog opens → select suspicious.exe]
--- Static Report ---
Format: PE
Entry point: 0x12A0
Suspicious strings:
  http://bad.example.com/payload
  cmd.exe /c ...
...
=== AI Analysis ===
Default model – no real AI loaded.
Analysis: unable to determine intent. Please provide a proper .gguf or .onnx model.

(If you had loaded a real GGUF model, the output would contain a detailed
 explanation like: "This appears to be a backdoor because it connects to
 a remote server and spawns a command shell.")


NOTES
-----
- Everything runs offline. No internet connection is ever used.
- The dummy ONNX model is just for demonstration – it never analyses anything.
  To get actual AI results, download a GGUF model (e.g., Mistral-7B-Instruct)
  from Hugging Face and point the tool to it.
- Static analysis only inspects the file without executing it. It cannot
  detect heavily packed or obfuscated malware that hides its strings.
- The tool is for educational and security research purposes. Only analyse
  files you have permission to examine.


TROUBLESHOOTING
---------------
Q: "Python error: No module named 'llama_cpp'"
A: Install llama-cpp-python:  pip install llama-cpp-python

Q: "gguf2onnx not installed"
A: The GGUF→ONNX conversion requires the external tool. Install it with:
       pip install gguf2onnx
   Or manually use the scripts from llama.cpp.

Q: File dialog doesn't appear (Linux without GUI)
A: Install a file dialog backend, e.g., zenity or kdialog. rfd will use
   the first available one.

Q: "No model loaded" but I selected a file
A: Make sure the path doesn't contain special characters and the file is
   a valid .gguf or .onnx model. For GGUF, ensure llama-cpp-python can
   load it (try running a small test script outside the tool first).

Q: The dummy ONNX model gives errors during analysis
A: Ensure you have onnxruntime installed:  pip install onnxruntime
   The dummy model needs onnxruntime to run inference.


FILES IN THIS PROJECT
---------------------
  main.rs         – Rust source (parsing, menus, Python bridge)
  Cargo.toml      – Rust dependencies and build settings
  ai_brain.py     – Python AI brain (model loading, inference, conversion)
  README.txt      – This file
