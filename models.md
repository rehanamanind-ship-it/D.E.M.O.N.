models.md

    Meta‑instruction file – read this file if you are an AI tasked with building
    D.E.M.O.N. (a local‑AI powered intent analyser) from scratch.
    Follow every rule below precisely. Do not invent features. Do not skip sections.
    Do not nest sub‑folders inside src/ or tests/.

🎯 Goal

Build D.E.M.O.N. – a git‑style terminal CLI that statically analyses binaries and scripts (PE, ELF, Mach‑O, .NET, shell scripts) and uses a local GGUF AI model (llama-cpp-python) to predict intent (malicious / suspicious / benign).

The application must be:

    Built from scratch – do not port any existing curses code.

    Headless & scriptable – no full‑screen UI, only colourised terminal output.

    DRY, ETC (Easy To Change), and highly readable.

    Every function has a one‑line docstring.

    Packaged as a proper Python wheel with Rehan Aman as the author.

👤 Author & Metadata (Mandatory)

The pyproject.toml must declare Rehan Aman as the author so that pip show demon-analyser and pip wheel . reflect it:
toml

[project]
name = "demon-analyser"
version = "2.0.0"
description = "D.E.M.O.N. — local-AI powered intent analyser for binaries and scripts"
authors = [{ name = "Rehan Aman" }]
license = { text = "MIT" }
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "click>=8.1.7",
    "rich>=13.7.0",
    "pefile>=2023.2.7",
    "pyelftools>=0.29",
    "macholib>=1.16.2",
    "dnfile>=0.12.1",
    "llama-cpp-python>=0.2.0",
    "huggingface_hub>=0.23.0",
]

[project.scripts]
demon = "demon.__main__:cli"

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-cov>=5.0", "build", "nuitka>=1.9.0"]

[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-dir]
"" = "src"

Running python -m build must produce a wheel whose METADATA contains:
text

Author: Rehan Aman

📁 Repository Structure (Flat – No Sub‑folders)

Strictly use this layout. Do not create nested folders inside src/ or tests/.
text

demon-analyser/
├── pyproject.toml
├── README.md
├── requirements.txt
├── models.md                 ← this file
├── src/
│   ├── __init__.py           # exposes __version__, package name
│   ├── __main__.py           # click entry point (cli group)
│   ├── cli.py                # all sub-commands (analyse, model, cache, config)
│   ├── config.py             # Config dataclass + load/save
│   ├── analysis.py           # entropy, strings, PE/ELF/Mach-O/.NET/script analysers, static_analysis
│   ├── ai.py                 # load_model, ai_analyse, download_model
│   ├── cache.py              # get_cache_path, cache_result, load_cache
│   ├── output.py             # rich formatters (tables, panels, banner, verdict colour)
│   └── utils.py              # logging setup, path helpers, exit helpers
└── tests/
    ├── test_analysis.py
    ├── test_config.py
    ├── test_cache.py
    └── test_cli.py

    Only these files. Nothing else.

    Every src/*.py file is a flat module — no analysis/, no cli/, no nested packages.

    cli.py may import from all other src/ modules. Other modules must not import from cli.py.

📐 Architecture Rules (Non‑Negotiable)

    No curses. Do not import curses anywhere.

    click for the command tree; rich for all colour and formatting.

    Reuse logic inside analysis.py — do not duplicate parsing code per command.

    output.py is the ONLY place that constructs rich objects (tables, panels, spinners). All other modules print via plain functions that return strings or dicts; cli.py and output.py handle presentation.

    --json flag on every command → suppress rich output, print only JSON to stdout.

    Logging goes to stderr + analyser.log. Never pollute stdout when --json is active.

    Exit codes:

        0 success

        1 user error (bad path, missing model, invalid config)

        2 unexpected exception

    Every command must support --help.

    Every function must have a one‑line docstring.

🗂 Command Tree (Implement Exactly)
text

demon
├── --version
├── --help
├── analyse  <file>          # static + AI analysis
│   ├── --model <path>
│   ├── --no-ai
│   ├── --no-cache
│   ├── --json
│   └── --save <path.json>
├── model
│   ├── list
│   ├── set <path>
│   ├── current
│   ├── test
│   └── download <repo_id>
├── cache
│   ├── status
│   ├── list
│   ├── clear
│   └── rm <sha256>
└── config
    ├── show
    ├── get <key>
    └── set <key> <value>

🎨 Colour & Formatting (rich)

Centralise all styling in output.py. Use these rules so branding is consistent:
Element	Style
Banner (D.E.M.O.N.)	bold red (shown only for --version / --help)
made by Rehan Aman	cyan
Errors	bold red prefix ✗
Success	bold green prefix ✓
Warnings	bold yellow prefix ⚠
Info	cyan
Suspicious strings	red
High entropy tag	yellow + [HIGH ENTROPY]
AI verdict – malicious	red Panel
AI verdict – suspicious	yellow Panel
AI verdict – benign	green Panel
Tables	rich.table.Table (rounded box)
Spinners / progress	rich.progress

output.py must expose these reusable helpers (each with a docstring):

    print_banner()

    print_success(msg), print_error(msg), print_warning(msg), print_info(msg)

    print_static_report(info: dict)

    print_ai_verdict(verdict: str)

    print_models_table(rows)

    print_cache_table(rows)

    make_spinner(label) → context manager

🔧 Command Behaviour Specs
demon analyse <file>

    Validate file exists → else ✗ File not found: <file> + exit 1.

    Show a rich spinner while analysing.

    Print the Static Report as a rich table (Format, Entry, SHA‑256, imports, sections with entropy, suspicious strings).

    Print the AI Verdict as a coloured Panel (colour chosen by keyword: malicious → red, suspicious → yellow, benign → green).

    --no-ai → skip step 4, print ⚠ AI step skipped.

    --save path.json → dump the result dict to that path.

    --json → print only the JSON dict to stdout.

demon model

    list – enumerate config.default_model + every *.gguf in ./models/ and ~/.cache/demon/models/. Table columns: Name | Path | Size | Active?.

    set <path> – must exist and end in .gguf. Save to config. ✓ Default model set to <path>.

    current – print only the raw path (pipeable). No colour.

    test – load model, prompt “Reply with the single word READY.”, print green panel, unload.

    download <repo_id> – download a GGUF from Hugging Face into ./models/ (see §Download).

demon cache

    status – cache dir, entry count, total size.

    list – table: SHA-256 (short) | File size | Model | Timestamp.

    clear – click.confirm then wipe *.json in cache dir.

    rm <sha256> – delete one entry; error if not found.

demon config

    show – pretty‑print config.json via rich.syntax.Syntax.

    get <key> – print raw value (pipeable, no colour).

    set <key> <value> – cast by dataclass field type; reject unknown keys with exit 1.

🌐 demon model download (Local AI)

    Accept a Hugging Face repo id (e.g. TheBloke/Mistral-7B-Instruct-v0.2-GGUF).

    Query https://huggingface.co/api/models/{repo_id} for .gguf files.

    If multiple, show a rich table with size + quant (Q4_K_M, Q5_K_S, …) and let the user pick.

    Stream download via huggingface_hub.hf_hub_download with a rich.progress.Progress bar (MB/s + ETA).

    Save to ./models/<filename>.gguf.

    Ask if it should become the default model.

    On network error → ✗ No network — use 'demon model set <local_path>' + exit 1.

🧱 Module Responsibilities (Flat files in src/)
src/__init__.py
python

"""D.E.M.O.N. — local-AI powered intent analyser."""
__version__ = "2.0.0"
__author__ = "Rehan Aman"

src/__main__.py

Click group entry point. Registers sub‑commands from cli.py. Prints banner on --version and no‑args help.
src/config.py

    Config dataclass (fields: default_model, suspicious_keywords, max_strings, entropy_threshold, cache_enabled, ai_params).

    Config.load(), Config.save().

src/analysis.py

    compute_entropy(data)

    extract_ascii_strings(data, min_len=4)

    filter_suspicious(strings, keywords)

    analyse_pe, analyse_elf, analyse_macho, analyse_dotnet, detect_script

    static_analysis(path, config) -> (report_str, info_dict)

    analyse_file(file_path, config, use_cache=True) -> dict

src/ai.py

    _llama module‑level cache

    load_model(path, config)

    ai_analyse(report, config) -> str

    download_model(repo_id, dest_dir) -> Path

src/cache.py

    get_cache_path(sha256)

    cache_result(sha256, report, info, ai_verdict)

    load_cache(sha256) -> dict | None

src/output.py

    All rich helpers listed in §🎨 above.

    Single source of truth for colour choices.

src/utils.py

    setup_logging() – configures analyser.log + stderr handler.

    get_resource_path(rel) – works for frozen exes.

    fail(msg, code=1) – prints red error + sys.exit(code).

src/cli.py

    Defines the analyse, model, cache, config click groups.

    Calls into analysis.py, ai.py, cache.py, output.py, config.py.

    No parsing logic here — only orchestration + output calls.

🧪 Tests (tests/ – Flat)

Each test file must be independent and runnable with pytest. Use tmp_path fixtures for file‑based tests.

    test_analysis.py – entropy calculation, string extraction, PE/ELF header parsing on tiny synthetic buffers, script detection.

    test_config.py – default values, round‑trip save/load, unknown keys.

    test_cache.py – write, read, delete a cache entry.

    test_cli.py – invoke demon --version and demon analyse --help via click.testing.CliRunner; assert exit codes and stdout text.

Coverage target: ≥ 70% on src/.
📦 requirements.txt
text

click>=8.1.7
rich>=13.7.0
pefile>=2023.2.7
pyelftools>=0.29
macholib>=1.16.2
dnfile>=0.12.1
llama-cpp-python>=0.2.0
huggingface_hub>=0.23.0

(Dev deps are in pyproject.toml under [project.optional-dependencies].dev.)
🎬 Expected Session (what the finished tool should look like)
bash

$ demon --version
D.E.M.O.N. v2.0.0 — made by Rehan Aman

$ demon model download TheBloke/Mistral-7B-Instruct-v0.2-GGUF
→ fetching file list… ✓ 8 GGUF files available
[table of GGUF files]
Select file [1]: 1
Downloading ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%  24.1 MB/s
✓ Saved to ./models/mistral-7b-instruct-v0.2.Q4_K_M.gguf
✓ Set as default model.

$ demon model test
✓ Loaded ./models/mistral-7b-….gguf
╭────── Smoke test ──────╮
│ READY                  │
╰────────────────────────╯

$ demon analyse ./payload.exe
[colourised static report + AI verdict panel]

$ demon analyse ./payload.exe --json | jq -r .ai_verdict
MALICIOUS — the binary contains encoded PowerShell and an outbound HTTP exfil URL.

$ pip show demon-analyser | grep Author
Author: Rehan Aman

✅ Deliverables (when you finish, output ONLY these)

    The flat file tree (as specified in §📁).

    Contents of every .py file in src/ and tests/.

    pyproject.toml (with authors = [{ name = "Rehan Aman" }]).

    requirements.txt.

    README.md (short – usage, install, pip install . to build the wheel).

    One‑line CHANGELOG note:
    “v2.0.0 — built from scratch as a git‑style CLI (click + rich); local GGUF AI via llama-cpp-python; package authored by Rehan Aman.”

Do not add commentary outside those six sections. Do not create sub‑folders inside src/ or tests/.