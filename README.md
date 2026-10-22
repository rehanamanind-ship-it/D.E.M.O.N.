# D.E.M.O.N.

D.E.M.O.N. is a headless, git-style terminal CLI for static analysis of
binaries and scripts, with optional local GGUF classification through
`llama-cpp-python`.

Install the wheel or editable project with:

```bash
pip install .
demon --help
demon analyse ./payload.exe --no-ai
```

Models are configured with `demon model set path/to/model.gguf`. Results are
cached under `~/.cache/demon`.

