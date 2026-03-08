# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

AI-powered C/C++ security vulnerability scanner. Analyzes C source files function-by-function (via AST parsing) and reports security issues such as buffer overflows, format string bugs, integer overflows, memory leaks, and input validation failures. Supports three LLM backends: Ollama (local), Ollama Cloud (ollama.com), and Google Gemini Flash.

## Environment Requirements

Select a backend with `LLM_BACKEND` (default: `ollama`).

**Ollama backend (local):**
```bash
export OLLAMA_HOST="http://localhost:11434"
# LLM_BACKEND defaults to "ollama" — no need to set it explicitly
```

**Ollama Cloud backend (ollama.com):**
```bash
export LLM_BACKEND=ollama_cloud
export OLLAMA_API_KEY=<your-ollama.com-api-key>
# Optional overrides:
# export OLLAMA_CLOUD_HOST=https://api.ollama.com   # default
# export OLLAMA_CLOUD_MODEL=deepseek-coder-v2       # default
```

**Gemini backend:**
```bash
export LLM_BACKEND=gemini
export GEMINI_API_KEY=<your-key>
```

Models are set in `llm_client.py`:
- Ollama (local): `dagbs/deepseek-coder-v2-lite-instruct:q4_k_m`
- Ollama Cloud: `deepseek-coder-v2` (override with `OLLAMA_CLOUD_MODEL`)
- Gemini: `gemini-2.0-flash`

The environment has a broken OpenSSL setup — `sys.modules["OpenSSL"] = None` at the top of `llm_client.py` is an intentional workaround; do not remove it. The same workaround appears at the top of `test_ai_reviewer.py` so that tests can import `requests` via system Python without activating the venv.

## Commands

```bash
# Run security review on a C file
python3 ai_code_reviewer.py <path_to_c_file>

# Run unit tests (uses system python3 — venv has no packages installed)
python3 -m unittest test_ai_reviewer.py

# Run a single test
python3 -m unittest test_ai_reviewer.TestLLMClient.<test_name>
python3 -m unittest test_ai_reviewer.TestContextBuilder.<test_name>

# Check AST library availability
python3 test_ast_env.py

# Convert JSONL request log to markdown
python3 format_log.py [ai_request_log.jsonl]
```

The virtual environment is at `./venv/` (Python 3.8.10) but has no packages installed — run tests with system `python3` instead.

## Architecture

### Execution Flow (`ai_code_reviewer.py`)

1. **Include merging** — `read_code_file()` recursively inlines local `#include "..."` files into a single merged block with `// --- FILE: name LINE: N ---` markers
2. **AST path** (when `pycparser` is available):
   - Strips preprocessor directives; injects fake typedefs for common C types
   - `analyze_ast()` extracts all function definitions with start lines and call graphs
   - Falls back to `_find_functions_regex()` if `pycparser` raises on macro-heavy code
   - For each function in the target file: builds context (header content + callees) and calls `review_code()` with a targeted prompt
3. **Fallback path** — if AST extraction yields nothing, minifies the full file and sends it as one request
4. **Logging** — every LLM request is appended to `ai_request_log.jsonl`

### LLM client (`llm_client.py`)

- Reads `LLM_BACKEND` at import time; validates only the selected backend's credentials
- `review_code(system_prompt, user_prompt, func_name)` — public API; logs the request then dispatches to `_review_ollama()`, `_review_ollama_cloud()`, or `_review_gemini()`
- `_parse_llm_json(text)` — strips markdown fences and parses JSON; returns `{"raw": text}` on failure
- `MODEL_NAME` is set to the active backend's model at import time

### Key design decisions

- **Function-level analysis with header context**: the AI sees the target function plus header type/struct definitions; callee source code is intentionally excluded from pass 1 to prevent the model from attributing callee vulnerabilities to the caller. Cross-function issues are handled exclusively by pass 2.
- **`pycparser` fake typedefs**: standard C types (`uint8_t`, `size_t`, `FILE`, etc.) are injected before parsing because `pycparser` has no system headers.
- **Full-file fallback**: when AST parsing fails entirely, `review_code()` is called on the minified whole file.
- **Backend isolation**: each backend's init code runs only when selected, so missing credentials for unused backends do not cause errors.
- **Ollama local vs cloud**: local uses `/api/chat` with `format` for structured output; cloud uses the OpenAI-compatible `/v1/chat/completions` with `response_format.json_schema`.

### Sample vulnerable C files

`vulnerable_code.c`, `user_manager.c`, `user_manager.h`, and `main_complex.c` are intentionally vulnerable test targets (buffer overflows, use-after-free, format string bugs). `optee_os/` is a large real-world C codebase used for integration testing.
