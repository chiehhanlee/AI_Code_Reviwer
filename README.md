# AI C/C++ Security Code Reviewer

An AI-powered security vulnerability scanner for C/C++ source files. It analyzes code function-by-function via AST parsing and reports security issues with approximate line numbers. Supports two LLM backends: a local [Ollama](https://ollama.ai) instance or the Google Gemini API.

## Features

- **Function-level analysis** — parses the AST to audit each function individually, reducing noise and token usage
- **Context injection** — passes callers/callees alongside the target function so the model can reason across call boundaries
- **Recursive include merging** — inlines local `#include "..."` headers and companion `.c` files before analysis
- **Regex fallback** — falls back to brace-depth heuristics when `pycparser` cannot parse macro-heavy code
- **Full-file fallback** — if AST extraction fails entirely, sends the minified whole file as a single request
- **JSON audit reports** — results are written to `<source>.audit.json`
- **Dual LLM backends** — switch between a local Ollama model and Google Gemini Flash via an environment variable
- **Request logging** — every prompt sent to the LLM is appended to `ai_request_log.jsonl`

## Detected Vulnerability Classes

| CWE | Description |
|-----|-------------|
| CWE-20  | Input Validation Failures |
| CWE-119 | Improper Restriction of Buffer Operations |
| CWE-121 | Stack-based Buffer Overflow |
| CWE-122 | Heap-based Buffer Overflow |
| CWE-125 | Out-of-bounds Read |
| CWE-134 | Use of Externally-Controlled Format String |
| CWE-190 | Integer Overflow / Wraparound |
| CWE-401 | Memory Leak |
| CWE-415 | Double Free |
| CWE-416 | Use After Free |
| CWE-676 | Use of Potentially Dangerous Function |

## Requirements

- Python 3.8+
- `requests` library
- `pycparser` (optional — enables AST mode, strongly recommended)
- [Ollama](https://ollama.ai) running locally or remotely **or** a Google Gemini API key

Install Python dependencies into the provided virtual environment:

```bash
source venv/bin/activate
pip install requests pycparser
```

## Setup

Select a backend with `LLM_BACKEND` (default: `ollama`).

### Ollama backend (default)

```bash
export LLM_BACKEND=ollama          # optional — ollama is the default
export OLLAMA_HOST="http://localhost:11434"
```

Pull the model if you haven't already:

```bash
ollama pull dagbs/deepseek-coder-v2-lite-instruct:q3_k_m
```

### Gemini backend

```bash
export LLM_BACKEND=gemini
export GEMINI_API_KEY=<your-api-key>
```

The Gemini model used is `gemini-2.0-flash`.

### Environment variable summary

| Variable | Required for | Default |
|----------|-------------|---------|
| `LLM_BACKEND` | all | `ollama` |
| `OLLAMA_HOST` | `LLM_BACKEND=ollama` | _(none, exits if missing)_ |
| `GEMINI_API_KEY` | `LLM_BACKEND=gemini` | _(none, exits if missing)_ |

## Usage

```bash
# Analyze a C source file
python ai_code_reviewer.py <path/to/file.c>

# With additional include search paths (like gcc -I)
python ai_code_reviewer.py <path/to/file.c> -I ./include -I ../shared

# Write the audit report to a specific file
python ai_code_reviewer.py <path/to/file.c> -o report.json
```

The audit report is written to `<source>.audit.json` by default.

### Output Format

**Function-by-function mode** (AST available):

```json
{
  "file": "vulnerable_code.c",
  "model": "dagbs/deepseek-coder-v2-lite-instruct:q3_k_m",
  "mode": "function-by-function",
  "functions": [
    {
      "function": "process_input",
      "vulnerabilities": [
        {
          "line": 42,
          "description": "CWE-121: strcpy into fixed-size stack buffer with no bounds check"
        }
      ]
    }
  ]
}
```

**Full-file mode** (AST unavailable):

```json
{
  "file": "legacy.c",
  "model": "dagbs/deepseek-coder-v2-lite-instruct:q3_k_m",
  "mode": "full-file",
  "vulnerabilities": [
    {
      "line": 17,
      "description": "CWE-134: printf called with user-controlled format string"
    }
  ]
}
```

## Project Structure

```
ai_code_reviewer.py   # CLI entry point and orchestration
context_builder.py    # AST parsing, include merging, prompt construction
llm_client.py         # LLM backends (Ollama + Gemini) and response parsing
format_log.py         # Converts ai_request_log.jsonl to readable Markdown
test_ai_reviewer.py   # Unit tests (context_builder + llm_client)
test_ast_env.py       # Checks pycparser availability
```

## Running Tests

```bash
source venv/bin/activate

# Run all unit tests
python -m unittest test_ai_reviewer.py

# Run a single test
python -m unittest test_ai_reviewer.TestContextBuilder.test_prune_context_removes_line_comments

# Check AST library availability
python test_ast_env.py
```

## Utilities

**Convert the request log to Markdown** (useful for reviewing what was sent to the model):

```bash
python format_log.py                        # reads ai_request_log.jsonl
python format_log.py path/to/custom.jsonl   # reads a specific log file
```

Output is written to `<input>.md` next to the log file.

## Architecture Notes

1. **Include merging** — `read_code_file()` recursively inlines `#include "..."` files, inserting `// --- FILE: name LINE: N ---` markers so that line numbers in the final report map back to the original per-file line numbers.

2. **AST path** — when `pycparser` is available, `analyze_ast()` strips preprocessor directives, injects fake typedefs for common C types (`uint8_t`, `size_t`, `FILE`, etc.), and parses the code. If `pycparser` fails (e.g., on macro-heavy code), `_find_functions_regex()` is used as a secondary fallback.

3. **Context injection** — for each target function, the system prompt instructs the model to report issues only in that function. Header content and callees are passed as supporting context so the model understands data flow without inflating results.

4. **Prompt logging** — every request is logged to `ai_request_log.jsonl` as newline-delimited JSON, preserving the full system and user prompt for debugging.
