# AI C/C++ Security Code Reviewer

An AI-powered security vulnerability scanner for C/C++ source files. It performs a **two-pass analysis** — first auditing each function individually, then running a dedicated cross-function pass to catch inter-procedural bugs invisible to single-function analysis. Supports two LLM backends: a local [Ollama](https://ollama.ai) instance or Google Gemini Flash.

## Features

- **Function-level analysis** — parses the AST to audit each function individually, reducing noise and token usage
- **Cross-function analysis pass** — a second LLM pass groups related functions into call-clusters and looks exclusively for inter-procedural bugs (UAF, double-free, memory leaks, NULL deref across boundaries)
- **Context injection** — callers/callees and header content are passed alongside each target function so the model can reason across call boundaries
- **Cross-file call-chain clustering** — clusters include callee functions from `#include`d files, so a one-function file (e.g. `main`) still forms a cluster with the functions it calls
- **Function role classification** — each function is auto-labelled as ALLOCATES / FREES / USES before the cross-function prompt so the model correctly attributes `functions_involved`
- **Recursive include merging** — inlines local `#include "..."` headers and companion `.c` files before analysis
- **Regex fallback** — falls back to brace-depth heuristics when `pycparser` cannot parse macro-heavy code
- **Full-file fallback** — if AST extraction fails entirely, sends the minified whole file as a single request
- **Dual LLM backends** — switch between Ollama and Google Gemini Flash via an environment variable
- **Robust JSON repair** — fixes LLM responses that embed unescaped double-quotes inside string values before falling back to raw storage
- **JSON audit reports** — results written to `<source>.audit.json`
- **Request logging** — every prompt sent to the LLM is appended to `ai_request_log.jsonl`

## Detected Vulnerability Classes

### Per-function pass

| CWE | Description |
|-----|-------------|
| CWE-20  | Input Validation Failures |
| CWE-119 | Improper Restriction of Buffer Operations |
| CWE-120 | Buffer Copy without Checking Size of Input |
| CWE-121 | Stack-based Buffer Overflow |
| CWE-122 | Heap-based Buffer Overflow |
| CWE-125 | Out-of-bounds Read |
| CWE-134 | Use of Externally-Controlled Format String |
| CWE-190 | Integer Overflow / Wraparound |
| CWE-401 | Memory Leak |
| CWE-415 | Double Free |
| CWE-416 | Use After Free |
| CWE-476 | NULL Pointer Dereference |
| CWE-676 | Use of Potentially Dangerous Function |
| CWE-787 | Out-of-bounds Write |

### Cross-function pass (inter-procedural only)

| CWE | Pattern detected |
|-----|-----------------|
| CWE-401 | Memory allocated in one function, never freed by any caller in the cluster |
| CWE-415 | Same pointer freed in two separate functions or call paths |
| CWE-416 | Pointer freed in one function, dereferenced in another |
| CWE-476 | NULL returned by callee, dereferenced in caller without a NULL check |

## Requirements

- Python 3.8+
- `requests` library
- `pycparser` (optional — enables AST mode, strongly recommended)
- [Ollama](https://ollama.ai) running locally or remotely **or** a Google Gemini API key

Install Python dependencies:

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

Model used: `gemini-2.0-flash`.

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

**Function-by-function mode** (AST available, no cross-function findings):

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

**Function-by-function mode with cross-function findings:**

```json
{
  "file": "main_complex.c",
  "model": "dagbs/deepseek-coder-v2-lite-instruct:q3_k_m",
  "mode": "function-by-function",
  "functions": [
    {
      "function": "main",
      "vulnerabilities": [...]
    }
  ],
  "cross_function": [
    {
      "functions_involved": ["delete_user", "process_user_command"],
      "file": "main_complex.c",
      "line": 22,
      "description": "CWE-416: alice freed in delete_user then dereferenced in process_user_command"
    },
    {
      "functions_involved": ["main", "delete_user"],
      "file": "main_complex.c",
      "line": 26,
      "description": "CWE-415: delete_user called twice on alice — double free"
    }
  ]
}
```

The `cross_function` key is omitted entirely when no inter-procedural clusters exist or the LLM finds no findings.

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
ai_code_reviewer.py   # CLI entry point and two-pass orchestration
context_builder.py    # AST parsing, include merging, clustering, prompt construction
llm_client.py         # LLM backends (Ollama + Gemini), JSON parsing and repair
format_log.py         # Converts ai_request_log.jsonl to readable Markdown
test_ai_reviewer.py   # Unit and integration tests
test_ast_env.py       # Checks pycparser availability
```

## Running Tests

```bash
# Run all unit tests (uses system python3; test file handles the OpenSSL workaround)
python3 -m unittest test_ai_reviewer.py

# Run a single test class
python3 -m unittest test_ai_reviewer.TestContextBuilder
python3 -m unittest test_ai_reviewer.TestCrossFunctionPass
python3 -m unittest test_ai_reviewer.TestLLMClient

# Check AST library availability
python3 test_ast_env.py
```

## Utilities

**Convert the request log to Markdown** (useful for reviewing what was sent to the model):

```bash
python3 format_log.py                        # reads ai_request_log.jsonl
python3 format_log.py path/to/custom.jsonl   # reads a specific log file
```

Output is written to `<input>.md` next to the log file.

## Architecture

### Execution flow

```
C source file
      │
      ▼
┌─────────────────────────────────┐
│  read_code_file()               │  Recursively inlines #include "..." files.
│  Include merging                │  Inserts // --- FILE: name LINE: N --- markers.
│  (context_builder.py)          │  Companion .c files pulled in alongside .h files.
└────────────┬────────────────────┘
             │ merged source (single string)
             ▼
┌─────────────────────────────────┐
│  analyze_ast()                  │  Strips preprocessor directives.
│  AST extraction                 │  Injects fake typedefs (uint8_t, size_t, FILE…).
│  (context_builder.py)          │  Parses with pycparser → FuncDefVisitor extracts
│                                 │  {name, start_line, calls[]} for every function.
│                                 │  On parse failure → _find_functions_regex() fallback.
└────────────┬────────────────────┘
             │ functions dict: {name → {source, calls, file}}
             │
      ┌──────┴───────┐
      │              │
      ▼              ▼
 target_funcs   non-target
 (functions in  (functions from
  target file)   included files)
      │
      ├─────────────────────────────────────────────────────┐
      │  PASS 1 — Per-function analysis                     │
      │                                                     │
      │  For each function in target_funcs:                 │
      │    • Build context: header content + callee sources │
      │    • system prompt: audit THIS function only        │
      │    • user prompt:   target source + context         │
      │    • review_code() → parse → append to functions[] │
      └─────────────────────────────────────────────────────┘
      │
      ├─────────────────────────────────────────────────────┐
      │  PASS 2 — Cross-function analysis                   │
      │                                                     │
      │  build_call_clusters(functions, target_funcs)       │
      │    • Nodes = target_funcs + their callees defined   │
      │      anywhere in functions (cross-file chains)      │
      │    • Union-Find groups nodes by call edges          │
      │    • Singletons discarded; clusters > max_size      │
      │      split into ego-neighborhoods                   │
      │                                                     │
      │  For each cluster:                                  │
      │    • _classify_function_role() labels each fn as:   │
      │      ALLOCATES / FREES / USES-OR-ORCHESTRATES       │
      │    • Memory Role Summary injected into user prompt  │
      │    • system prompt: inter-procedural bugs only      │
      │      (CWE-401/415/416/476), with attribution rules  │
      │    • review_code() → parse → extend cross_function[]│
      └─────────────────────────────────────────────────────┘
             │
             ▼
      audit report written to <source>.audit.json
```

### Component responsibilities

#### `ai_code_reviewer.py` — Orchestration

Drives both analysis passes. After the per-function loop finishes:
- Calls `build_call_clusters()` to identify function groups
- Iterates clusters, builds prompts, calls `review_code()`, accumulates findings
- Writes the final JSON report (omits `cross_function` key when empty)

#### `context_builder.py` — Analysis engine

| Function | Role |
|---|---|
| `read_code_file()` | Recursive `#include` inlining with `FILE/LINE` markers |
| `analyze_ast()` | pycparser → `FuncDefVisitor`; fallback to `_find_functions_regex()` |
| `extract_function_source()` | Brace-matching extractor; prepends `// File:` header and line numbers |
| `_build_file_map()` / `_file_for_line()` | Maps merged-code line numbers back to per-file originals |
| `_extract_file_sections()` | Splits merged content back into per-file chunks (for header context) |
| `build_call_clusters()` | Union-Find clustering across target + callee functions; ego-neighborhood splitting for oversized clusters |
| `_classify_function_role()` | Regex scan for `malloc`/`strdup` (ALLOCATES) and `free` (FREES) |
| `_build_system_prompt()` | Per-function system prompt (focus on one function) |
| `_build_user_prompt()` | Per-function user prompt (target source + context section) |
| `_build_cross_function_system_prompt()` | Cross-function system prompt with CWE focus and attribution rules |
| `_build_cross_function_user_prompt()` | Cross-function user prompt with Memory Role Summary + all cluster sources |

#### `llm_client.py` — LLM interface

| Function | Role |
|---|---|
| `review_code()` | Logs request, dispatches to `_review_ollama()` or `_review_gemini()` |
| `_review_ollama()` | Posts to `/api/chat`; handles timeout/connection errors |
| `_review_gemini()` | Posts to Gemini `generateContent`; handles timeout/connection errors |
| `_parse_llm_json()` | Strips markdown fences; on `JSONDecodeError` runs `_repair_unescaped_quotes()` before giving up |
| `_repair_unescaped_quotes()` | Single-pass scanner that escapes bare `"` inside JSON string values — fixes a common LLM formatting mistake |

### Key design decisions

**Two-pass design — why not one pass?**
A single prompt covering all functions at once would exceed context limits for large files. The per-function pass keeps token usage predictable. The cross-function pass runs separately on small clusters (≤ 8 functions by default), so each LLM call stays focused and within context limits.

**Cross-file cluster membership**
The original design only clustered functions defined in the *target file*. This missed the common pattern where `main.c` is the only target function and all the interesting callee logic lives in included `.c` files. The fix: callee functions found anywhere in `functions` (via include merging) are added as secondary cluster nodes, enabling cross-file inter-procedural analysis.

**Function role classification**
Early versions of the cross-function prompt produced findings with wrong `functions_involved` — e.g. blaming the allocating function for a UAF instead of the freeing function. Injecting a pre-computed Memory Role Summary (ALLOCATES / FREES / USES) as a section in the user prompt gives the model explicit context to attribute findings correctly without over-constraining what it detects.

**pycparser fake typedefs**
`pycparser` has no system headers. Common C types (`uint8_t`, `size_t`, `FILE`, `ssize_t`, etc.) are injected as `typedef int <name>` before parsing to prevent parse failures on standard code.

**Dangling-pointer safe JSON repair**
LLMs sometimes write `"description": "strcmp with "admin_access""` — a bare `"` inside a JSON string. Rather than discarding the entire response as `{"raw": ...}`, `_repair_unescaped_quotes()` uses a single-pass character scanner: while inside a string, a `"` is treated as the closing delimiter only if the next non-space character is a JSON structural token (`,  }  ]  :`). Otherwise it is escaped in-place.
