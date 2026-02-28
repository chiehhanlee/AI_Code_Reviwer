#!/usr/bin/env python3
import sys
# WORKAROUND: The environment has a broken OpenSSL/cryptography setup that crashes on import.
# We block 'OpenSSL' so that requests/urllib3 fall back to the standard 'ssl' library.
sys.modules["OpenSSL"] = None

import os
# Ollama configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST")
if not OLLAMA_HOST:
    print("[ERROR] OLLAMA_HOST environment variable is not set.")
    sys.exit(1)
OLLAMA_URL = OLLAMA_HOST if OLLAMA_HOST.startswith("http") else f"http://{OLLAMA_HOST}"

# ---------------------------------------------------------------------------
# --- Configuration ----------------------------------------------------------
# ---------------------------------------------------------------------------

# -- Model --
MODEL_NAME    = "dagbs/deepseek-coder-v2-lite-instruct:q3_k_m"
# MODEL_NAME  = "llama3.2:3b"   # alternative model
API_TIMEOUT   = 300             # seconds per Ollama request
LOG_FILE_PATH = "ai_request_log.jsonl"
INCLUDE_DIRS  = []              # additional header/source search paths (like -I flags)

# -- Task --
ROLE = "You are an expert C/C++ security researcher and code reviewer using english"

FOCUS_AREAS = """\
1. Buffer overflows
2. Format string vulnerabilities
3. Integer overflows/underflows
4. Memory leaks and management issues
5. Input validation failures"""

CONTEXT_SECTION_TEMPLATE = """\
## Supporting Context
The following functions are called by or call `{func_name}`. They are provided \
ONLY to help you understand data flow and interactions. Do NOT report \
vulnerabilities in them.
```c
{context_code}
```
"""

# -- Output format --
OUTPUT_FORMAT_FUNCTION = """\
Respond with a JSON object only — no prose, no markdown fences. Schema:
{{
  "vulnerabilities": [
    {{
      "line": <approximate line number as integer>,
      "description": "<vulnerability description>"
    }},
    {{
      "line": <approximate line number as integer>,
      "description": "<vulnerability description>"
    }}
  ]
}}
List ALL vulnerabilities found — one object per issue. If no vulnerabilities are found, return an empty "vulnerabilities" array."""

OUTPUT_FORMAT_FULL_FILE = """\
Respond with a JSON object only — no prose, no markdown fences. Schema:
{
  "vulnerabilities": [
    {
      "line": <approximate line number as integer>,
      "description": "<vulnerability description>"
    },
    {
      "line": <approximate line number as integer>,
      "description": "<vulnerability description>"
    }
  ]
}
List ALL vulnerabilities found — one object per issue. If no vulnerabilities are found, return an empty "vulnerabilities" array."""

import json
import re

# --- AST Parsing Classes ---
try:
    from pycparser import c_parser, c_ast
    HAS_PYCPARSER = True
except ImportError:
    HAS_PYCPARSER = False

class FuncCallVisitor(c_ast.NodeVisitor):
    def __init__(self):
        self.calls = set()

    def visit_FuncCall(self, node):
        if getattr(node.name, 'name', None):
            self.calls.add(node.name.name)
        self.generic_visit(node)

class FuncDefVisitor(c_ast.NodeVisitor):
    def __init__(self):
        self.functions = {}

    def visit_FuncDef(self, node):
        func_name = node.decl.name
        start_line = node.coord.line
        
        call_visitor = FuncCallVisitor()
        call_visitor.visit(node.body)
        
        self.functions[func_name] = {
            'start_line': start_line,
            'calls': list(call_visitor.calls),
        }
        self.generic_visit(node)

def extract_function_source(code_lines, start_line, filename="<unknown>", line_offset=0):
    start_idx = start_line - 1
    brace_count = 0
    found_brace = False
    end_idx = start_idx
    
    # Simple brace matching to extract function body
    for i in range(start_idx, len(code_lines)):
        line = code_lines[i]
        
        # Don't match braces inside comments or strings (assuming pruned context mostly)
        for char in line:
            if char == '{':
                found_brace = True
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                
        if found_brace and brace_count == 0:
            end_idx = i
            break
            
    if not found_brace:
        return ""
        
    # Prepend line numbers and filename
    source_lines = []
    source_lines.append(f"// File: {filename}")
    for i in range(start_idx, end_idx + 1):
         source_lines.append(f"{i + 1 + line_offset:4d} | {code_lines[i]}")
         
    return '\n'.join(source_lines)

def _build_file_map(code_content):
    """
    Scan the merged code_content for '// --- FILE: name LINE: N ---' markers
    inserted by read_code_file().
    Returns a sorted list of (merged_line_1indexed, filename, orig_line_in_file).
    """
    file_map = []
    marker_re = re.compile(r'^// --- FILE: (.+) LINE: (\d+) ---$')
    for i, line in enumerate(code_content.split('\n'), start=1):
        m = marker_re.match(line)
        if m:
            file_map.append((i, m.group(1), int(m.group(2))))
    return file_map


def _file_for_line(file_map, merged_line, fallback):
    """
    Return (filename, line_offset) for a given 1-indexed merged line number.
    line_offset is chosen so that extract_function_source() displays per-file
    line numbers, correctly accounting for spliced include blocks.

    extract_function_source displays: i + 1 + line_offset  (i = merged_line - 1)
    = merged_line + line_offset
    We want displayed = orig_line + (merged_line - marker_merged_line) - 1
    → line_offset = orig_line - marker_merged_line - 1
    """
    filename = fallback
    line_offset = 0
    for mline, fname, orig_line in file_map:
        if mline <= merged_line:
            filename = fname
            line_offset = orig_line - mline - 1
        else:
            break
    return filename, line_offset


def _extract_file_sections(code_content, file_map):
    """
    Extract the content belonging to each file from the merged code_content.
    Returns {filename: content_string}, concatenating multiple sections for
    files (like the outer file) that are split by included content.
    """
    lines = code_content.split('\n')
    sections = {}
    for i, (mline, fname, _orig_line) in enumerate(file_map):
        # marker is at lines[mline-1]; content starts at lines[mline]
        content_start = mline
        content_end = file_map[i + 1][0] - 1 if i + 1 < len(file_map) else len(lines)
        chunk = '\n'.join(lines[content_start:content_end])
        if fname in sections:
            sections[fname] += '\n' + chunk
        else:
            sections[fname] = chunk
    return sections


def _find_functions_regex(stripped_code):
    """
    Fallback function finder using brace-depth tracking + signature heuristics.
    Used when pycparser fails on macro-heavy C (e.g. TAILQ_ENTRY, TOKEN_COUNT).
    Returns {func_name: {'start_line': int, 'calls': list}} — same shape as
    FuncDefVisitor.functions so the rest of analyze_ast() is unchanged.
    """
    C_KEYWORDS = {
        'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
        'return', 'break', 'continue', 'goto', 'typedef', 'struct', 'union',
        'enum', 'sizeof', '__typeof__', '__attribute__', 'asm', '__asm__',
        '__asm', 'volatile', '__volatile__',
    }
    ident_call_re = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')

    lines = stripped_code.split('\n')
    result = {}
    brace_depth = 0
    pending_name = None
    pending_start = None
    sig_buf = []

    for lineno, line in enumerate(lines, start=1):
        opens = line.count('{')
        closes = line.count('}')

        if brace_depth == 0:
            if opens > 0:
                sig = ' '.join(sig_buf + [line[:line.index('{')]])
                if ')' in sig and '=' not in sig:
                    candidates = [m for m in ident_call_re.findall(sig)
                                  if m not in C_KEYWORDS]
                    if candidates:
                        pending_name = candidates[-1]
                        pending_start = lineno
                sig_buf = []
                brace_depth += opens - closes
            else:
                stripped = line.strip()
                if ';' in stripped:
                    sig_buf = []
                elif stripped and not stripped.startswith('*'):
                    sig_buf.append(stripped)
        else:
            brace_depth += opens - closes
            if brace_depth == 0 and pending_name:
                body = '\n'.join(lines[pending_start - 1:lineno])
                calls = list(
                    set(ident_call_re.findall(body))
                    - C_KEYWORDS - {pending_name}
                )
                result[pending_name] = {
                    'start_line': pending_start,
                    'calls': calls,
                }
                pending_name = None
                pending_start = None

    return result


def analyze_ast(code_content,filepath="<unknown>"):
    if not HAS_PYCPARSER:
        print("[WARNING] pycparser not found. Skipping AST analysis.")
        return {}

    # Build file map before pruning (markers are // comments, lost after prune_context)
    file_map = _build_file_map(code_content)

    # Strip directives and comments for AST parsing
    code_no_comments = prune_context(code_content)
    
    lines = code_no_comments.split('\n')
    out = []
    for line in lines:
        if line.strip().startswith('#'):
            out.append('')
        else:
            out.append(line)
            
    ast_code_stripped = '\n'.join(out)

    # Inject standard types
    typedefs = """
typedef unsigned int size_t;
typedef void FILE;
typedef int ssize_t;
typedef int uint32_t;
typedef int int32_t;
typedef int uint8_t;
typedef int int8_t;
typedef int uint16_t;
typedef int int16_t;
typedef int uint64_t;
typedef int int64_t;
"""
    ast_code = typedefs + "\n" + ast_code_stripped
    typedefs_lines = typedefs.count('\n') + 1  # lines added before the real code

    parser = c_parser.CParser()
    try:
        ast = parser.parse(ast_code, filename='<code_content>')
        visitor = FuncDefVisitor()
        visitor.visit(ast)
        funcs_data = visitor.functions
    except Exception as e:
        print(f"[WARNING] pycparser failed ({e}), retrying with regex extraction.")
        funcs_data = _find_functions_regex(ast_code_stripped)
        typedefs_lines = 0  # regex line numbers already match code_no_comments

    # Extract source code for each function using the original code_no_comments lines
    original_lines = code_no_comments.split('\n')

    result = {}
    for func_name, data in funcs_data.items():
        original_start_line = data['start_line'] - typedefs_lines
        if original_start_line < 1:
            original_start_line = 1
        filename, line_offset = _file_for_line(file_map, original_start_line, filepath)
        source_text = extract_function_source(
            original_lines, original_start_line,
            filename=filename, line_offset=line_offset)
        result[func_name] = {
            'source': source_text,
            'calls': data['calls'],
            'file': filename,
        }

    return result

def prune_context(code_content):
    """
    Minifies C code by removing comments and extra whitespace.
    This reduces token usage and noise for the AI.
    """
    # Remove single-line comments // ...
    code_content = re.sub(r'//.*', '', code_content)
    # Remove multi-line comments /* ... */
    code_content = re.sub(r'/\\*.*?\\*/', '', code_content, flags=re.DOTALL)
    return code_content

def _resolve_include(include_file, base_dir, include_dirs):
    """Return the first existing path for include_file, searching base_dir then include_dirs."""
    for directory in [base_dir] + list(include_dirs):
        candidate = os.path.join(directory, include_file)
        if os.path.exists(candidate):
            return candidate
    return None


def read_code_file(filepath, processed_files=None, include_dirs=()):
    """
    Reads C source file and recursively merges local #include "..." files.
    Searches base_dir of the current file first, then include_dirs in order.
    Angle-bracket includes (<...>) are ignored (system headers).
    """
    if processed_files is None:
        processed_files = set()

    abs_path = os.path.abspath(filepath)
    if abs_path in processed_files:
        return ""

    processed_files.add(abs_path)

    try:
        if not os.path.exists(abs_path):
            return f"// [MISSING FILE] {filepath}\n"

        with open(abs_path, 'r') as f:
            content = f.read()

        base_dir = os.path.dirname(abs_path)
        basename = os.path.basename(filepath)
        orig_line = 1  # tracks current line number within this file
        merged_content = f"// --- FILE: {basename} LINE: 1 ---\n"

        for line in content.split('\n'):
            match = re.match(r'^\s*#include\s+"([^"]+)"', line)
            if match:
                orig_line += 1  # the #include line itself is not emitted
                include_file = match.group(1)
                include_path = _resolve_include(include_file, base_dir, include_dirs)
                if include_path:
                    merged_content += read_code_file(include_path, processed_files, include_dirs)
                    # Also pull in the companion .c file if it exists
                    c_file = include_file.replace('.h', '.c')
                    c_path = _resolve_include(c_file, base_dir, include_dirs)
                    if c_path and c_file != os.path.basename(filepath):
                        merged_content += read_code_file(c_path, processed_files, include_dirs)
                    # Resume marker: tells the parser we're back in this file at orig_line
                    merged_content += f"// --- FILE: {basename} LINE: {orig_line} ---\n"
                else:
                    merged_content += f"// [MISSING FILE] {include_file}\n"
            else:
                merged_content += line + "\n"
                orig_line += 1

        return merged_content

    except Exception as e:
        return f"// Error reading {filepath}: {e}\n"

def _build_prompt(code_content, func_name=None, context_code=""):
    if func_name:
        context_section = ""
        if context_code:
            context_section = CONTEXT_SECTION_TEMPLATE.format(
                func_name=func_name, context_code=context_code)
        output_format = OUTPUT_FORMAT_FUNCTION.format(func_name=func_name)
        return (
            f"{ROLE}\n\n"
            f"## Task\n"
            f"Analyze the target function `{func_name}` for security vulnerabilities. "
            f"Focus exclusively on the target function — do not report issues in the "
            f"supporting context functions.\n\n"
            f"## Focus Areas\n{FOCUS_AREAS}\n\n"
            f"## Output Format\n{output_format}\n"
            f"{context_section}"
            f"## Target Function: `{func_name}`\n"
            f"Analyze this function for the vulnerabilities listed above.\n"
            f"```c\n{code_content}\n```\n"
        )
    else:
        return (
            f"{ROLE}\n\n"
            f"## Task\n"
            f"Analyze the following C code for security vulnerabilities.\n\n"
            f"## Focus Areas\n{FOCUS_AREAS}\n\n"
            f"## Output Format\n{OUTPUT_FORMAT_FULL_FILE}\n\n"
            f"## Code\n"
            f"```c\n{code_content}\n```\n"
        )


def review_code(code_content, func_name=None, context_code=""):
    """Sends the code to the LLM for security review using Ollama."""
    import requests, datetime

    prompt_text = _build_prompt(code_content, func_name=func_name, context_code=context_code)

    log_entry = {"timestamp": datetime.datetime.now().isoformat(),
                 "func_name": func_name, "prompt": prompt_text}
    with open(LOG_FILE_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    url = f"{OLLAMA_URL}/api/generate"
    try:
        response = requests.post(url,
                                 json={"model": MODEL_NAME, "prompt": prompt_text, "stream": False},
                                 timeout=API_TIMEOUT)
        if response.status_code == 200:
            return response.json().get("response", "No response text found.")
        return f"API Error {response.status_code}: {response.text}"
    except requests.exceptions.Timeout:
        return f"Error: Request to Ollama timed out after {API_TIMEOUT} seconds."
    except requests.exceptions.ConnectionError:
        return f"Error: Could not connect to Ollama at {OLLAMA_URL}. Is Ollama running?"
    except Exception as e:
        return f"Error communicating with AI service: {e}"

def _parse_llm_json(text):
    """Parse LLM response as JSON. Strips markdown code fences if present."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text.strip())
        text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AI C/C++ security reviewer")
    parser.add_argument("filepath", help="C source file to analyze")
    parser.add_argument("-I", "--include-dir", action="append", dest="include_dirs",
                        default=[], metavar="DIR",
                        help="Additional include search path (repeatable, like gcc -I)")
    parser.add_argument("-o", "--output", dest="output", default=None, metavar="FILE",
                        help="Output JSON file (default: <source>.audit.json)")
    args = parser.parse_args()

    filepath = args.filepath
    output_path = args.output or (os.path.splitext(filepath)[0] + ".audit.json")
    include_dirs = INCLUDE_DIRS + [os.path.abspath(d) for d in args.include_dirs]

    if include_dirs:
        print(f"Include search paths: {include_dirs}", file=sys.stderr)
    print(f"Analyzing {filepath}...", file=sys.stderr)

    code_content = read_code_file(filepath, include_dirs=include_dirs)
    report = {"file": filepath, "model": MODEL_NAME}

    if HAS_PYCPARSER:
        print("Extracting AST and function dependencies...", file=sys.stderr)
        functions = analyze_ast(code_content, filepath)

        if not functions:
            print("Failed to build AST. Falling back to full file review...", file=sys.stderr)
            pruned_content = prune_context(code_content)
            report["mode"] = "full-file"
            report.update(_parse_llm_json(review_code(pruned_content)))
        else:
            target_basename = os.path.basename(filepath)
            target_funcs = {n: d for n, d in functions.items()
                            if d['file'] == target_basename}
            total = len(target_funcs)
            print(f"Found {len(functions)} functions ({total} in target file). "
                  f"Auditing function-by-function...", file=sys.stderr)
            report["mode"] = "function-by-function"
            report["functions"] = []

            # Build header context once — shared across all function reviews
            file_map = _build_file_map(code_content)
            file_sections = _extract_file_sections(code_content, file_map)
            header_context = ""
            for fname, content in file_sections.items():
                if fname.endswith('.h') and fname != target_basename:
                    header_context += f"// --- Header: {fname} ---\n{content}\n"

            for idx, (func_name, data) in enumerate(target_funcs.items(), start=1):
                pct = int(idx / total * 100)
                print(f"[{idx}/{total}] ({pct}%) Auditing: {func_name}", file=sys.stderr)

                context_code = header_context
                dependencies = [c for c in data['calls'] if c in functions and c != func_name]
                if dependencies:
                    for dep in dependencies:
                        context_code += f"// --- Context Function: {dep} ---\n"
                        context_code += functions[dep]['source'] + "\n"

                raw = review_code(data['source'], func_name=func_name, context_code=context_code)
                entry = {"function": func_name, **_parse_llm_json(raw)}
                report["functions"].append(entry)
    else:
        print("Pruning code context...", file=sys.stderr)
        pruned_content = prune_context(code_content)
        report["mode"] = "full-file"
        report.update(_parse_llm_json(review_code(pruned_content)))

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Audit report written to {output_path}", file=sys.stderr)

if __name__ == "__main__":
    main()
