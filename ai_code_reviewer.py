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
First, provide a 1-2 sentence summary of what `{func_name}` does.
Then, for each vulnerability found IN THE TARGET FUNCTION:
- Line number (approximate)
- Vulnerability description"""

OUTPUT_FORMAT_FULL_FILE = """\
For each vulnerability found:
- Line number (approximate)
- Vulnerability description"""

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

    # Find the original filename from the first line if it exists
    original_filename = filepath
    for line in original_lines:
        if line.startswith("// --- FILE:"):
            original_filename = line.replace("// --- FILE:", "").replace("---", "").strip()
            break

    result = {}
    for func_name, data in funcs_data.items():
        original_start_line = data['start_line'] - typedefs_lines
        if original_start_line < 1:
            original_start_line = 1
        source_text = extract_function_source(
            original_lines, original_start_line,
            filename=original_filename, line_offset=-1)
        result[func_name] = {
            'source': source_text,
            'calls': data['calls']
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

def read_code_file(filepath, processed_files=None):
    """
    Reads C source file and recursively merges local #include "..." files.
    Values found in <> are ignored (system headers).
    """
    if processed_files is None:
        processed_files = set()
    
    abs_path = os.path.abspath(filepath)
    if abs_path in processed_files:
        return "" # Avoid infinite recursion
    
    processed_files.add(abs_path)
    
    try:
        if not os.path.exists(abs_path):
            # Try finding it in the same directory as the script if not absolute
            return f"// [MISSING FILE] {filepath}\\n"

        with open(abs_path, 'r') as f:
            content = f.read()
            
        base_dir = os.path.dirname(abs_path)
        merged_content = f"// --- FILE: {os.path.basename(filepath)} ---\n"
        
        lines = content.split('\n')
        for line in lines:
            # Check for #include "filename"
            match = re.match(r'^\s*#include\s+"([^"]+)"', line)
            if match:
                include_file = match.group(1)
                include_path = os.path.join(base_dir, include_file)
                merged_content += read_code_file(include_path, processed_files)
                
                # Also try to include the .c implementation if it exists
                c_file = include_file.replace('.h', '.c')
                c_path = os.path.join(base_dir, c_file)
                if os.path.exists(c_path) and c_file != os.path.basename(filepath):
                     merged_content += read_code_file(c_path, processed_files)
            else:
                merged_content += line + "\n"
                
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
    import requests, json, datetime

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

def main():
    if len(sys.argv) < 2:
        print("Usage: python ai_code_reviewer.py <path_to_c_file>")
        sys.exit(1)

    REPORT_SEP   = "=" * 30
    REPORT_TITLE = " SECURITY REVIEW REPORT "

    filepath = sys.argv[1]
    print(f"Analyzing {filepath}...")
    
    code_content = read_code_file(filepath)
    if HAS_PYCPARSER:
        print("Extracting AST and function dependencies...")
        functions = analyze_ast(code_content, filepath)
    
        if not functions:
            print("Failed to build AST. Falling back to full file review...")
            pruned_content = prune_context(code_content)
            review_report = review_code(pruned_content)
            print("\\n" + REPORT_SEP)
            print(REPORT_TITLE)
            print(REPORT_SEP + "\\n")
            print(review_report)
        else:
            total = len(functions)
            print(f"Found {total} functions. Auditing function-by-function...")

            for idx, (func_name, data) in enumerate(functions.items(), start=1):
                pct = int(idx / total * 100)
                print(f"\n{'='*40}")
                print(f" [{idx}/{total}] ({pct}%) Auditing function: {func_name} ")
                print(f"{'='*40}")
                
                # Build context block (supporting functions only)
                context_code = ""
                dependencies = [c for c in data['calls'] if c in functions and c != func_name]
                if dependencies:
                    for dep in dependencies:
                        context_code += f"// --- Context Function: {dep} ---\n"
                        context_code += functions[dep]['source'] + "\n"

                review_report = review_code(data['source'], func_name=func_name, context_code=context_code)
                print(review_report)
                
    else:
        print("Pruning code context...")
        pruned_content = prune_context(code_content)
        review_report = review_code(pruned_content)
        print("\n" + REPORT_SEP)
        print(REPORT_TITLE)
        print(REPORT_SEP + "\n")
        print(review_report)

if __name__ == "__main__":
    main()
