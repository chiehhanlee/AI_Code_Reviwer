import sys
# WORKAROUND: The environment has a broken OpenSSL/cryptography setup that crashes on import.
# We block 'OpenSSL' so that requests/urllib3 fall back to the standard 'ssl' library.
sys.modules["OpenSSL"] = None

import os
try:
    import google.generativeai as genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False


# Configure the API key
API_KEY = os.getenv("GEMINI_API_KEY")

import re

def prune_context(code_content):
    """
    Minifies C code by removing comments and extra whitespace.
    This reduces token usage and noise for the AI.
    """
    # Remove single-line comments // ...
    code_content = re.sub(r'//.*', '', code_content)
    # Remove multi-line comments /* ... */
    code_content = re.sub(r'/\*.*?\*/', '', code_content, flags=re.DOTALL)
    # Remove extra whitespace (multiple spaces/tabs to single space, multiple newlines to single)
    code_content = re.sub(r'\s+', ' ', code_content).strip()
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
            return f"// [MISSING FILE] {filepath}\n"

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

def review_code(code_content):
    """Sends the code to the LLM for security review."""
    if not API_KEY:

        print("\n[WARNING] GEMINI_API_KEY environment variable not set.")
        print("Skipping actual API call. Mocking response for demonstration.")
        return mock_review_response(code_content)

    # DIRECT REST API FALLBACK (Since installed library is too old)
    import requests
    import json

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={API_KEY}"
    
    headers = {
        'Content-Type': 'application/json'
    }
    
    prompt_text = f"""
You are an expert C/C++ security researcher and code reviewer.
Your task is to analyze the following C code for security vulnerabilities.
Focus on:
1. Buffer overflows
2. Format string vulnerabilities
3. Integer overflows/underflows
4. Memory leaks and management issues
5. Input validation failures

For each issue found:
- specific the line number (approximate)
- Describe the vulnerability
- Explain the potential impact
- Suggest a fix

Here is the code:
```c
{code_content}
```
"""
    
    data = {
        "contents": [{
            "parts": [{
                "text": prompt_text
            }]
        }]
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        
        if response.status_code == 200:
            result = response.json()
            # Extract text from response
            try:
                candidates = result.get('candidates', [])
                if candidates:
                    return candidates[0]['content']['parts'][0]['text']
                else:
                    return "AI returned no candidates. Raw response: " + str(result)
            except (KeyError, IndexError) as e:
                 return f"Error parsing API response: {e}. Raw: {str(result)}"
        else:
            return f"API Error {response.status_code}: {response.text}"

    except Exception as e:
        return f"Error communicating with AI service: {e}"

def mock_review_response(code_content):
    """Provides a canned response for testing without an API key."""
    return """
[MOCK AI REVIEW REPORT]

1. **Buffer Overflow**
   - **Location**: `strcpy(buffer, input);`
   - **Issue**: Source string structure is blindly copied to a fixed-size buffer.
   - **Impact**: Code execution or crash.
   - **Fix**: Use `strncpy` or explicitly check length.

2. **Format String Vulnerability**
   - **Location**: `printf(buffer);`
   - **Issue**: Passing user-controlled input directly as the format string.
   - **Impact**: Information leak or crash.
   - **Fix**: Use `printf("%s", buffer);`.
"""

def main():
    if len(sys.argv) < 2:
        print("Usage: python ai_code_reviewer.py <path_to_c_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    print(f"Analyzing {filepath}...")
    
    code_content = read_code_file(filepath)
    
    # Prune context to optimize token usage
    print("Pruning code context...")
    pruned_content = prune_context(code_content)
    
    review_report = review_code(pruned_content)
    
    print("\n" + "="*30)
    print(" SECURITY REVIEW REPORT ")
    print("="*30 + "\n")
    print(review_report)

if __name__ == "__main__":
    main()
