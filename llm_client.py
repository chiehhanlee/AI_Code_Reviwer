#!/usr/bin/env python3
import sys
# WORKAROUND: The environment has a broken OpenSSL/cryptography setup that crashes on import.
# We block 'OpenSSL' so that requests/urllib3 fall back to the standard 'ssl' library.
sys.modules["OpenSSL"] = None

import os
import json
import re
import datetime
import requests

API_TIMEOUT   = 300              # seconds per request
LOG_FILE_PATH = "ai_request_log.jsonl"

ACTIVE_BACKEND = os.getenv("LLM_BACKEND", "ollama").lower()
if ACTIVE_BACKEND not in ("ollama", "gemini"):
    print(f"[ERROR] LLM_BACKEND must be 'ollama' or 'gemini', got: {ACTIVE_BACKEND!r}")
    sys.exit(1)

# Ollama (only validated when selected)
OLLAMA_URL = ""
if ACTIVE_BACKEND == "ollama":
    _host = os.getenv("OLLAMA_HOST")
    if not _host:
        print("[ERROR] OLLAMA_HOST environment variable is not set.")
        sys.exit(1)
    OLLAMA_URL = _host if _host.startswith("http") else f"http://{_host}"

# Gemini (only validated when selected)
GEMINI_API_KEY = ""
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
if ACTIVE_BACKEND == "gemini":
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    if not GEMINI_API_KEY:
        print("[ERROR] GEMINI_API_KEY environment variable is not set.")
        sys.exit(1)

#_OLLAMA_MODEL = "dagbs/deepseek-coder-v2-lite-instruct:q3_k_m"
#_OLLAMA_MODEL = "qwen3.5:9b"
_OLLAMA_MODEL = "dagbs/deepseek-coder-v2-lite-instruct:q4_k_m"
_GEMINI_MODEL = "gemini-2.0-flash"
MODEL_NAME = _GEMINI_MODEL if ACTIVE_BACKEND == "gemini" else _OLLAMA_MODEL


def _review_ollama(system_prompt, user_prompt, schema=None):
    url = f"{OLLAMA_URL}/api/chat"
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt}]
    body = {"model": MODEL_NAME, "messages": messages, "stream": False}
    if schema is not None:
        body["format"] = schema
    try:
        response = requests.post(url, json=body, timeout=API_TIMEOUT)
        if response.status_code == 200:
            return response.json().get("message", {}).get("content", "No response text found.")
        return f"API Error {response.status_code}: {response.text}"
    except requests.exceptions.Timeout:
        return f"Error: Request to Ollama timed out after {API_TIMEOUT} seconds."
    except requests.exceptions.ConnectionError:
        return f"Error: Could not connect to Ollama at {OLLAMA_URL}. Is Ollama running?"
    except Exception as e:
        return f"Error communicating with AI service: {e}"


def _review_gemini(system_prompt, user_prompt, schema=None):
    url = f"{GEMINI_BASE_URL}/{MODEL_NAME}:generateContent?key={GEMINI_API_KEY}"
    body = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
    }
    if schema is not None:
        body["generationConfig"] = {
            "response_mime_type": "application/json",
            "response_schema": schema,
        }
    try:
        response = requests.post(url, json=body, timeout=API_TIMEOUT)
        if response.status_code == 200:
            try:
                return response.json()["candidates"][0]["content"]["parts"][0]["text"]
            except (KeyError, IndexError):
                return "No response text found."
        return f"API Error {response.status_code}: {response.text}"
    except requests.exceptions.Timeout:
        return f"Error: Request to Gemini timed out after {API_TIMEOUT} seconds."
    except requests.exceptions.ConnectionError:
        return f"Error: Could not connect to Gemini API."
    except Exception as e:
        return f"Error communicating with AI service: {e}"


def review_code(system_prompt, user_prompt, func_name=None, schema=None):
    """Send pre-built prompts to the active LLM backend and return raw response text."""
    log_entry = {"timestamp": datetime.datetime.now().isoformat(),
                 "func_name": func_name,
                 "system": system_prompt,
                 "user": user_prompt}
    with open(LOG_FILE_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    if ACTIVE_BACKEND == "gemini":
        return _review_gemini(system_prompt, user_prompt, schema=schema)
    return _review_ollama(system_prompt, user_prompt, schema=schema)


def _repair_unescaped_quotes(text):
    """
    Escape bare double-quotes that the LLM embedded inside JSON string values.
    Uses a single-pass scanner: when inside a string, a '"' is treated as the
    closing delimiter only if the next non-space character is a JSON structural
    token (`,  }  ]  :  newline`).  Otherwise it is escaped in-place.
    """
    result = []
    in_string = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '\\' and in_string:
            # Already-escaped sequence — pass both characters through untouched.
            result.append(c)
            i += 1
            if i < n:
                result.append(text[i])
                i += 1
            continue
        if c == '"':
            if not in_string:
                in_string = True
                result.append(c)
            else:
                # Peek at the next non-space character to decide.
                j = i + 1
                while j < n and text[j] in ' \t':
                    j += 1
                if j >= n or text[j] in (',', '}', ']', ':', '\n', '\r'):
                    in_string = False
                    result.append(c)
                else:
                    result.append('\\"')
            i += 1
            continue
        result.append(c)
        i += 1
    return ''.join(result)


def _parse_llm_json(text):
    """Parse LLM response as JSON. Strips markdown code fences if present.
    Falls back to a quote-repair pass before giving up."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text.strip())
        text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(_repair_unescaped_quotes(text))
    except json.JSONDecodeError:
        return {"raw": text}
