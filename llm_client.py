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

API_TIMEOUT = int(os.getenv("API_TIMEOUT_SECS", "300"))  # override with API_TIMEOUT_SECS env var
LOG_FILE_PATH = "ai_request_log.jsonl"

ACTIVE_BACKEND = os.getenv("LLM_BACKEND", "ollama").lower()
if ACTIVE_BACKEND not in ("ollama", "ollama_cloud", "gemini"):
    print(f"[ERROR] LLM_BACKEND must be 'ollama', 'ollama_cloud', or 'gemini', got: {ACTIVE_BACKEND!r}")
    sys.exit(1)

# Local Ollama (only validated when selected)
OLLAMA_URL = ""
if ACTIVE_BACKEND == "ollama":
    _host = os.getenv("OLLAMA_HOST")
    if not _host:
        print("[ERROR] OLLAMA_HOST environment variable is not set.")
        sys.exit(1)
    OLLAMA_URL = _host if _host.startswith("http") else f"http://{_host}"

# Ollama Cloud / ollama.com (only validated when selected)
OLLAMA_CLOUD_URL = ""
OLLAMA_CLOUD_API_KEY = ""
if ACTIVE_BACKEND == "ollama_cloud":
    OLLAMA_CLOUD_API_KEY = os.getenv("OLLAMA_API_KEY", "")
    if not OLLAMA_CLOUD_API_KEY:
        print("[ERROR] OLLAMA_API_KEY environment variable is not set.")
        sys.exit(1)
    _cloud_host = os.getenv("OLLAMA_CLOUD_HOST", "https://ollama.com")    

    OLLAMA_CLOUD_URL = _cloud_host.rstrip("/")

# Gemini (only validated when selected)
GEMINI_API_KEY = ""
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
if ACTIVE_BACKEND == "gemini":
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    if not GEMINI_API_KEY:
        print("[ERROR] GEMINI_API_KEY environment variable is not set.")
        sys.exit(1)

_OLLAMA_MODEL       = os.getenv("OLLAMA_MODEL",       "dagbs/deepseek-coder-v2-lite-instruct:q4_k_m")
_OLLAMA_CLOUD_MODEL = os.getenv("OLLAMA_CLOUD_MODEL", "qwen3-coder-next:cloud")
_GEMINI_MODEL       = os.getenv("GEMINI_MODEL",       "gemini-2.0-flash")
if ACTIVE_BACKEND == "gemini":
    MODEL_NAME = _GEMINI_MODEL
elif ACTIVE_BACKEND == "ollama_cloud":
    MODEL_NAME = _OLLAMA_CLOUD_MODEL
else:
    MODEL_NAME = _OLLAMA_MODEL


def _review_ollama(system_prompt, user_prompt, schema=None, url=None, model=None):
    _url   = url   or f"{OLLAMA_URL}/api/chat"
    _model = model or MODEL_NAME
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt}]
    body = {"model": _model, "messages": messages, "stream": False}
    if schema is not None:
        body["format"] = schema
    try:
        response = requests.post(_url, json=body, timeout=API_TIMEOUT)
        if response.status_code == 200:
            return response.json().get("message", {}).get("content", "No response text found.")
        return f"API Error {response.status_code}: {response.text}"
    except requests.exceptions.Timeout:
        return f"Error: Request to Ollama timed out after {API_TIMEOUT} seconds."
    except requests.exceptions.ConnectionError:
        return f"Error: Could not connect to Ollama at {_url}. Is Ollama running?"
    except Exception as e:
        return f"Error communicating with AI service: {e}"


def _review_ollama_cloud(system_prompt, user_prompt, schema=None, url=None, key=None, model=None):
    _url   = url   or "https://ollama.com/api/chat"
    _key   = key   or OLLAMA_CLOUD_API_KEY
    _model = model or MODEL_NAME
    headers = {"Authorization": f"Bearer {_key}", "Content-Type": "application/json"}
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt}]
    body = {"model": _model, "messages": messages, "stream": False}
    if schema is not None:
        body["format"] = schema
    try:
        response = requests.post(_url, json=body, headers=headers, timeout=API_TIMEOUT)
        if response.status_code == 200:
            return response.json().get("message", {}).get("content", "No response text found.")
        return f"API Error {response.status_code}: {response.text}"
    except requests.exceptions.Timeout:
        return f"Error: Request to Ollama Cloud timed out after {API_TIMEOUT} seconds."
    except requests.exceptions.ConnectionError:
        return f"Error: Could not connect to Ollama Cloud at {_url}."
    except Exception as e:
        return f"Error communicating with AI service: {e}"


def _review_gemini(system_prompt, user_prompt, schema=None, key=None, model=None):
    _key   = key   or GEMINI_API_KEY
    _model = model or MODEL_NAME
    url = f"{GEMINI_BASE_URL}/{_model}:generateContent?key={_key}"
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
    if ACTIVE_BACKEND == "ollama_cloud":
        return _review_ollama_cloud(system_prompt, user_prompt, schema=schema)
    return _review_ollama(system_prompt, user_prompt, schema=schema)


# ---------------------------------------------------------------------------
# Verifier backend — independently configured, falls back to analysis backend
# ---------------------------------------------------------------------------
VERIFY_BACKEND = os.getenv("VERIFY_BACKEND", ACTIVE_BACKEND).lower()
if VERIFY_BACKEND not in ("ollama", "ollama_cloud", "gemini"):
    print(f"[ERROR] VERIFY_BACKEND must be 'ollama', 'ollama_cloud', or 'gemini', "
          f"got: {VERIFY_BACKEND!r}")
    sys.exit(1)

_verify_cfg = {}

if VERIFY_BACKEND == "ollama":
    _vhost = os.getenv("VERIFY_OLLAMA_HOST") or os.getenv("OLLAMA_HOST", "")
    if not _vhost:
        print("[ERROR] VERIFY_OLLAMA_HOST (or OLLAMA_HOST) is not set for verifier.")
        sys.exit(1)
    _verify_cfg["url"] = (_vhost if _vhost.startswith("http") else f"http://{_vhost}") + "/api/chat"

elif VERIFY_BACKEND == "ollama_cloud":
    _vkey = os.getenv("VERIFY_OLLAMA_API_KEY") or os.getenv("OLLAMA_API_KEY", "")
    if not _vkey:
        print("[ERROR] VERIFY_OLLAMA_API_KEY (or OLLAMA_API_KEY) is not set for verifier.")
        sys.exit(1)
    _vhost = os.getenv("VERIFY_OLLAMA_CLOUD_HOST",
                       os.getenv("OLLAMA_CLOUD_HOST", "https://ollama.com"))
    _verify_cfg["url"] = _vhost.rstrip("/") + "/api/chat"
    _verify_cfg["key"] = _vkey

elif VERIFY_BACKEND == "gemini":
    _vkey = os.getenv("VERIFY_GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY", "")
    if not _vkey:
        print("[ERROR] VERIFY_GEMINI_API_KEY (or GEMINI_API_KEY) is not set for verifier.")
        sys.exit(1)
    _verify_cfg["key"] = _vkey

_default_verify_models = {
    "ollama":       _OLLAMA_MODEL,
    "ollama_cloud": _OLLAMA_CLOUD_MODEL,
    "gemini":       _GEMINI_MODEL,
}
VERIFY_MODEL_NAME = os.getenv("VERIFY_MODEL", _default_verify_models[VERIFY_BACKEND])
_verify_cfg["model"] = VERIFY_MODEL_NAME


def verify_findings(system_prompt, user_prompt, schema=None):
    """Send verification prompts to the verifier backend (independently configured,
    or inherited from the analysis backend when VERIFY_BACKEND is not set)."""

    log_entry = {"timestamp": datetime.datetime.now().isoformat(),
                 "func_name": "__verify__",
                 "system": system_prompt,
                 "user": user_prompt}
    with open(LOG_FILE_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    if VERIFY_BACKEND == "ollama":
        return _review_ollama(system_prompt, user_prompt, schema=schema,
                              url=_verify_cfg.get("url"), model=_verify_cfg.get("model"))
    if VERIFY_BACKEND == "ollama_cloud":
        return _review_ollama_cloud(system_prompt, user_prompt, schema=schema,
                                    url=_verify_cfg.get("url"), key=_verify_cfg.get("key"),
                                    model=_verify_cfg.get("model"))
    # gemini
    return _review_gemini(system_prompt, user_prompt, schema=schema,
                          key=_verify_cfg.get("key"), model=_verify_cfg.get("model"))


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
