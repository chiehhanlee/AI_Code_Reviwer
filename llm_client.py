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

MODEL_NAME    = "dagbs/deepseek-coder-v2-lite-instruct:q3_k_m"
API_TIMEOUT   = 300              # seconds per Ollama request
LOG_FILE_PATH = "ai_request_log.jsonl"

OLLAMA_HOST = os.getenv("OLLAMA_HOST")
if not OLLAMA_HOST:
    print("[ERROR] OLLAMA_HOST environment variable is not set.")
    sys.exit(1)
OLLAMA_URL = OLLAMA_HOST if OLLAMA_HOST.startswith("http") else f"http://{OLLAMA_HOST}"


def review_code(system_prompt, user_prompt, func_name=None):
    """Send pre-built prompts to Ollama /api/chat and return raw response text."""
    log_entry = {"timestamp": datetime.datetime.now().isoformat(),
                 "func_name": func_name,
                 "system": system_prompt,
                 "user": user_prompt}
    with open(LOG_FILE_PATH, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    url = f"{OLLAMA_URL}/api/chat"
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt}]
    try:
        response = requests.post(url,
                                 json={"model": MODEL_NAME, "messages": messages,
                                       "stream": False},
                                 timeout=API_TIMEOUT)
        if response.status_code == 200:
            return response.json().get("message", {}).get("content",
                                                          "No response text found.")
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
