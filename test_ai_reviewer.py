#!/usr/bin/env python3
import sys
sys.modules["OpenSSL"] = None  # broken OpenSSL workaround — must precede llm_client import

import os
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")  # required for llm_client import

import unittest
from unittest.mock import patch, MagicMock, mock_open
import requests

import context_builder
import llm_client


class TestContextBuilder(unittest.TestCase):

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data="void func() { char b[10]; }")
    def test_read_code_file(self, mock_file, mock_exists):
        content = context_builder.read_code_file("dummy.c")
        self.assertIn("// --- FILE: dummy.c LINE: 1 ---", content)
        self.assertIn("void func() { char b[10]; }", content)

    def test_prune_context_removes_line_comments(self):
        code = "int x = 1; // this is a comment\n"
        result = context_builder.prune_context(code)
        self.assertNotIn("this is a comment", result)
        self.assertIn("int x = 1;", result)

    def test_build_system_prompt_full_file(self):
        prompt = context_builder._build_system_prompt()
        self.assertIn("security vulnerabilities", prompt)
        self.assertIn("Buffer overflows", prompt)

    def test_build_system_prompt_function(self):
        prompt = context_builder._build_system_prompt(func_name="my_func")
        self.assertIn("my_func", prompt)
        self.assertIn("target function", prompt)

    def test_build_user_prompt_full_file(self):
        prompt = context_builder._build_user_prompt("int main() {}")
        self.assertIn("int main() {}", prompt)

    def test_build_user_prompt_function(self):
        prompt = context_builder._build_user_prompt("int foo() {}", func_name="foo")
        self.assertIn("foo", prompt)
        self.assertIn("int foo() {}", prompt)

    def test_build_user_prompt_function_with_context(self):
        prompt = context_builder._build_user_prompt(
            "int foo() {}", func_name="foo", context_code="int bar() {}")
        self.assertIn("Supporting Context", prompt)
        self.assertIn("int bar() {}", prompt)


class TestLLMClient(unittest.TestCase):

    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post')
    def test_review_code_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": {"content": "found issue"}}
        mock_post.return_value = mock_response

        result = llm_client.review_code("system prompt", "user prompt")
        self.assertEqual(result, "found issue")

    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post')
    def test_review_code_api_error(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.return_value = mock_response

        result = llm_client.review_code("system prompt", "user prompt")
        self.assertIn("API Error 500", result)

    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post', side_effect=requests.exceptions.Timeout)
    def test_review_code_timeout(self, mock_post):
        result = llm_client.review_code("system prompt", "user prompt")
        self.assertIn("timed out", result)

    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post', side_effect=requests.exceptions.ConnectionError)
    def test_review_code_connection_error(self, mock_post):
        result = llm_client.review_code("system prompt", "user prompt")
        self.assertIn("Could not connect", result)

    @patch('llm_client.ACTIVE_BACKEND', 'gemini')
    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post')
    def test_review_code_gemini_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "gemini found issue"}]}}]
        }
        mock_post.return_value = mock_response

        result = llm_client.review_code("system prompt", "user prompt")
        self.assertEqual(result, "gemini found issue")

    @patch('llm_client.ACTIVE_BACKEND', 'gemini')
    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post')
    def test_review_code_gemini_api_error(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.text = "Too Many Requests"
        mock_post.return_value = mock_response

        result = llm_client.review_code("system prompt", "user prompt")
        self.assertIn("API Error 429", result)

    @patch('llm_client.ACTIVE_BACKEND', 'gemini')
    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post', side_effect=requests.exceptions.Timeout)
    def test_review_code_gemini_timeout(self, mock_post):
        result = llm_client.review_code("system prompt", "user prompt")
        self.assertIn("timed out", result)

    @patch('llm_client.ACTIVE_BACKEND', 'gemini')
    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post', side_effect=requests.exceptions.ConnectionError)
    def test_review_code_gemini_connection_error(self, mock_post):
        result = llm_client.review_code("system prompt", "user prompt")
        self.assertIn("Could not connect", result)

    @patch('llm_client.ACTIVE_BACKEND', 'gemini')
    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post')
    def test_review_code_gemini_malformed_response(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_post.return_value = mock_response

        result = llm_client.review_code("system prompt", "user prompt")
        self.assertEqual(result, "No response text found.")

    @patch('llm_client.ACTIVE_BACKEND', 'gemini')
    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post')
    def test_review_code_gemini_request_body(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "ok"}]}}]
        }
        mock_post.return_value = mock_response

        llm_client.review_code("my system", "my user")

        _, kwargs = mock_post.call_args
        body = kwargs["json"]
        self.assertIn("system_instruction", body)
        self.assertIn("contents", body)
        self.assertEqual(body["system_instruction"]["parts"][0]["text"], "my system")
        self.assertEqual(body["contents"][0]["parts"][0]["text"], "my user")

    def test_parse_llm_json_clean(self):
        result = llm_client._parse_llm_json('{"vulnerabilities": []}')
        self.assertEqual(result, {"vulnerabilities": []})

    def test_parse_llm_json_fenced(self):
        result = llm_client._parse_llm_json('```json\n{"vulnerabilities": []}\n```')
        self.assertEqual(result, {"vulnerabilities": []})

    def test_parse_llm_json_invalid(self):
        result = llm_client._parse_llm_json("not valid json")
        self.assertIn("raw", result)
        self.assertEqual(result["raw"], "not valid json")


if __name__ == '__main__':
    unittest.main()
