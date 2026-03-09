#!/usr/bin/env python3
import sys
sys.modules["OpenSSL"] = None  # broken OpenSSL workaround — must precede llm_client import

import os
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")  # required for llm_client import

import json
import unittest
from unittest.mock import patch, MagicMock, mock_open
import requests

import context_builder
import llm_client
import ai_code_reviewer


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
        self.assertIn("CWE-121", prompt)

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

    # --- build_call_clusters tests ---

    def test_build_call_clusters_singleton_skipped(self):
        funcs = {'foo': {'calls': [], 'source': '', 'file': 'test.c'}}
        result = context_builder.build_call_clusters(funcs, funcs)
        self.assertEqual(result, [])

    def test_build_call_clusters_two_function_cluster(self):
        funcs = {
            'foo': {'calls': ['bar'], 'source': '', 'file': 'test.c'},
            'bar': {'calls': ['foo'], 'source': '', 'file': 'test.c'},
        }
        result = context_builder.build_call_clusters(funcs, funcs)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], {'foo', 'bar'})

    def test_build_call_clusters_unidirectional_edge(self):
        funcs = {
            'foo': {'calls': ['bar'], 'source': '', 'file': 'test.c'},
            'bar': {'calls': [], 'source': '', 'file': 'test.c'},
        }
        result = context_builder.build_call_clusters(funcs, funcs)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], {'foo', 'bar'})

    def test_build_call_clusters_includes_callee_from_other_file(self):
        # A target function calling a function defined in an included file
        # should form a cluster so cross-file chains are detected.
        all_funcs = {
            'foo': {'calls': ['bar'], 'source': '', 'file': 'main.c'},
            'bar': {'calls': [], 'source': '', 'file': 'other.c'},
        }
        target_funcs = {'foo': all_funcs['foo']}
        result = context_builder.build_call_clusters(all_funcs, target_funcs)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], {'foo', 'bar'})

    def test_build_call_clusters_excludes_unknown_callee(self):
        # Callees not defined in the codebase (e.g. system calls) are not nodes.
        funcs = {'foo': {'calls': ['printf'], 'source': '', 'file': 'test.c'}}
        result = context_builder.build_call_clusters(funcs, funcs)
        self.assertEqual(result, [])

    def test_build_call_clusters_oversized_split(self):
        # 9-node linear chain: 0→1→2→...→8, max_cluster_size=8
        funcs = {str(i): {'calls': [str(i + 1)], 'source': '', 'file': 'test.c'}
                 for i in range(8)}
        funcs['8'] = {'calls': [], 'source': '', 'file': 'test.c'}
        result = context_builder.build_call_clusters(funcs, funcs, max_cluster_size=8)
        self.assertTrue(len(result) > 0)
        for cluster in result:
            self.assertLessEqual(len(cluster), 3)

    def test_build_call_clusters_two_independent_components(self):
        funcs = {
            'a': {'calls': ['b'], 'source': '', 'file': 'test.c'},
            'b': {'calls': [], 'source': '', 'file': 'test.c'},
            'c': {'calls': ['d'], 'source': '', 'file': 'test.c'},
            'd': {'calls': [], 'source': '', 'file': 'test.c'},
        }
        result = context_builder.build_call_clusters(funcs, funcs)
        self.assertEqual(len(result), 2)
        cluster_sets = [frozenset(c) for c in result]
        self.assertIn(frozenset({'a', 'b'}), cluster_sets)
        self.assertIn(frozenset({'c', 'd'}), cluster_sets)

    # --- cross-function prompt tests ---

    def test_cross_function_system_prompt_contains_cwes(self):
        prompt = context_builder._build_cross_function_system_prompt()
        for cwe in ['CWE-401', 'CWE-415', 'CWE-416', 'CWE-476']:
            self.assertIn(cwe, prompt)

    def test_cross_function_system_prompt_schema_keys(self):
        prompt = context_builder._build_cross_function_system_prompt()
        self.assertIn('cross_function_vulnerabilities', prompt)
        self.assertIn('functions_involved', prompt)
        self.assertIn('"file"', prompt)

    def test_cross_function_user_prompt_includes_all_functions(self):
        cluster_sources = {
            'foo': 'void foo() { bar(); }',
            'bar': 'void bar() {}',
        }
        prompt = context_builder._build_cross_function_user_prompt(cluster_sources)
        self.assertIn('foo', prompt)
        self.assertIn('bar', prompt)
        self.assertIn('void foo() { bar(); }', prompt)
        self.assertIn('void bar() {}', prompt)


class TestClassifyFunctionRole(unittest.TestCase):

    def test_malloc_only(self):
        src = "void *f() { return malloc(4); }"
        self.assertIn("ALLOCATES", context_builder._classify_function_role(src))

    def test_free_only(self):
        src = "void f(void *p) { free(p); }"
        self.assertIn("FREES", context_builder._classify_function_role(src))

    def test_both_alloc_and_free(self):
        src = "void *f() { void *p = malloc(4); free(p); return NULL; }"
        role = context_builder._classify_function_role(src)
        self.assertIn("ALLOCATES", role)
        self.assertIn("FREES", role)

    def test_no_alloc_no_free(self):
        src = "int f(int x) { return x + 1; }"
        role = context_builder._classify_function_role(src)
        self.assertIn("USES", role)

    def test_malloc_in_string_literal_ignored(self):
        src = 'void f() { puts("malloc(4)"); }'
        role = context_builder._classify_function_role(src)
        self.assertNotIn("ALLOCATES", role)

    def test_free_in_line_comment_ignored(self):
        src = "void f() { // free(p);\n}"
        role = context_builder._classify_function_role(src)
        self.assertNotIn("FREES", role)

    def test_calloc(self):
        src = "void *f(int n) { return calloc(n, 4); }"
        self.assertIn("ALLOCATES", context_builder._classify_function_role(src))

    def test_strdup(self):
        src = 'char *f(const char *s) { return strdup(s); }'
        self.assertIn("ALLOCATES", context_builder._classify_function_role(src))


class TestCrossFunctionPass(unittest.TestCase):

    def _make_functions(self, call_graph, filename='test.c'):
        return {
            fname: {
                'source': f'void {fname}() {{}}',
                'calls': callees,
                'file': filename,
            }
            for fname, callees in call_graph.items()
        }

    def _run_main(self, functions, review_side_effect):
        """Run main() with mocked dependencies; return the captured report dict."""
        report_holder = {}

        def capture_dump(data, f, **kwargs):
            report_holder.update(data)

        with patch('sys.argv', ['prog', 'test.c']), \
             patch('ai_code_reviewer.HAS_PYCPARSER', True), \
             patch('ai_code_reviewer.read_code_file', return_value=''), \
             patch('ai_code_reviewer.analyze_ast', return_value=functions), \
             patch('ai_code_reviewer._build_file_map', return_value=[]), \
             patch('ai_code_reviewer._extract_file_sections', return_value={}), \
             patch('ai_code_reviewer.review_code', side_effect=review_side_effect), \
             patch('ai_code_reviewer._run_verification_pass'), \
             patch('builtins.open', mock_open()), \
             patch('json.dump', side_effect=capture_dump):
            ai_code_reviewer.main()

        return report_holder

    def test_cross_function_key_populated(self):
        # Functions need malloc/free in their source to pass the alloc/free filter
        funcs = {
            'foo': {'calls': ['bar'], 'source': 'void *foo() { return malloc(4); }', 'file': 'test.c'},
            'bar': {'calls': [], 'source': 'void bar(void *p) { free(p); }', 'file': 'test.c'},
        }
        cf_json = ('{"cross_function_vulnerabilities": [{'
                   '"functions_involved": ["foo", "bar"], '
                   '"line": 10, "description": "CWE-416: UAF"}]}')
        responses = [
            '{"function": "foo", "vulnerabilities": []}',
            '{"function": "bar", "vulnerabilities": []}',
            cf_json,
        ]
        report = self._run_main(funcs, responses)
        self.assertIn('cross_function', report)
        self.assertEqual(len(report['cross_function']), 1)

    def test_cross_function_key_absent_no_clusters(self):
        funcs = self._make_functions({'foo': [], 'bar': []})
        responses = [
            '{"function": "foo", "vulnerabilities": []}',
            '{"function": "bar", "vulnerabilities": []}',
        ]
        report = self._run_main(funcs, responses)
        self.assertNotIn('cross_function', report)

    def test_cross_function_key_absent_empty_llm(self):
        funcs = self._make_functions({'foo': ['bar'], 'bar': []})
        responses = [
            '{"function": "foo", "vulnerabilities": []}',
            '{"function": "bar", "vulnerabilities": []}',
            '{"cross_function_vulnerabilities": []}',
        ]
        report = self._run_main(funcs, responses)
        self.assertNotIn('cross_function', report)

    def test_cross_function_review_called_with_cluster_func_name(self):
        funcs = self._make_functions({'foo': ['bar'], 'bar': []})
        call_func_names = []

        def mock_review(system_prompt, user_prompt, func_name=None, **kwargs):
            call_func_names.append(func_name)
            if func_name and func_name.startswith('__cross_function_cluster_'):
                return '{"cross_function_vulnerabilities": []}'
            return f'{{"function": "{func_name}", "vulnerabilities": []}}'

        # Give functions malloc/free source so they pass the alloc/free filter
        funcs = {
            'foo': {'calls': ['bar'], 'source': 'void *foo() { return malloc(4); }', 'file': 'test.c'},
            'bar': {'calls': [], 'source': 'void bar(void *p) { free(p); }', 'file': 'test.c'},
        }
        with patch('sys.argv', ['prog', 'test.c']), \
             patch('ai_code_reviewer.HAS_PYCPARSER', True), \
             patch('ai_code_reviewer.read_code_file', return_value=''), \
             patch('ai_code_reviewer.analyze_ast', return_value=funcs), \
             patch('ai_code_reviewer._build_file_map', return_value=[]), \
             patch('ai_code_reviewer._extract_file_sections', return_value={}), \
             patch('ai_code_reviewer.review_code', side_effect=mock_review), \
             patch('ai_code_reviewer._run_verification_pass'), \
             patch('builtins.open', mock_open()), \
             patch('json.dump', lambda *a, **k: None):
            ai_code_reviewer.main()

        cf_calls = [n for n in call_func_names
                    if n and n.startswith('__cross_function_cluster_')]
        self.assertGreaterEqual(len(cf_calls), 1)


class TestLLMClient(unittest.TestCase):

    def setUp(self):
        self._orig_max = llm_client.MAX_RETRIES
        self._orig_delay = llm_client.RETRY_DELAY_SECS
        llm_client.MAX_RETRIES = 0      # disable retries so existing tests run once
        llm_client.RETRY_DELAY_SECS = 0

    def tearDown(self):
        llm_client.MAX_RETRIES = self._orig_max
        llm_client.RETRY_DELAY_SECS = self._orig_delay

    def test_is_error_response_timeout(self):
        self.assertTrue(llm_client.is_error_response("Error: Request timed out after 300 seconds."))

    def test_is_error_response_api_error(self):
        self.assertTrue(llm_client.is_error_response("API Error 500: Internal Server Error"))

    def test_is_error_response_valid_json(self):
        self.assertFalse(llm_client.is_error_response('{"vulnerabilities": []}'))

    def test_is_error_response_non_string(self):
        self.assertFalse(llm_client.is_error_response(None))

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


class TestErrorHandling(unittest.TestCase):
    """Integration tests for is_error_response guards in main()."""

    def _run_main(self, functions, review_side_effect):
        report_holder = {}

        def capture_dump(data, f, **kwargs):
            report_holder.update(data)

        with patch('sys.argv', ['prog', 'test.c']), \
             patch('ai_code_reviewer.HAS_PYCPARSER', True), \
             patch('ai_code_reviewer.read_code_file', return_value=''), \
             patch('ai_code_reviewer.analyze_ast', return_value=functions), \
             patch('ai_code_reviewer._build_file_map', return_value=[]), \
             patch('ai_code_reviewer._extract_file_sections', return_value={}), \
             patch('ai_code_reviewer.review_code', side_effect=review_side_effect), \
             patch('ai_code_reviewer._run_verification_pass'), \
             patch('builtins.open', mock_open()), \
             patch('json.dump', side_effect=capture_dump):
            ai_code_reviewer.main()

        return report_holder

    def test_main_skips_errored_function(self):
        funcs = {
            'foo': {'calls': [], 'source': 'void foo() {}', 'file': 'test.c'},
            'bar': {'calls': [], 'source': 'void bar() {}', 'file': 'test.c'},
        }
        responses = [
            "Error: Request to Ollama timed out after 300 seconds.",
            '{"function": "bar", "vulnerabilities": []}',
        ]
        report = self._run_main(funcs, responses)
        entries = report.get('functions', [])
        foo_entries = [e for e in entries if e.get('function') == 'foo']
        bar_entries = [e for e in entries if e.get('function') == 'bar']
        self.assertEqual(len(foo_entries), 1)
        self.assertIn('error', foo_entries[0])
        self.assertEqual(len(bar_entries), 1)
        self.assertNotIn('error', bar_entries[0])


class TestRetryLogic(unittest.TestCase):

    def setUp(self):
        self._orig_max = llm_client.MAX_RETRIES
        self._orig_delay = llm_client.RETRY_DELAY_SECS
        llm_client.MAX_RETRIES = 1
        llm_client.RETRY_DELAY_SECS = 0

    def tearDown(self):
        llm_client.MAX_RETRIES = self._orig_max
        llm_client.RETRY_DELAY_SECS = self._orig_delay

    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post')
    def test_review_code_retries_on_timeout(self, mock_post):
        success = MagicMock()
        success.status_code = 200
        success.json.return_value = {"message": {"content": "found issue"}}
        mock_post.side_effect = [requests.exceptions.Timeout, success]

        result = llm_client.review_code("system", "user")
        self.assertEqual(result, "found issue")
        self.assertEqual(mock_post.call_count, 2)

    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post')
    def test_review_code_retries_on_500(self, mock_post):
        fail = MagicMock()
        fail.status_code = 500
        fail.text = "Internal Server Error"
        success = MagicMock()
        success.status_code = 200
        success.json.return_value = {"message": {"content": "ok"}}
        mock_post.side_effect = [fail, success]

        result = llm_client.review_code("system", "user")
        self.assertEqual(result, "ok")
        self.assertEqual(mock_post.call_count, 2)

    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post')
    def test_review_code_no_retry_on_400(self, mock_post):
        fail = MagicMock()
        fail.status_code = 400
        fail.text = "Bad Request"
        mock_post.return_value = fail

        result = llm_client.review_code("system", "user")
        self.assertIn("API Error 400", result)
        self.assertEqual(mock_post.call_count, 1)

    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post')
    def test_review_code_no_retry_on_success(self, mock_post):
        success = MagicMock()
        success.status_code = 200
        success.json.return_value = {"message": {"content": "great"}}
        mock_post.return_value = success

        result = llm_client.review_code("system", "user")
        self.assertEqual(result, "great")
        self.assertEqual(mock_post.call_count, 1)

    @patch('builtins.open', mock_open())
    @patch('llm_client.requests.post')
    def test_max_retries_exhausted(self, mock_post):
        mock_post.side_effect = requests.exceptions.Timeout

        result = llm_client.review_code("system", "user")
        self.assertIn("timed out", result)
        self.assertEqual(mock_post.call_count, 2)  # initial + 1 retry


class TestDeduplicateReport(unittest.TestCase):

    def test_dedup_per_function_removes_duplicate(self):
        report = {"functions": [{"function": "f", "vulnerabilities": [
            {"line": 1, "CWE_ID": "CWE-121", "description": "first"},
            {"line": 1, "CWE_ID": "CWE-121", "description": "duplicate"},
        ]}]}
        ai_code_reviewer._deduplicate_report(report)
        self.assertEqual(len(report["functions"][0]["vulnerabilities"]), 1)
        self.assertEqual(report["functions"][0]["vulnerabilities"][0]["description"], "first")

    def test_dedup_per_function_keeps_different_cwe(self):
        report = {"functions": [{"function": "f", "vulnerabilities": [
            {"line": 1, "CWE_ID": "CWE-121", "description": "a"},
            {"line": 1, "CWE_ID": "CWE-122", "description": "b"},
        ]}]}
        ai_code_reviewer._deduplicate_report(report)
        self.assertEqual(len(report["functions"][0]["vulnerabilities"]), 2)

    def test_dedup_per_function_keeps_different_lines(self):
        report = {"functions": [{"function": "f", "vulnerabilities": [
            {"line": 1, "CWE_ID": "CWE-121", "description": "a"},
            {"line": 2, "CWE_ID": "CWE-121", "description": "b"},
        ]}]}
        ai_code_reviewer._deduplicate_report(report)
        self.assertEqual(len(report["functions"][0]["vulnerabilities"]), 2)

    def test_dedup_cross_function_removes_duplicate(self):
        report = {"cross_function": [
            {"functions_involved": ["a", "b"], "CWE_ID": "CWE-416", "line": 5},
            {"functions_involved": ["b", "a"], "CWE_ID": "CWE-416", "line": 5},
        ]}
        ai_code_reviewer._deduplicate_report(report)
        self.assertEqual(len(report["cross_function"]), 1)

    def test_dedup_cross_function_keeps_different_cwe(self):
        report = {"cross_function": [
            {"functions_involved": ["a", "b"], "CWE_ID": "CWE-416", "line": 5},
            {"functions_involved": ["a", "b"], "CWE_ID": "CWE-401", "line": 5},
        ]}
        ai_code_reviewer._deduplicate_report(report)
        self.assertEqual(len(report["cross_function"]), 2)

    def test_dedup_full_file_removes_duplicate(self):
        report = {"vulnerabilities": [
            {"line": 10, "CWE_ID": "CWE-134", "description": "first"},
            {"line": 10, "CWE_ID": "CWE-134", "description": "dup"},
        ]}
        ai_code_reviewer._deduplicate_report(report)
        self.assertEqual(len(report["vulnerabilities"]), 1)

    def test_dedup_empty_report_does_not_crash(self):
        ai_code_reviewer._deduplicate_report({})
        ai_code_reviewer._deduplicate_report({"functions": []})


class TestGoldenSamples(unittest.TestCase):
    """Validate golden sample files and provide a comparison utility."""

    GOLDEN_FILES = [
        "sample/easy_sample_1/vulnerable_code.golden.json",
        "sample/easy_sample_2/user_manager.golden.json",
        "sample/easy_sample_2/main_complex.golden.json",
        "sample/medium_sample_1/network_parser.golden.json",
        "sample/medium_sample_2/session_mgr.golden.json",
        "sample/medium_sample_3/config_reader.golden.json",
    ]

    SAMPLE_FUNCTIONS = {
        "sample/medium_sample_1/network_parser.c": {
            "alloc_field_value", "fill_field", "parse_tlv",
            "summarize_packet", "process_packet",
        },
        "sample/medium_sample_2/session_mgr.c": {
            "session_create", "session_authenticate", "session_free",
            "session_get_user", "session_logout", "admin_action",
        },
        "sample/medium_sample_3/config_reader.c": {
            "log_error", "read_line", "parse_config_line",
            "read_config", "apply_config",
        },
    }

    def test_golden_files_valid_json(self):
        for path in self.GOLDEN_FILES:
            with self.subTest(path=path):
                with open(path) as f:
                    data = json.load(f)
                self.assertIn("model", data)
                self.assertEqual(data["model"], "golden")
                self.assertIn("mode", data)
                self.assertIn("functions", data)

    def test_golden_files_function_structure(self):
        for path in self.GOLDEN_FILES:
            with self.subTest(path=path):
                with open(path) as f:
                    data = json.load(f)
                for func in data["functions"]:
                    self.assertIn("function", func)
                    self.assertIn("vulnerabilities", func)
                    self.assertIsInstance(func["vulnerabilities"], list)
                    for v in func["vulnerabilities"]:
                        self.assertIn("line", v, f"{func['function']}: missing 'line'")
                        self.assertIn("CWE_ID", v, f"{func['function']}: missing 'CWE_ID'")
                        self.assertIn("description", v, f"{func['function']}: missing 'description'")
                        self.assertRegex(v["CWE_ID"], r"^CWE-\d+$")

    def test_golden_cross_function_structure(self):
        for path in self.GOLDEN_FILES:
            with self.subTest(path=path):
                with open(path) as f:
                    data = json.load(f)
                for v in data.get("cross_function", []):
                    self.assertIn("functions_involved", v)
                    self.assertIsInstance(v["functions_involved"], list)
                    self.assertGreater(len(v["functions_involved"]), 1)
                    self.assertIn("CWE_ID", v)
                    self.assertIn("line", v)
                    self.assertIn("description", v)

    def test_medium_samples_have_expected_functions(self):
        for path, expected_funcs in self.SAMPLE_FUNCTIONS.items():
            with self.subTest(path=path):
                basename = os.path.basename(path).replace(".c", "")
                golden_path = os.path.join(os.path.dirname(path), basename + ".golden.json")
                with open(golden_path) as f:
                    data = json.load(f)
                actual_funcs = {e["function"] for e in data["functions"]}
                self.assertEqual(actual_funcs, expected_funcs)

    def test_ast_extracts_medium_sample_functions(self):
        """Verify pycparser correctly finds all expected functions in each sample."""
        try:
            import pycparser  # noqa: F401
        except ImportError:
            self.skipTest("pycparser not installed")

        for path, expected_funcs in self.SAMPLE_FUNCTIONS.items():
            with self.subTest(path=path):
                code = context_builder.read_code_file(path)
                funcs = context_builder.analyze_ast(code, path)
                self.assertEqual(set(funcs.keys()), expected_funcs,
                                 f"AST function mismatch for {path}")

    # ------------------------------------------------------------------
    # Comparison utility — used for integration testing against golden
    # ------------------------------------------------------------------

    @staticmethod
    def compare_report_to_golden(actual, golden):
        """Compare an AI-generated report against a golden report.

        Returns (missing, extra) where each is a list of finding keys.

        Key shapes:
        - Per-function:   (function_name: str, line: int, CWE_ID: str)
        - Cross-function: (functions_involved: frozenset, CWE_ID: str)

        missing — findings present in golden but absent from actual
                  (false negatives: things the AI missed)
        extra   — findings present in actual but absent from golden
                  (false positives: things the AI over-reported)
        """
        def _index(report):
            idx = set()
            for entry in report.get("functions", []):
                fname = entry["function"]
                for v in entry.get("vulnerabilities", []):
                    if isinstance(v, dict):
                        idx.add((fname, v.get("line"), v.get("CWE_ID")))
            for v in report.get("cross_function", []):
                if isinstance(v, dict):
                    idx.add((frozenset(v.get("functions_involved", [])), v.get("CWE_ID")))
            return idx

        golden_idx = _index(golden)
        actual_idx = _index(actual)
        return sorted(golden_idx - actual_idx, key=str), sorted(actual_idx - golden_idx, key=str)

    def test_compare_exact_match(self):
        report = {"functions": [{"function": "f", "vulnerabilities": [
            {"line": 1, "CWE_ID": "CWE-121"}
        ]}]}
        golden = {"functions": [{"function": "f", "vulnerabilities": [
            {"line": 1, "CWE_ID": "CWE-121"}
        ]}]}
        missing, extra = self.compare_report_to_golden(report, golden)
        self.assertEqual(missing, [])
        self.assertEqual(extra, [])

    def test_compare_missing_finding(self):
        report = {"functions": [{"function": "f", "vulnerabilities": []}]}
        golden = {"functions": [{"function": "f", "vulnerabilities": [
            {"line": 1, "CWE_ID": "CWE-121"}
        ]}]}
        missing, extra = self.compare_report_to_golden(report, golden)
        self.assertIn(("f", 1, "CWE-121"), missing)
        self.assertEqual(extra, [])

    def test_compare_extra_finding(self):
        report = {"functions": [{"function": "f", "vulnerabilities": [
            {"line": 1, "CWE_ID": "CWE-121"},
            {"line": 5, "CWE_ID": "CWE-122"},
        ]}]}
        golden = {"functions": [{"function": "f", "vulnerabilities": [
            {"line": 1, "CWE_ID": "CWE-121"}
        ]}]}
        missing, extra = self.compare_report_to_golden(report, golden)
        self.assertEqual(missing, [])
        self.assertIn(("f", 5, "CWE-122"), extra)

    def test_compare_empty_report(self):
        golden = {"functions": [{"function": "f", "vulnerabilities": [
            {"line": 1, "CWE_ID": "CWE-121"}
        ]}]}
        missing, extra = self.compare_report_to_golden({}, golden)
        self.assertEqual(len(missing), 1)
        self.assertEqual(extra, [])

    def test_compare_cross_function_missing(self):
        report = {"cross_function": []}
        golden = {"cross_function": [
            {"functions_involved": ["foo", "bar"], "CWE_ID": "CWE-416", "line": 10}
        ]}
        missing, extra = self.compare_report_to_golden(report, golden)
        self.assertIn((frozenset({"foo", "bar"}), "CWE-416"), missing)

    def test_compare_cross_function_extra(self):
        report = {"cross_function": [
            {"functions_involved": ["foo", "bar"], "CWE_ID": "CWE-416", "line": 10}
        ]}
        missing, extra = self.compare_report_to_golden(report, {})
        self.assertIn((frozenset({"foo", "bar"}), "CWE-416"), extra)

    def test_compare_cross_function_order_independent(self):
        # functions_involved order should not matter (frozenset key)
        report = {"cross_function": [
            {"functions_involved": ["a", "b"], "CWE_ID": "CWE-401", "line": 5}
        ]}
        golden = {"cross_function": [
            {"functions_involved": ["b", "a"], "CWE_ID": "CWE-401", "line": 5}
        ]}
        missing, extra = self.compare_report_to_golden(report, golden)
        self.assertEqual(missing, [])
        self.assertEqual(extra, [])


if __name__ == '__main__':
    unittest.main()
