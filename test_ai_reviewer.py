import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Mock the module if it doesn't exist so we can import the script
if 'google.generativeai' not in sys.modules:
    sys.modules['google.generativeai'] = MagicMock()

sys.modules["OpenSSL"] = None
import requests
import ai_code_reviewer

class TestAICodeReviewer(unittest.TestCase):

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data="void func() { char b[10]; }")
    def test_read_code_file(self, mock_file, mock_exists):
        content = ai_code_reviewer.read_code_file("dummy.c")
        self.assertEqual(content, "// --- FILE: dummy.c ---\nvoid func() { char b[10]; }\n")

    def test_review_code_with_api_key(self):
        with patch('ai_code_reviewer.HAS_GENAI', True):
            with patch.dict(os.environ, {'GEMINI_API_KEY': 'fake_key'}):
                with patch('ai_code_reviewer.API_KEY', 'fake_key'):
                    with patch('requests.post') as mock_post:
                        mock_response = MagicMock()
                        mock_response.status_code = 200
                        mock_response.json.return_value = {
                            "candidates": [{"content": {"parts": [{"text": "This is a secure code review."}]}}]
                        }
                        mock_post.return_value = mock_response
                        
                        report = ai_code_reviewer.review_code("int main() {}")
                        self.assertIn("This is a secure code review", report)

    def test_review_code_no_api_key(self):
        with patch('ai_code_reviewer.API_KEY', None):
            report = ai_code_reviewer.review_code("int main() {}")
            self.assertIn("MOCK AI REVIEW REPORT", report)

    def test_review_code_no_module(self):
        with patch('ai_code_reviewer.HAS_GENAI', False):
             with patch('ai_code_reviewer.API_KEY', None):
                 report = ai_code_reviewer.review_code("int main() {}")
                 self.assertIn("MOCK AI REVIEW REPORT", report)

if __name__ == '__main__':
    unittest.main()
