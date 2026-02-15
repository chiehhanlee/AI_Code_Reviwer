import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Mock the module if it doesn't exist so we can import the script
if 'google.generativeai' not in sys.modules:
    sys.modules['google.generativeai'] = MagicMock()

import ai_code_reviewer

class TestAICodeReviewer(unittest.TestCase):

    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data="void func() { char b[10]; }")
    def test_read_code_file(self, mock_file):
        content = ai_code_reviewer.read_code_file("dummy.c")
        self.assertEqual(content, "void func() { char b[10]; }")

    def test_review_code_with_api_key(self):
        # We need to simulate HAS_GENAI being true for this test
        # and mock the actual genai module calls
        with patch('ai_code_reviewer.HAS_GENAI', True):
            with patch.dict(os.environ, {'GEMINI_API_KEY': 'fake_key'}):
                with patch('ai_code_reviewer.genai', create=True) as mock_genai:
                    mock_model = MagicMock()
                    mock_response = MagicMock()
                    mock_response.text = "This is a secure code review."
                    mock_model.generate_content.return_value = mock_response
                    mock_genai.GenerativeModel.return_value = mock_model

                    # Re-bind API_KEY inside the function logic by patching the module attribute if logical
                    # or relying on os.getenv which we patched.
                    # Wait, the script reads os.getenv at module level.
                    # We need to reload or patch the module-level variable.
                    with patch('ai_code_reviewer.API_KEY', 'fake_key'):
                        report = ai_code_reviewer.review_code("int main() {}")
                        self.assertIn("This is a secure code review", report)

    def test_review_code_no_api_key(self):
        with patch('ai_code_reviewer.API_KEY', None):
            report = ai_code_reviewer.review_code("int main() {}")
            self.assertIn("MOCK AI REVIEW REPORT", report)

    def test_review_code_no_module(self):
        with patch('ai_code_reviewer.HAS_GENAI', False):
             report = ai_code_reviewer.review_code("int main() {}")
             self.assertIn("MOCK AI REVIEW REPORT", report)

if __name__ == '__main__':
    unittest.main()
