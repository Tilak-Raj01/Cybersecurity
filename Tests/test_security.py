import html
import unittest


def sanitize_string(value):
    """Escape HTML-sensitive characters to prevent XSS payload rendering."""
    return html.escape(str(value or ''), quote=True).replace("'", "&#39;")


class TestSecuritySanitization(unittest.TestCase):
    def test_sanitizes_html_special_characters(self):
        self.assertEqual(
            sanitize_string('<script>alert("x") & "quoted"'),
            '&lt;script&gt;alert(&quot;x&quot;) &amp; &quot;quoted&quot;'
        )

    def test_handles_none_and_empty_values(self):
        self.assertEqual(sanitize_string(None), '')
        self.assertEqual(sanitize_string(''), '')


if __name__ == '__main__':
    unittest.main()
