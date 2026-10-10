"""Formatted previews preserve raw evidence and escape embedded HTML."""
import unittest
import test_incidents as fixtures
from dashboard.markdown_view import render_preview


class MarkdownTests(unittest.TestCase):
    def test_headings_lists_tables_and_code(self):
        text = '# Sample\n\n## Evidence\n\n- One\n- Two\n\n| A | B |\n|---|---|\n| x | y |\n\n```bash\nprintf "sample"\n```\n'
        rendered = str(render_preview(text))
        for expected in ('<h1>Sample</h1>', '<h2>Evidence</h2>', '<ul>', '<table>', '<pre><code class="language-bash">'):
            self.assertIn(expected, rendered)

    def test_html_unsafe_links_and_remote_images(self):
        rendered = str(render_preview('<script>alert(1)</script>\n\n[bad](javascript:alert(1))\n\n![remote](https://example.com/image.png)'))
        self.assertNotIn('<script>', rendered)
        self.assertNotIn('href="javascript:', rendered)
        self.assertNotIn('<img', rendered)
        self.assertIn('&lt;script&gt;', rendered)

    def test_strip_complete_header_only_when_requested(self):
        source = '---\nstatus: open\n---\n# Sample\n'
        self.assertNotIn('status: open', render_preview(source, True))
        self.assertIn('status: open', render_preview(source))
        self.assertIn('status: open', render_preview('---\nstatus: open\n', True))


class PreviewPageTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.IncidentTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.IncidentTests.tearDownClass.__func__)
    setUp = fixtures.IncidentTests.setUp
    tearDown = fixtures.IncidentTests.tearDown

    def test_preview_and_raw_source_do_not_modify_ticket(self):
        before = self.ticket.read_bytes()
        response = self.client.get('/alerts/sample.md')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'<h1>Synthetic alert</h1>', response.data)
        self.assertIn(b'View raw source ticket and metadata', response.data)
        self.assertIn(b'status: open', response.data)
        self.assertEqual(self.ticket.read_bytes(), before)

    def test_real_runbook_table_rendered(self):
        self.ticket.write_text('---\nstatus: open\nrunbook: docs/runbooks/RB-001-unknown-device.md\n---\n# Sample\n')
        page = self.client.get('/alerts/sample.md').data
        self.assertIn(b'View raw runbook Markdown', page)
        self.assertIn(b'<table>', page)
        self.assertIn(b'<ol>', page)


if __name__ == '__main__':
    unittest.main()
