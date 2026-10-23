"""scripts/format_intake.py: the weekly queue of new and changed token formats (no network here).

Run: python3 -m unittest tests.test_format_intake -v
"""
from __future__ import annotations

import datetime
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import format_intake as fi  # noqa: E402

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Access service token secrets use a scannable format</title><link>https://example.com/a</link>
<description>Secrets now carry a prefix and a checksum.</description>
<pubDate>Mon, 19 Oct 2026 10:00:00 GMT</pubDate></item>
<item><title>Faster builds for monorepos</title><link>https://example.com/b</link>
<description>Build caching.</description><pubDate>Tue, 20 Oct 2026 10:00:00 GMT</pubDate></item>
<item><title>New API key format for organizations</title><link>https://example.com/c</link>
<pubDate>Mon, 01 Jun 2026 10:00:00 GMT</pubDate></item>
</channel></rss>"""
ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Personal access tokens get a new prefix</title><link href="https://example.com/d"/>
<updated>2026-10-21T08:00:00Z</updated><summary>Tokens start with a new prefix.</summary></entry>
</feed>"""


class FormatIntakeTests(unittest.TestCase):
    since = datetime.date(2026, 10, 9)

    def test_a_feed_post_about_a_token_format_in_the_window_is_queued(self):
        rss = fi.feed_items("acme", RSS, self.since)
        self.assertEqual([i["url"] for i in rss], ["https://example.com/a"])   # not the build post, not June
        atom = fi.feed_items("acme", ATOM, self.since)
        self.assertEqual([(i["item"], i["date"]) for i in atom], [("Personal access tokens get a new prefix",
                                                                     "2026-10-21")])

    def test_the_format_words_take_a_format_post_and_leave_a_post_that_names_a_key(self):
        for text in ("Access service token secrets use a scannable format", "New API key format",
                     "API tokens now include a checksum", "Personal access tokens get a new prefix"):
            with self.subTest(text=text):
                self.assertTrue(fi.FORMAT_WORDS.search(text))
        for text in ("Faster builds for monorepos", "Store your API key in the dashboard",
                     "Keyboard shortcuts for the editor"):
            with self.subTest(text=text):
                self.assertIsNone(fi.FORMAT_WORDS.search(text))

    def test_only_open_format_reports_are_queued(self):
        issues = [{"title": "Token format: abcd_ + 32 alphanumerics", "html_url": "https://example.com/1",
                   "created_at": "2026-10-20T00:00:00Z"},
                  {"title": "False positive: generic-api-key (SECRET)", "html_url": "https://example.com/2"},
                  {"title": "Token format: zz_ + 20 hex", "pull_request": {}, "html_url": "https://example.com/3"}]
        self.assertEqual(fi.report_items(issues), [{"kind": "report", "source": "github-issue",
                                                    "item": "abcd_ + 32 alphanumerics",
                                                    "url": "https://example.com/1", "date": "2026-10-20"}])

    def test_the_feed_list_reads_name_and_url_and_skips_comments(self):
        text = "# comment\nacme https://example.com/feed  # trailing\n\nbroken-line-without-url\n"
        self.assertEqual(fi.load_feeds(text), [("acme", "https://example.com/feed")])
        self.assertEqual(fi.load_feeds(fi.FEEDS.read_text(encoding="utf-8"))[0][0], "github-changelog")

    def test_the_run_writes_the_queue_and_exits_1_with_an_item_and_0_without(self):
        item = {"kind": "watch-changed", "source": "gitleaks", "item": "acme-key", "url": "", "date": "2026-10-23"}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with mock.patch.object(fi, "watch_items", return_value=[item]), \
                    mock.patch.object(fi, "_get", side_effect=OSError("offline")), redirect_stdout(io.StringIO()):
                self.assertEqual(fi.main(["--out", str(out)]), 1)
            self.assertEqual([json.loads(line) for line in (out / "queue.jsonl").read_text().splitlines()], [item])
            md = (out / "queue.md").read_text()
            self.assertIn("## watch-changed (1)", md)
            self.assertIn("## Sources not read", md)   # an unreachable source is named, not hidden
            with mock.patch.object(fi, "watch_items", return_value=[]), \
                    mock.patch.object(fi, "_get", side_effect=OSError("offline")), redirect_stdout(io.StringIO()):
                self.assertEqual(fi.main(["--out", str(out)]), 0)


if __name__ == "__main__":
    unittest.main()
