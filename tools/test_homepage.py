#!/usr/bin/env python3
"""Static homepage checks. Run: python3 tools/test_homepage.py"""
import json
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit

from build_home_en import render

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


class Page(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.text = []
        self.stack = []
        self.parents = {}
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if "id" in attrs:
            self.parents[attrs["id"]] = [a.get("id") for _, a in self.stack]
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append((tag, attrs))

    def handle_endtag(self, tag):
        if self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_data(self, data):
        self.text.append(data)


class HomepageTests(unittest.TestCase):
    def test_english_is_up_to_date(self):
        self.assertEqual(render((DOCS / "index.html").read_text()),
                         (DOCS / "index.en.html").read_text())

    def test_language_metadata_and_navigation(self):
        for name, lang, active in [("index.html", "zh-CN", "zh"), ("index.en.html", "en", "en")]:
            page = Page((DOCS / name).read_text())
            self.assertEqual(next(a["lang"] for t, a in page.tags if t == "html"), lang)
            selected = [a["data-language"] for t, a in page.tags if "data-language" in a and "aria-current" in a]
            self.assertEqual(selected, [active])
            self.assertEqual(sum(t == "h1" for t, a in page.tags), 1)
            self.assertEqual({a["hreflang"] for t, a in page.tags if a.get("rel") == "alternate"}, {"en", "zh-CN", "x-default"})
            self.assertTrue(all(a.get("tabindex") == "0" and a.get("aria-label") for t, a in page.tags if t == "pre"))
            self.assertTrue(all(a.get("alt") and a.get("width") and a.get("height") for t, a in page.tags if t == "img"))
        english = "".join(Page((DOCS / "index.en.html").read_text()).text).replace("中文", "")
        self.assertFalse(re.search(r"[\u4e00-\u9fff]", english), "Untranslated English page text")

    def test_local_links_and_legacy_anchors(self):
        required = {"article", "navigate", "evidence", "architecture", "boundaries", "quickstart",
                    "experiments", "tb4-experiment", "agent-comparison", "long-trial"}
        for name in ["index.html", "index.en.html"]:
            page = Page((DOCS / name).read_text())
            ids = [a["id"] for _, a in page.tags if "id" in a]
            self.assertEqual(len(ids), len(set(ids)))
            self.assertTrue(required <= set(ids))
            for tag, attrs in page.tags:
                for key in ["href", "src"]:
                    if key not in attrs:
                        continue
                    url = urlsplit(attrs[key])
                    if url.scheme or url.netloc:
                        continue
                    target = DOCS / unquote(url.path) if url.path else DOCS / name
                    if target.is_dir():
                        target /= "index.html"
                    self.assertTrue(target.is_file(), str(target))
                    if url.fragment:
                        target_ids = {a.get("id") for _, a in Page(target.read_text()).tags}
                        self.assertIn(unquote(url.fragment), target_ids)

    def test_sample_is_actual_export_subset(self):
        from html import unescape
        source = (DOCS / "index.html").read_text()
        excerpt = json.loads(unescape(re.search(r'<pre[^>]*><code>(.*?)</code>', source, re.S)[1]))
        sample = json.loads((DOCS / "data/tinybox-recording-sample.json").read_text())
        self.assertTrue(any(all(a[k] == v for k, v in excerpt.items()) for a in sample["attempts"]))

    def test_acceptance_is_part_of_cloud_native_deployment(self):
        for name in ["index.html", "index.en.html"]:
            page = Page((DOCS / name).read_text())
            self.assertIn("cloud-native", page.parents["evidence"])
            self.assertIn("architecture", page.parents["evidence"])
            self.assertEqual(next(t for t, a in page.tags if a.get("id") == "evidence-title"), "h4")
            self.assertFalse(any("home-evidence" in a.get("class", "").split() for _, a in page.tags))

    def test_no_decorative_dashes(self):
        for name in ["index.html", "index.en.html"]:
            self.assertFalse(re.search("[—–]", "".join(Page((DOCS / name).read_text()).text)))


if __name__ == "__main__":
    unittest.main()
