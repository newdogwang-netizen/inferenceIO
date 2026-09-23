#!/usr/bin/env python3
"""Render the English homepage from index.html's leaf translations to stdout.

No dependencies. After editing index.html, regenerate index.en.html and run
tools/test_homepage.py to catch missing translations and stale output.
"""
import html
from html.parser import HTMLParser
from pathlib import Path


class EnglishHomepage(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.output = []
        self.translating = None

    def handle_starttag(self, tag, attrs):
        if self.translating:
            raise ValueError("data-en is only allowed on leaf elements")
        values = dict(attrs)
        translated = {
            key.removeprefix("data-en-"): value
            for key, value in attrs if key.startswith("data-en-")
        }
        attrs = [(key, translated.get(key, value)) for key, value in attrs
                 if key != "data-en" and not key.startswith("data-en-")]
        if tag == "html":
            attrs = [(k, "en" if k == "lang" else v) for k, v in attrs]
        if values.get("data-language"):
            attrs = [(k, v) for k, v in attrs if k != "aria-current"]
            if values["data-language"] == "en":
                attrs.append(("aria-current", "page"))
        self.output.append("<" + tag + "".join(
            f' {k}' if v is None else f' {k}="{html.escape(v, quote=True)}"'
            for k, v in attrs) + ">")
        if "data-en" in values:
            self.output.append(html.escape(values["data-en"], quote=False))
            self.translating = tag

    def handle_endtag(self, tag):
        if self.translating:
            if self.translating != tag:
                raise ValueError("Invalid translated leaf")
            self.translating = None
        self.output.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.translating:
            self.output.append(data)

    def handle_entityref(self, name):
        self.handle_data(f"&{name};")

    def handle_charref(self, name):
        self.handle_data(f"&#{name};")

    def handle_decl(self, decl):
        self.output.append(f"<!{decl}>")

    def handle_comment(self, data):
        self.output.append(f"<!--{data}-->")


def render(source):
    parser = EnglishHomepage()
    parser.feed(source)
    parser.close()
    if parser.translating:
        raise ValueError("Unclosed translated leaf")
    return "".join(parser.output)


if __name__ == "__main__":
    print(render((Path(__file__).resolve().parents[1] / "docs/index.html").read_text()), end="")
