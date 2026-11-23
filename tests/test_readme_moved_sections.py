"""The README is split by reader (docs/USING.md, ADMIN.md, HOW-IT-WORKS.md, KNOWN-GAPS.md, CLIENTS.md).

A section that moved must not get lost, and a link from outside (the website, an issue, a hint the CLI prints) to an
old README heading must still land: README.md keeps one anchor (`<a name="...">`) per moved section under "Moved
sections", and a link to the new place right after it. Every link with an anchor in the repository must name a heading
or an anchor that exists.
"""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
READER_DOCS = [ROOT / "docs" / name for name in
               ("USING.md", "ADMIN.md", "HOW-IT-WORKS.md", "KNOWN-GAPS.md", "CLIENTS.md")]

# The level-2 headings of README.md before the split (0.9.12, 178,565 bytes), and its two level-3 headings.
OLD_HEADINGS = [
    "What it does", "Quick start", "How it works", "What it looks like", "Status", "Client support", "Requirements",
    "Install", "Update and uninstall", "For administrators", "What the plugin runs, sends and fetches",
    "Secret hygiene skill", "Options", "Vault", "Check a value first: ms:(…)",
    "Handing a value to Claude on purpose", "Invisible characters", "Disguised values in tool results",
    "Password exports in tool results", "Reporting a wrong detection", "Reporting an internal failure",
    "Gates around a resolve", "SSH consent (optional)", "Rehydration policy (optional)",
    "Test data that maisecrets leaves alone", "Detection rules", "Rules of your own", "PDFs and images",
    "Terms: names, case numbers, customer names", "Values from your own tools", "Vault references",
    "Sensitive References", "Names from a service (optional)", "Known gaps (measured or documented)", "Licence",
]
OLD_SUBHEADINGS = ["Settings you decide", "Where your secrets went"]

LINK = re.compile(r"\]\(([^)\s]+)\)")
NAMED = re.compile(r'<a name="([\w-]+)"></a>')
MOVED = re.compile(r'<a name="([\w-]+)"></a>\[[^\]]+\]\(([^)\s]+)\)')
URL = re.compile(r"https://github\.com/Mcpgate-de/maisecrets(?:/blob/main/([\w./-]+))?#([\w-]+)")


def slug(heading: str) -> str:
    """GitHub's anchor of a heading: lower case, punctuation removed, a space becomes a hyphen."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def headings(text: str) -> list[tuple[int, str]]:
    """(level, text) of each Markdown heading outside a fenced code block."""
    out, fenced = [], False
    for line in text.split("\n"):
        if line.startswith("```"):
            fenced = not fenced
        m = None if fenced else re.match(r"(#{1,6}) (.+?)\s*$", line)
        if m:
            out.append((len(m.group(1)), m.group(2)))
    return out


def anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    out = set()
    for _, h in headings(path.read_text(encoding="utf-8")):
        s = slug(h)
        n = seen.get(s, 0)
        seen[s] = n + 1
        out.add(s if n == 0 else f"{s}-{n}")
    return out | set(NAMED.findall(path.read_text(encoding="utf-8")))


def tracked(*patterns: str) -> list[Path]:
    names = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard",
                            *patterns], capture_output=True, text=True, check=True).stdout.split()
    return [ROOT / n for n in names if not n.startswith("bench/results/") and (ROOT / n).is_file()]


class MovedSectionsTests(unittest.TestCase):
    def test_the_readme_is_short(self):
        # counted with LF line ends: a Windows checkout writes CRLF and adds a byte per line
        self.assertLess(len(README.read_bytes().replace(b"\r\n", b"\n")), 15_000)

    def test_every_old_section_lives_in_the_readme_or_a_reader_document(self):
        level2 = {h for p in [README] + READER_DOCS for lvl, h in headings(p.read_text(encoding="utf-8"))
                  if lvl == 2}
        missing = [h for h in OLD_HEADINGS if h not in level2]
        self.assertEqual(missing, [], "a section of the old README has no place")

    def test_every_old_anchor_still_exists_in_the_readme(self):
        here = anchors(README)
        lost = [h for h in OLD_HEADINGS + OLD_SUBHEADINGS if slug(h) not in here]
        self.assertEqual(lost, [], "a link from outside to README.md#<anchor> would land nowhere")

    def test_every_moved_heading_links_to_a_heading_that_exists(self):
        text = README.read_text(encoding="utf-8")
        moved = text.split("\n## Moved sections\n", 1)[1]
        rows = MOVED.findall(moved)
        self.assertEqual(len(rows), len(NAMED.findall(moved)), "each anchor is followed by its link")
        for name, target in rows:
            path, _, anchor = target.partition("#")
            with self.subTest(target=target):
                self.assertIn(anchor, anchors(ROOT / path))

    def test_every_link_with_an_anchor_resolves(self):
        bad = []
        for f in tracked("*.md"):
            for target in LINK.findall(f.read_text(encoding="utf-8")):
                path, hash_, anchor = target.partition("#")
                if not hash_ or path.startswith(("http://", "https://", "mailto:")):
                    continue
                dest = (f.parent / path).resolve() if path else f
                if dest.suffix != ".md" or not dest.is_file():
                    continue
                if anchor not in anchors(dest):
                    bad.append(f"{f.relative_to(ROOT)}: {target}")
        for f in tracked("*.py", "*.json", "*.md"):
            for path, anchor in URL.findall(f.read_text(encoding="utf-8")):
                if anchor != "readme" and anchor not in anchors(ROOT / (path or "README.md")):
                    bad.append(f"{f.relative_to(ROOT)}: {path or 'README.md'}#{anchor}")
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
