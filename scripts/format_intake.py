#!/usr/bin/env python3
"""The weekly intake of token formats: every signal that a format is new or changed, in one queue
(docs/DETECTION-COVERAGE.md, loop 3).

    python3 scripts/format_intake.py [--out DIR] [--days N]

It collects, without a value:

- watch: the entries of the public format lists that are new, or whose rule text changed (scripts/watch_formats.py
  against docs/format-watch.txt and docs/format-watch-fp.txt);
- report: the open issues on the GitHub tracker whose title begins "Token format:", the reports that the answer of
  ms:(…) links (the shape only, never the value);
- feed: the posts of the last N days (default 14) in the provider changelogs of docs/format-feeds.txt whose title or
  summary names a token, key or secret format.

It writes DIR/queue.jsonl (one item per line: kind, source, item, url, date) and DIR/queue.md for a person or an
agent, and exits 1 when the queue holds an item, so the scheduled job turns red as the notice. Nothing is added to
the rules by itself: whoever works the queue researches each item (bench/formats/research-<date>.jsonl), drafts rules
with scripts/draft_researched_rules.py, and runs the FP bank, the catalog coverage and the release gate. A watch item
stays in the queue until `scripts/watch_formats.py update` takes it into the snapshot; a report until its issue is
closed; a feed post for N days. Standard library only; GITHUB_TOKEN is used when set.
"""
from __future__ import annotations

import argparse
import datetime
import email.utils
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import watch_formats as wf  # noqa: E402

FEEDS = ROOT / "docs" / "format-feeds.txt"
TRACKER = "Mcpgate-de/maisecrets"
# a post about a token format, not every post that mentions a key
FORMAT_WORDS = re.compile(r"(?i)\b(?:(?:api|access|secret|signing|deploy|service|personal)[ -]?(?:key|token)s?|"
                          r"tokens?|secret scanning|push protection|credential)\b.{0,60}\b(?:format|prefix|"
                          r"scannable|new|rotat\w*|checksum|length|identifiable)\b|"
                          r"\b(?:new|scannable|identifiable)\b.{0,40}\b(?:tokens?|api keys?|secrets?)\b")


def _get(url: str) -> bytes:
    return wf._get(url)


def watch_items() -> list[dict]:
    news, changed = wf.diff_against_snapshot(wf.fetch_all())
    today = datetime.date.today().isoformat()
    out = [{"kind": "watch-new", "source": s, "item": i, "url": "", "date": today} for s, ids in news.items()
           for i in ids]
    out += [{"kind": "watch-changed", "source": s, "item": i, "url": "", "date": today} for s, ids in changed.items()
            for i in ids]
    return out


def report_items(issues: list[dict]) -> list[dict]:
    """The open format reports among GitHub issues (pull requests left out)."""
    return [{"kind": "report", "source": "github-issue", "item": i["title"].split(":", 1)[1].strip(),
             "url": i.get("html_url", ""), "date": (i.get("created_at") or "")[:10]}
            for i in issues if "pull_request" not in i and i.get("title", "").startswith("Token format:")]


def _date(text: str | None) -> datetime.date | None:
    if not text:
        return None
    try:
        return email.utils.parsedate_to_datetime(text).date()          # RSS
    except (TypeError, ValueError, IndexError):
        pass
    try:
        return datetime.date.fromisoformat(text.strip()[:10])            # Atom
    except ValueError:
        return None


def feed_posts(xml: bytes) -> list[tuple]:
    """(title, link, summary, date) of each item of an RSS feed or entry of an Atom feed."""
    root = ET.fromstring(xml)
    out = []
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag not in ("item", "entry"):
            continue
        kids = {c.tag.rsplit("}", 1)[-1]: c for c in el}
        title = (kids["title"].text or "") if "title" in kids else ""
        link = kids.get("link")
        href = (link.get("href") or link.text or "") if link is not None else ""
        summary = ""
        for k in ("description", "summary", "content"):
            if k in kids and kids[k].text:
                summary = re.sub(r"<[^>]+>", " ", kids[k].text)[:600]
                break
        when = None
        for k in ("pubDate", "published", "updated", "date"):
            if k in kids:
                when = _date(kids[k].text)
                if when:
                    break
        out.append((title.strip(), href.strip(), summary, when))
    return out


def feed_items(name: str, xml: bytes, since: datetime.date) -> list[dict]:
    return [{"kind": "feed", "source": name, "item": title, "url": link, "date": when.isoformat()}
            for title, link, summary, when in feed_posts(xml)
            if when and when >= since and FORMAT_WORDS.search(f"{title} {summary}")]


def load_feeds(text: str) -> list[tuple]:
    """`name url` per line; # starts a comment."""
    return [tuple(line.split(None, 1)) for line in (r.split("#", 1)[0].strip() for r in text.splitlines())
            if line and len(line.split(None, 1)) == 2]


def markdown(items: list[dict]) -> str:
    if not items:
        return "# Format intake\n\nNothing new this week.\n"
    lines = ["# Format intake", "", f"{len(items)} items. Research each one (its provider's documentation, SDK and "
             "changelog), write bench/formats/research-<date>.jsonl, and draft rules with "
             "scripts/draft_researched_rules.py.", ""]
    for kind in ("watch-new", "watch-changed", "report", "feed"):
        rows = [i for i in items if i["kind"] == kind]
        if rows:
            lines += [f"## {kind} ({len(rows)})", ""]
            lines += [f"- {r['source']}: {r['item']}" + (f" ({r['url']})" if r["url"] else "") + f", {r['date']}"
                      for r in rows]
            lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("format-intake"))
    ap.add_argument("--days", type=int, default=14)
    a = ap.parse_args(argv)
    items, problems = watch_items(), []
    try:
        items += report_items(json.loads(_get(f"{wf.API}{TRACKER}/issues?state=open&per_page=100")))
    except Exception as e:  # noqa: BLE001 - one unreachable source must not hide the others
        problems.append(f"reports: {type(e).__name__}")
    since = datetime.date.today() - datetime.timedelta(days=a.days)
    for name, url in load_feeds(FEEDS.read_text(encoding="utf-8")):
        try:
            items += feed_items(name, _get(url), since)
        except Exception as e:  # noqa: BLE001
            problems.append(f"feed {name}: {type(e).__name__}")
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "queue.jsonl").write_text("".join(json.dumps(i, ensure_ascii=False) + "\n" for i in items),
                                       encoding="utf-8")
    report = markdown(items) + ("\n## Sources not read\n\n" + "\n".join(f"- {p}" for p in problems) + "\n"
                                if problems else "")
    (a.out / "queue.md").write_text(report, encoding="utf-8")
    print(report)
    return 1 if items else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
