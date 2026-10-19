"""Write every hit of the detector on fixed inputs to one file, so a refactor of the rules can show it changed nothing.

    python3 scripts/detection_fingerprint.py --out FILE [--creddata DIR] [--regions none,de,us,all]
        [--channels prompt,tool] [--samples FILE] [--no-tests] [--workers N]

For each input text, each channel and each region set the file holds one JSON line with the full hit list of
`detect.scan()`: rule id, placeholder type, start, end, and three flags per hit (`is_fixture` with no path,
`is_fixture` under a test path, `is_public_test_value`). The lines are sorted, so two runs on the same code give
the same bytes: compare them with `cmp`. A first line names the rules that `rules()` loads for each region set (a
count and a digest of the ids in their order).

The inputs:
- CredData (`--creddata`): every unique line of the labelled rows, read with the loader of
  `scripts/measure_creddata.py`. A line is named by its first row id (file path and CredData id).
- `tests/fp_corpus.py`: `NO_HIT` and `HIT`, with the `§` marks removed as the test does.
- `tests/fp_corpus_pii.py`, if the tree has it: `PII_NO_HIT` and `POSITIVE`.
- The token lists of the tests (`TOKENS` in `tests/test_rules_from_the_catalogs.py` and
  `tests/test_rules_from_other_detectors.py`), drawn with the seeds the tests use, in the forms the tests use.
- `--samples FILE`: a JSON list of `[corpus, id, text]`, for a check of the script itself.

The file holds ids, rule ids and offsets, never a value or a line. Each region set runs with its own fresh temp
store home and the test locale (`de_DE`), never ~/.maisecrets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from multiprocessing import get_context
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
CHANNELS = ("prompt", "tool")
# every country code that maisecrets/detection/regions.py names a language for: a superset of the regions of the
# regional
# and the Presidio rules. Fixed here, so a change in how a rule finds its region shows up as a changed hit
ALL_REGIONS = ("at", "au", "be", "br", "ca", "ch", "cz", "de", "dk", "es", "fi", "fr", "ie", "in", "it", "kr", "li",
               "lu", "ng", "nl", "no", "nz", "ph", "pl", "pt", "se", "sg", "th", "tr", "uk", "us", "za")
REGION_SETS = {"none": (), "de": ("de",), "us": ("us",), "all": ALL_REGIONS, "de+own": ("de",)}
# the set "de+own" adds rules of your own (a *.prefixes and a *.json file in rules.d) and an allow list that switches a
# built-in rule off and allows one exact value, so the rules of your own and the allow list are in the fingerprint too
OWN_PREFIXES = ("acme-deploy-token  acme_dpl_[A-Za-z0-9]{24}\n"
                # a rule of your own that overlaps the personal-data step: it must run after it (registry phase 3)
                "street-no  Hauptstra(?:ss|\u00df)e [0-9]+\n")
OWN_JSON = {"rules": [{"id": "ticket-secret", "regex": "TKT-SECRET-[0-9a-f]{16}", "keywords": ["tkt-secret"]},
                      {"id": "staff-number", "type": "SECRET", "regex": "\\bSTAFF-[0-9]{7}\\b"}]}
OWN_ALLOW_RULE = "jwt"
TEST_PATH = "tests/test_fingerprint_probe.py"
_HOME_VAR = "MAISECRETS" + "_HOME"
_CLIENT_PREFIXES = ("CODEX_", "CLAUDE_CODE_", "CLAUDE_PLUGIN_OPTION_")
_CLIENT_NAMES = ("CLAUDECODE", "MAISECRETS_KEY_FILE", "MAISECRETS_DEBUG_LOG", "MAISECRETS_TEST_HOME_OWNED")

_detect = None


# ------------------------------------------------------------------------------------------------- inputs --
def creddata_items(cd: str) -> list:
    sys.path.insert(0, str(ROOT / "scripts"))
    import measure_creddata as mc
    first: dict = {}
    for it in mc.load_items(cd):
        first.setdefault(it[2], it[6] + "#" + it[7])
    return [("creddata", rid, line) for line, rid in first.items()]


def corpus_items() -> list:
    sys.path.insert(0, str(TESTS))
    import fp_corpus
    out = [("fp_corpus:NO_HIT", f"{i:04d} {name}", text.replace("§", ""))
           for i, (name, text) in enumerate(fp_corpus.NO_HIT)]
    out += [("fp_corpus:HIT", f"{i:04d} {name}", text.replace("§", ""))
            for i, (name, text, _) in enumerate(fp_corpus.HIT)]
    if (TESTS / "fp_corpus_pii.py").exists():
        import fp_corpus_pii
        out += [("fp_corpus_pii:PII_NO_HIT", f"{i:04d} {name}", text)
                for i, (name, text) in enumerate(fp_corpus_pii.PII_NO_HIT)]
        out += [("fp_corpus_pii:POSITIVE", f"{i:04d} {name}", text)
                for i, (name, text, _) in enumerate(fp_corpus_pii.POSITIVE)]
    return out


_OWN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"


def _own_token(r, n: int = 24) -> str:
    return "acme_dpl_" + "".join(r.choice(_OWN_ALPHABET) for _ in range(n))


def own_items() -> list:
    """Texts for the rules of your own of the set "de+own", drawn from a fixed seed. The first token is the value the
    allow list of that set names."""
    import random
    r = random.Random("own rules")
    out = []
    for n in range(10):
        tok, ticket, staff = _own_token(r), "TKT-SECRET-" + "".join(r.choice("0123456789abcdef") for _ in range(16)), \
            "STAFF-" + "".join(r.choice("0123456789") for _ in range(7))
        forms = (tok, f"deploy with {tok} today", f"ticket {ticket} and staff {staff}", f"mail {staff}@example.org",
                 f"export TOKEN={tok}\n", _own_token(r, 12))
        out += [("own", f"{n:02d} {k}", text) for k, text in enumerate(forms)]
    return out


def _allowed_value() -> str:
    import random
    return _own_token(random.Random("own rules"))


# the test modules whose scans are replayed (recorded_items): the detector tests. A module that changes the store, the
# config or the clipboard is left out; it scans little and its texts hold temp paths
RECORDED_MODULES = ("test_core", "test_detect_rules", "test_rules_from_the_catalogs",
                    "test_rules_from_other_detectors", "test_rule_filter", "test_literal_values",
                    "test_tool_channel_normaliser", "test_shapeless_passwords",
                    "test_password_export", "test_labelled_keys", "test_detection_matrix", "test_tool_channel",
                    "test_public_benchmark_gaps", "test_personal_data", "test_label_languages", "test_fixtures",
                    "test_bank_and_company_numbers", "test_review_cases_0616", "test_word_values_not_hunted",
                    "test_fp_corpus", "test_leak_direction")
RECORD_MAX_CHARS = 20000     # the timing tests scan megabytes; their shapes are in the probes


def _record(out_path: str) -> int:
    """Run RECORDED_MODULES in this process with detect.scan wrapped, and write every distinct call (text, channel,
    path, enabled as a sorted list or null) to out_path. A call with rule_list, a text over RECORD_MAX_CHARS or a text
    that names a temp directory is left out: the last changes from run to run."""
    import io
    import unittest
    sys.path.insert(0, str(TESTS))
    import _isolate  # noqa: F401  first: a temp vault home, never the real one
    sys.path.insert(0, str(ROOT))
    from maisecrets import detect
    seen: dict = {}
    real = detect.scan
    tmp = tempfile.gettempdir()
    # a value of this machine's environment (a token in a variable) never goes into a recording
    env_values = [v for v in os.environ.values() if len(v) >= 12]

    def scan(text, enabled=None, channel="prompt", path="", rule_list=None):
        if rule_list is None and isinstance(text, str) and len(text) <= RECORD_MAX_CHARS and tmp not in text \
                and "maisecrets-test-" not in text and tmp not in (path or "") \
                and not any(v in text for v in env_values):
            key = (text, channel if channel == "tool" else "prompt", path or "",
                   None if enabled is None else tuple(sorted(enabled)))
            seen.setdefault(key, None)
        return real(text, enabled=enabled, channel=channel, path=path, rule_list=rule_list)
    detect.scan = scan
    suite = unittest.defaultTestLoader.loadTestsFromNames(list(RECORDED_MODULES))
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    detect.scan = real
    if result.errors or not result.testsRun:
        # a module that cannot load or a setup that breaks records less, silently (codex Gate A, round 2). A failed
        # assertion is reported but kept: a timing test under load fails without changing what it scanned
        print(f"recording refused: {len(result.errors)} errors in {result.testsRun} tests", file=sys.stderr)
        return 1
    if result.failures:
        print(f"recording: {len(result.failures)} failed tests", file=sys.stderr)
    rows = sorted(seen, key=lambda k: (k[0], k[1], k[2], k[3] or ()))
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # it holds the test texts
    with open(fd, "w", encoding="utf-8") as fh:
        json.dump([[t, c, p, list(e) if e is not None else None] for t, c, p, e in rows], fh, ensure_ascii=False)
    return 0


def recorded_items(recording: str = "") -> list:
    """The scans of the detector tests, recorded in a child process (or read from a recording of --record) and
    replayed here in both channels, each with its path and its enabled set. Ids are a count in sorted order, so the
    file names no text."""
    if recording:
        rows = json.loads(Path(recording).read_text(encoding="utf-8"))
        return [("tests:recorded", f"{n:05d} {c}", t, p, e) for n, (t, c, p, e) in enumerate(rows)]
    out_dir = tempfile.mkdtemp(prefix="maisecrets-fingerprint-rec-")
    try:
        out = os.path.join(out_dir, "rec.json")
        import subprocess
        subprocess.run([sys.executable, str(Path(__file__).resolve()), "--record", out], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)
        rows = json.loads(Path(out).read_text(encoding="utf-8"))
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
    return [("tests:recorded", f"{n:05d} {c}", t, p, e) for n, (t, c, p, e) in enumerate(rows)]


def probe_items() -> list:
    """One or more inputs for each matcher and each named filter of maisecrets/detection/registry.py, and for the
    password
    export, which reads the file name (a 4th element: the path given to scan). Values are drawn at run time from a
    fixed seed; the published test values are built from parts."""
    import random
    r = random.Random("probes")
    alnum = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    hexd, b32 = "0123456789abcdef", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    def rnd(alpha: str, n: int) -> str:
        return "".join(r.choice(alpha) for _ in range(n))
    pw = rnd(alnum, 6) + "#" + rnd(alnum, 6) + "!"
    akid = "AK" + "IA" + rnd(b32, 16)
    docs_key = "sk" + "_test_" + "4eC39HqLyjWD" + "arjtT1zdp7dc"     # the key of the Stripe API reference
    filler = "lorem ipsum dolor sit amet " * 200
    label = "pass" + "word"
    out = [
        ("windowed generic-api-key", filler + "\napi_" + "key = \"" + rnd(alnum, 32) + "\"\n" + filler),
        ("windowed word-path", filler + "\napi_" + "key = \"some/word/path\"\n" + filler),
        ("word-path", "api_" + "key = \"some/word/path\""),
        ("lines: a label at the end of a line", label + ":\n  " + pw + "\n"),
        ("lines: German label", "pass" + "wort:\n\n" + pw + "\nnext line"),
        ("escaped-value-quote", "{\\\"" + label + "\\\":\\\"" + pw + "\\\"}"),
        ("escaped-label-quote", "log: \"{\\\"db_" + label + "\\\": \\\"" + pw + "\\\"}\""),
        ("curl twice", "cu" + "rl -u alice" + ":" + rnd(alnum, 12) + " --user bob" + ":" + rnd(alnum, 12)
         + " https://x.example"),
        ("user-equals-password, curl", "curl -u alice:alice https://x.example"),
        ("curl header", "curl -H \"Authorization: Bearer " + rnd(alnum, 40) + "\" https://x.example"),
        ("sigv4-scope, query", "https://b.s3.amazonaws.com/o?X-Amz-Credential=" + akid
         + "%2F20240101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=" + rnd(hexd, 64)),
        ("sigv4-scope, header", "Authorization: AWS4-HMAC-SHA256 Credential=" + akid
         + "/20240101/us-east-1/s3/aws4_request, SignedHeaders=host"),
        ("an AWS key id alone", "key id " + akid + " here"),
        ("encoded-mail-context", "mailto:john.doe%40example.org and to=jane.roe%40example.net"),
        ("encoded mail without context", "path/john.doe%40example.org/x"),
        ("phone-shape", "call me at +49 " + "30 1234 5678 tomorrow, or 030 " + "1234 5678"),
        ("phone-shape, a version", "version 1.2.3.4 build 2024 12 31"),
        ("url-password-value", "https://:" + pw + "@db.example.org/x and https://:${PASS" + "WORD}@db.example.org/x"),
        ("password-value", 'resource "x" "y" {\n  ' + label + ' = "' + pw + '"\n  ' + label + ' = "var.db"\n}'),
        ("public test value after a label", "api_" + "key=" + docs_key),
        ("public test value after Bearer", "Authorization: Bearer " + docs_key),
        ("public test value in a query", "https://x.example/cb?token=" + docs_key),
        ("public test value alone", "use " + docs_key + " in tests"),
        ("words-not-token", "Authorization: Bearer some-words-here"),
        ("template-value", "https://x.example/cb?token={body['transfer_id']}"),
        ("seed-phrase", "seed: " + " ".join(["abandon"] * 11 + ["about"])),
        ("base64-wrapped-end", "private_" + "key: MII" + rnd(alnum + "+/", 60) + "\n  " + rnd(alnum + "+/", 60) + "=="),
        ("pg-password-switch", "psql --" + label + " app_db"),
        ("list", label + "s:\n- " + pw + "\n- " + rnd(alnum, 14)),
        ("user-equals-password, url", "https://bob:bob@host.example/"),
        ("basic auth", "https://bob:" + pw + "@host.example/"),
        ("derived-label", "secret_" + "id = 3f2b8c1e-4d5a-4b6c-8d7e-9f0a1b2c3d4e"),
        ("a measure after a label", "TTL_REFRESH_TOKEN = 2592000"),
        ("literal", "pw " + pw),
        ("personal data and a rule of your own", "Adresse: Hauptstra\u00dfe 12, 10115 Berlin"),
        ("a label value that holds a label form", label + ': "api_' + "key=" + rnd(alnum, 24) + '"'),
        ("a label value that holds a query form", label + ': "https://x.example/cb?token=' + rnd(alnum, 24) + '"'),
        ("a label value that holds a Bearer form", label + ': "Bearer ' + rnd(alnum, 32) + '"'),
    ]
    items = [("probes", name, text) for name, text in out]
    export = "url,username," + label + "\nhttps://a.example.org,alice," + pw + "\nhttps://b.example.org,bob," \
        + rnd(alnum, 14) + "\n"
    items += [("probes", "password export, its file name", export, "exports/" + label + "s.csv"),
              ("probes", "password export, another name", export, "data/report.csv")]
    return items


def token_items() -> list:
    """The tokens and look-alikes of the token tests, drawn with the tests' seeds (random.Random(rule id), 20 draws),
    in the three forms the tests scan. The test modules import tests/_isolate.py, which gives this process a temp
    home; each region set below still gets its own."""
    import random
    sys.path.insert(0, str(TESTS))
    out = []
    for mod_name in ("test_rules_from_the_catalogs", "test_rules_from_other_detectors"):
        mod = __import__(mod_name)
        for rule_id, gen in sorted(mod.TOKENS.items()):
            r = random.Random(rule_id)
            for n in range(20):
                tok, miss = gen(r)
                forms = (tok, f"export TOKEN_VALUE={tok}\n", f"here it is: {tok} thanks", miss)
                for k, text in enumerate(forms):
                    out.append((f"tokens:{mod_name}", f"{rule_id} {n:02d} {k}", text))
    return out


# ----------------------------------------------------------------------------------------------- the scan --
def _init(home: str) -> None:
    global _detect
    for k in list(os.environ):
        if k.startswith(_CLIENT_PREFIXES) or k in _CLIENT_NAMES:
            del os.environ[k]
    os.environ[_HOME_VAR] = home
    os.environ["MAISECRETS_LOCALE"] = "de_DE"
    sys.path.insert(0, str(ROOT))
    from maisecrets import detect
    detect.rules()
    _detect = detect


def _hits(text: str, channel: str, path: str = "", enabled=None) -> list:
    d = _detect
    out = []
    for m in d.scan(text, channel=channel, path=path, enabled=None if enabled is None else set(enabled)):
        out.append([m.kind, m.type, m.start, m.end, int(d.is_fixture(m, text)), int(d.is_fixture(m, text, TEST_PATH)),
                    int(d.is_public_test_value(m.value, m.type))])
    return out


def _work(item):
    corpus, rid, text, path, enabled, channels = item
    return corpus, rid, {ch: _hits(text, ch, path, enabled) for ch in channels}


def _rule_info(_=None):
    d = _detect
    ids = [r.id for r in d.rules()]
    active = d.active_regions()
    return {"rules": len(ids), "ids_sha256": hashlib.sha256("\n".join(ids).encode()).hexdigest(),
            "regions": list(active.regions), "languages": list(active.languages)}


def _home_for(name: str) -> str:
    home = tempfile.mkdtemp(prefix="maisecrets-fingerprint-")
    with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as fh:
        json.dump({"backend": "jsonfile", "allow_plaintext_store": True, "regions": list(REGION_SETS[name])}, fh)
    if name.endswith("+own"):
        own = os.path.join(home, "rules.d")
        os.makedirs(own)
        with open(os.path.join(own, "acme.prefixes"), "w", encoding="utf-8") as fh:
            fh.write(OWN_PREFIXES)
        with open(os.path.join(own, "team.json"), "w", encoding="utf-8") as fh:
            json.dump(OWN_JSON, fh)
        with open(os.path.join(home, "allow.txt"), "w", encoding="utf-8") as fh:
            fh.write(f"rule: {OWN_ALLOW_RULE}\n{_allowed_value()}\n")
    return home


def run(items: list, region_sets: list, channels: tuple, workers: int) -> tuple:
    """(header, lines, hits): the rule info per region set, one sorted JSON line per input, channel and region set,
    and the number of hits in them."""
    header, lines, hits = {}, [], 0
    ctx = get_context("spawn")    # the same start on every platform; a fork would copy this process' imports
    for name in region_sets:
        home = _home_for(name)
        try:
            with ctx.Pool(max(1, workers), initializer=_init, initargs=(home,)) as pool:
                header[name] = pool.apply(_rule_info)
                work = [(it[0], it[1], it[2], it[3] if len(it) > 3 else "", it[4] if len(it) > 4 else None,
                         channels) for it in items]
                for corpus, rid, res in pool.imap(_work, work, chunksize=50):
                    for ch in channels:
                        hits += len(res[ch])
                        lines.append(json.dumps([name, corpus, rid, ch, res[ch]], ensure_ascii=False,
                                                separators=(",", ":")))
        finally:
            shutil.rmtree(home, ignore_errors=True)
    lines.sort()
    return header, lines, hits


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out")
    ap.add_argument("--creddata", help="a CredData checkout (meta/ and data/)")
    ap.add_argument("--regions", default="none,de,us,all,de+own", help="region sets: " + ",".join(REGION_SETS))
    ap.add_argument("--channels", default=",".join(CHANNELS))
    ap.add_argument("--samples", help="a JSON list of [corpus, id, text] instead of the built-in inputs")
    ap.add_argument("--no-tests", action="store_true", help="leave out the corpora and token lists of tests/")
    ap.add_argument("--no-recorded", action="store_true", help="leave out the recorded scans of the detector tests")
    ap.add_argument("--record", help=argparse.SUPPRESS)
    ap.add_argument("--recorded", help="replay this recording (written by --record FILE) instead of recording again")
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args(argv)
    if a.record:
        return _record(a.record)
    if not a.out:
        ap.error("--out is required")
    region_sets = [x for x in a.regions.split(",") if x]
    bad = [x for x in region_sets if x not in REGION_SETS]
    channels = tuple(x for x in a.channels.split(",") if x)
    if bad or not region_sets or not channels or set(channels) - set(CHANNELS):
        ap.error(f"unknown region set or channel: {bad or channels}")
    items: list = []
    if a.samples:
        items += [tuple(x) for x in json.loads(Path(a.samples).read_text(encoding="utf-8"))]
    else:
        if a.creddata:
            items += creddata_items(a.creddata)
        if not a.no_tests:
            items += corpus_items() + token_items() + own_items() + probe_items()
            if not a.no_recorded:
                items += recorded_items(a.recorded or "")
    keys = [(it[0], it[1]) for it in items]
    if len(set(keys)) != len(keys):
        raise SystemExit("two inputs have the same corpus and id")
    header, lines, hits = run(items, region_sets, channels, a.workers)
    with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps({"inputs": len(items), "rules": header}, sort_keys=True) + "\n")
        for ln in lines:
            fh.write(ln + "\n")
    print(f"{len(items)} inputs, {len(lines)} lines, {hits} hits -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
