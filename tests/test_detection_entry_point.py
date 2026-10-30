"""The JSON entry point of the detection core (python3 -m maisecrets.detection, contract maisecrets.detect/1;
docs/DETECTION.md, "The JSON entry point").

The conformance cases go through the entry point in a process of their own and must agree with the Python API; every
response kind and the examples of the docs fit the schema; one request gives the same bytes in two fresh processes;
the ruleset digest does not depend on line ends; and no output holds a value of the request.

Run: python3 -m unittest tests.test_detection_entry_point -v
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import NO_REFERENCES, NO_SOURCES, TYPES, Active, Detector, Host, contract  # noqa: E402

CASES = json.loads((ROOT / "tests" / "conformance" / "cases.json").read_text(encoding="utf-8"))["cases"]
SCHEMA = json.loads(contract.SCHEMA.read_text(encoding="utf-8"))
# a GitHub token shape, made at run time so the file holds none; it names itself as synthetic
TOKEN = "ghp_" + "Synthetic" + "A1b2C3d4" * 3 + "Zz9y5"


def call(request, root: Path = ROOT, args=(), env: dict | None = None) -> subprocess.CompletedProcess:
    """python3 -m maisecrets.detection in a fresh process, with the package of `root`."""
    raw = request if isinstance(request, bytes) else json.dumps(request).encode("utf-8")
    environ = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    environ.update(env or {})
    return subprocess.run([sys.executable, "-m", "maisecrets.detection", *args], input=raw, cwd=str(root),
                          capture_output=True, env=environ, timeout=120)


def request_of(case: dict) -> dict:
    out = {"contract": contract.CONTRACT, "text": case["input"], "channel": case["channel"],
           "regions": case["regions"], "languages": case["languages"]}
    if "context" in case:
        out["context"] = case["context"]
    return out


def fields_of(case: dict):
    given = case.get("context", {}).get("fields")
    return None if given is None else [(f["start"], f["end"], tuple(f["name"])) for f in given]


def library(case: dict) -> list:
    """(start, end, type, rule) of the Python API with the configuration of the entry point."""
    d = Detector(regions=Active(regions=tuple(case["regions"]), languages=tuple(case["languages"]), source="t"),
                 sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="", year=time.gmtime().tm_year))
    return sorted({(m.start, m.end, m.type, m.kind) for m in d.findings(case["input"], channel=case["channel"],
                                                                fields=fields_of(case))})


# ------------------------------------------------------------------------------------------- a small schema check --
# jsonschema is no dependency; the schema uses these keywords only, and test_the_schema_uses_only_checked_keywords
# holds that, so a keyword added later is not silently ignored here
CHECKED = {"type", "const", "enum", "pattern", "minimum", "maximum", "required", "properties", "additionalProperties",
           "items", "oneOf", "$ref"}
ANNOTATIONS = {"$schema", "$id", "title", "description", "$defs"}
TYPE_OF = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float)}


def problems(value, schema: dict, where: str = "") -> list:
    if "$ref" in schema:
        return problems(value, SCHEMA["$defs"][schema["$ref"].rsplit("/", 1)[1]], where)
    if "oneOf" in schema:
        fits = [s for s in schema["oneOf"] if not problems(value, s, where)]
        return [] if len(fits) == 1 else [f"{where}: fits {len(fits)} of oneOf"]
    out = []
    t = schema.get("type")
    if t and (not isinstance(value, TYPE_OF[t]) or isinstance(value, bool)):
        return [f"{where}: not {t}"]
    if "const" in schema and value != schema["const"]:
        out.append(f"{where}: not the const")
    if "enum" in schema and value not in schema["enum"]:
        out.append(f"{where}: not in the enum")
    if "pattern" in schema and not re.search(schema["pattern"], value):
        out.append(f"{where}: does not match")
    if "minimum" in schema and value < schema["minimum"]:
        out.append(f"{where}: below the minimum")
    if "maximum" in schema and value > schema["maximum"]:
        out.append(f"{where}: above the maximum")
    if isinstance(value, dict):
        out += [f"{where}.{k}: missing" for k in schema.get("required", ()) if k not in value]
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            out += [f"{where}.{k}: not allowed" for k in value if k not in props]
        for k, v in value.items():
            if k in props:
                out += problems(v, props[k], f"{where}.{k}")
    if isinstance(value, list) and "items" in schema:
        for i, v in enumerate(value):
            out += problems(v, schema["items"], f"{where}[{i}]")
    return out


def response_problems(doc) -> list:
    return problems(doc, SCHEMA["$defs"]["response"], "response")


class ConformanceThroughTheEntryPoint(unittest.TestCase):
    def test_each_case_holds_through_the_entry_point_and_agrees_with_the_python_api(self):
        self.assertGreaterEqual(len(CASES), 15, "the premise: the cases of the file, the three of the entry point too")
        for c in CASES:
            with self.subTest(case=c["id"]):
                r = call(request_of(c))
                self.assertEqual((r.returncode, r.stderr), (0, b""))
                out = json.loads(r.stdout)
                self.assertEqual(response_problems(out), [])
                rows = [(f["start"], f["end"], f["type"], f["provenance"]["rule"]) for f in out["findings"]]
                self.assertEqual(rows, library(c), "the entry point and the Python API give the same findings")
                found = {(s, e, t) for s, e, t, _ in rows}
                for s in c["expected"]:
                    self.assertIn((s["start"], s["end"], s["type"]), found)
                for s in c["not_expected"]:
                    self.assertEqual([x for x in rows if x[2] == s["type"] and x[0] < s["end"] and s["start"] < x[1]],
                                     [])
                self.assertTrue(all(rows[i][1] <= rows[i + 1][0] for i in range(len(rows) - 1)), "no overlap")

    def test_the_file_names_the_contract_and_the_unit_of_its_offsets(self):
        doc = json.loads((ROOT / "tests" / "conformance" / "cases.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["contract"], contract.CONTRACT)
        self.assertIn("code points", doc["offsets"])
        astral = next(c for c in CASES if c["id"] == "offsets-count-code-points")
        self.assertGreater(len(astral["input"].encode("utf-16-le")) // 2, len(astral["input"]),
                           "the premise: the case has characters outside the BMP")


class TheSchema(unittest.TestCase):
    def test_the_schema_uses_only_checked_keywords(self):
        def keywords(node, out):
            if isinstance(node, dict):
                for k, v in node.items():
                    out.add(k)
                    # the names under properties and $defs are names, not keywords
                    for sub in (v.values() if k in ("properties", "$defs") else [v]):
                        keywords(sub, out)
            elif isinstance(node, list):
                for v in node:
                    keywords(v, out)
            return out
        self.assertEqual(keywords(SCHEMA, set()) - CHECKED - ANNOTATIONS, set())

    def test_the_check_refuses_a_wrong_response(self):
        good = json.loads(call(request_of(CASES[0])).stdout)
        self.assertEqual(response_problems(good), [], "the premise: a real response fits")
        wrong = [
            {**good, "findings": [{**good["findings"][0], "value": "x"}]},
            {**good, "findings": [{**good["findings"][0], "start": -1}]},
            {**good, "findings": [{**good["findings"][0], "start": True}]},
            {**good, "engine": {**good["engine"], "ruleset": "md5:00"}},
            {**good, "contract": "maisecrets.detect/2"},
            {k: v for k, v in good.items() if k != "findings"},
            {**good, "error": {"code": "invalid_json", "path": "", "message": ""}},
            {"contract": contract.CONTRACT, "error": {"code": "timeout", "path": "", "message": ""}},
        ]
        for doc in wrong:
            with self.subTest(doc=sorted(doc)):
                self.assertNotEqual(response_problems(doc), [])

    def test_every_type_of_the_vocabulary_fits_the_type_of_a_finding(self):
        pattern = SCHEMA["$defs"]["finding"]["properties"]["type"]["pattern"]
        self.assertEqual([t for t in TYPES if not re.search(pattern, t)], [])

    def test_the_examples_of_the_docs_fit_and_the_entry_point_gives_the_example_response(self):
        text = (ROOT / "docs" / "DETECTION.md").read_text(encoding="utf-8")
        section = text.split("## The JSON entry point", 1)[1].split("\n## ", 1)[0]
        blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", section, re.S)]
        self.assertEqual(len(blocks), 3, "the request, the response and the error of the section")
        request, response, err = blocks
        self.assertEqual(problems(request, SCHEMA["$defs"]["request"]), [])
        self.assertEqual(response_problems(err), [])
        r = call(request)
        self.assertEqual(r.returncode, 0)
        got = json.loads(r.stdout)
        self.assertEqual(response_problems(got), [])
        # the version and the digest of the docs are placeholders; the rest is what the engine answers
        self.assertEqual({**got, "engine": response["engine"]}, response)
        bad = call({**request, "regions": ["generic", "xx"]})
        self.assertEqual((bad.returncode, json.loads(bad.stdout)), (2, err))


class Errors(unittest.TestCase):
    def assertRefused(self, request, code: str, path: str, status: int = 2):
        r = call(request)
        self.assertEqual(r.returncode, status)
        self.assertEqual(r.stderr, b"")
        out = json.loads(r.stdout)
        self.assertEqual(response_problems(out), [])
        self.assertEqual((out["error"]["code"], out["error"]["path"]), (code, path))
        self.assertNotIn(TOKEN.encode(), r.stdout)
        self.assertNotIn(TOKEN[4:12].encode(), r.stdout)
        return out

    def test_a_secret_in_a_wrong_field_is_never_echoed(self):
        ok = {"contract": contract.CONTRACT, "text": "plain text", "channel": "tool", "regions": ["generic"],
              "languages": ["en"]}
        cases = [
            ({**ok, "contract": TOKEN}, "unsupported_contract", "contract"),
            ({**ok, "channel": TOKEN}, "invalid_request", "channel"),
            ({**ok, "regions": ["generic", TOKEN]}, "invalid_request", "regions[1]"),
            ({**ok, "languages": [TOKEN]}, "invalid_request", "languages[0]"),
            ({**ok, TOKEN: "x"}, "invalid_request", ""),
            ({**ok, "extra": TOKEN}, "invalid_request", ""),
            ({**ok, "context": {TOKEN: 1}}, "invalid_request", "context"),
            ({**ok, "context": {"fields": [{"start": 0, "end": 5, "name": ["a"], TOKEN: 1}]}}, "invalid_request",
             "context.fields[0]"),
            ({**ok, "context": {"fields": [{"start": 0, "end": 99, "name": [TOKEN]}]}}, "invalid_request",
             "context.fields[0]"),
            ({**ok, "context": {"fields": [{"start": 0, "end": 5, "name": [TOKEN, None]}]}}, "invalid_request",
             "context.fields[0].name[1]"),
            ({**ok, "context": {"fields": [{"start": 0, "end": 5, "name": ["a"], "format": [TOKEN]}]}},
             "invalid_request", "context.fields[0].format"),
            ({**ok, "context": {"fields": TOKEN}}, "invalid_request", "context.fields"),
            ({**ok, "context": TOKEN}, "invalid_request", "context"),
            ({**ok, "text": [TOKEN]}, "invalid_request", "text"),
            ({k: v for k, v in {**ok, "note": TOKEN}.items() if k != "text"}, "invalid_request", ""),
            ([TOKEN], "invalid_request", ""),
        ]
        for request, code, path in cases:
            with self.subTest(code=code, path=path):
                self.assertRefused(request, code, path)
        raw = json.dumps(ok).encode()
        for broken in (raw[:-1] + b', "text": "' + TOKEN.encode() + b'"}',          # a key twice
                       b'{"contract": "' + TOKEN.encode() + b'", ',                  # cut off
                       raw.replace(b'"plain text"', b'"' + TOKEN.encode() + b'\xff"'),   # no UTF-8
                       raw[:-1] + b', "n": NaN, "x": "' + TOKEN.encode() + b'"}'):
            with self.subTest(raw=len(broken)):
                self.assertRefused(broken, "invalid_json", "")

    def test_context_fields_reach_the_detector_and_no_name_is_echoed(self):
        base = {"contract": contract.CONTRACT, "text": "0171 4829173", "channel": "tool", "regions": ["generic", "de"],
                "languages": ["de", "en"]}
        self.assertEqual(json.loads(call(base).stdout)["findings"], [], "the premise: bare it is no finding")
        field = {"start": 0, "end": 12, "name": ["customer", "telefon"], "format": "json"}
        r = call({**base, "context": {"fields": [field]}})
        self.assertEqual((r.returncode, r.stderr), (0, b""))
        out = json.loads(r.stdout)
        self.assertEqual(response_problems(out), [])
        self.assertEqual([(f["start"], f["end"], f["type"]) for f in out["findings"]], [(0, 12, "PHONE")])
        r = call({**base, "context": {"fields": [{"start": 0, "end": 12, "name": [TOKEN, 0]}]}})
        self.assertEqual((r.returncode, json.loads(r.stdout)["findings"]), (0, []))
        self.assertNotIn(TOKEN.encode(), r.stdout)
        for bad in ({"start": True, "end": 12, "name": ["a"]}, {"start": 0, "end": 12.0, "name": ["a"]},
                    {"start": 0, "end": 12, "name": []}, {"start": 0, "end": 12},
                    {"start": 3, "end": 3, "name": ["a"]}):
            with self.subTest(bad=sorted(bad)):
                r = call({**base, "context": {"fields": [bad]}})
                self.assertEqual((r.returncode, json.loads(r.stdout)["error"]["code"]), (2, "invalid_request"))
                self.assertTrue(json.loads(r.stdout)["error"]["path"].startswith("context.fields[0]"))

    def test_the_required_keys_and_the_arguments(self):
        ok = {"contract": contract.CONTRACT, "text": "", "channel": "prompt", "regions": [], "languages": []}
        for key in ok:
            with self.subTest(missing=key):
                self.assertRefused({k: v for k, v in ok.items() if k != key}, "invalid_request", key)
        self.assertRefused({**ok, "context": {"path": 3}}, "invalid_request", "context.path")
        r = call(ok, args=[TOKEN])
        self.assertEqual((r.returncode, r.stderr, json.loads(r.stdout)["error"]["code"]), (2, b"", "invalid_request"))
        self.assertNotIn(TOKEN.encode(), r.stdout)
        self.assertEqual(json.loads(call(ok).stdout)["findings"], [], "the premise: the request itself is good")

    def test_an_internal_error_names_the_class_and_no_value(self):
        raw = json.dumps({"contract": contract.CONTRACT, "text": "token " + TOKEN, "channel": "tool",
                          "regions": ["generic"], "languages": ["en"]}).encode()
        with mock.patch.object(contract, "detect", side_effect=ValueError("bad value " + TOKEN)):
            status, line = contract.respond(raw, [])
        self.assertEqual(status, 3)
        self.assertEqual(json.loads(line)["error"], {"code": "internal_error", "path": "",
                                                     "message": "the engine failed: ValueError"})
        self.assertNotIn(TOKEN, line)

    def test_a_finding_carries_no_value(self):
        r = call({"contract": contract.CONTRACT, "text": "my token " + TOKEN + " here", "channel": "prompt",
                  "regions": ["generic"], "languages": ["en"]})
        out = json.loads(r.stdout)
        self.assertEqual([(f["start"], f["end"], f["type"]) for f in out["findings"]], [(9, 9 + len(TOKEN), "SECRET")])
        self.assertNotIn(TOKEN[4:12].encode(), r.stdout)
        self.assertEqual(r.stderr, b"")


class Determinism(unittest.TestCase):
    TEXT = ("Name: Dana Okafor\nIBAN: DE89 3704 0044 0532 0130 00\nmail dana.okafor@mail-host.test\n"
            "token " + TOKEN + "\nSteuer-ID 12 345 678 901\n")

    def request(self, regions=("generic", "de", "us")) -> dict:
        return {"contract": contract.CONTRACT, "text": self.TEXT, "channel": "tool", "regions": list(regions),
                "languages": ["en", "de"]}

    def test_two_fresh_processes_give_the_same_bytes_sorted(self):
        a = call(self.request(), env={"PYTHONHASHSEED": "1"})
        b = call(self.request(), env={"PYTHONHASHSEED": "2"})
        self.assertEqual(a.returncode, 0)
        self.assertEqual(a.stdout, b.stdout)
        rows = [(f["start"], f["end"], f["type"], f["provenance"]["rule"]) for f in json.loads(a.stdout)["findings"]]
        self.assertGreaterEqual(len(rows), 3, "the premise: several findings to order")
        self.assertEqual(rows, sorted(rows))
        self.assertEqual(list(json.loads(a.stdout)), ["contract", "engine", "findings"])

    def test_the_ruleset_names_the_regions_and_the_languages(self):
        digest = [json.loads(call(r).stdout)["engine"]["ruleset"] for r in (
            self.request(), self.request(("generic", "us", "de")), self.request(("generic", "de")),
            {**self.request(), "languages": ["en"]})]
        self.assertEqual(digest[0], digest[1], "the same regions in another order load the same rules")
        self.assertNotEqual(digest[0], digest[2])
        self.assertNotEqual(digest[0], digest[3])
        # a region with no rule of its own under English labels (France): the digest names it all the same
        alone = [json.loads(call({**self.request(r), "languages": ["en"]}).stdout)["engine"]["ruleset"]
                 for r in (("generic",), ("generic", "fr"))]
        self.assertNotEqual(alone[0], alone[1])

    def test_crlf_line_ends_give_the_same_response(self):
        # a Windows checkout with core.autocrlf: every text file of the package with CRLF
        with tempfile.TemporaryDirectory(prefix="ms-crlf-") as tmp:
            dst = Path(tmp) / "maisecrets"
            shutil.copytree(ROOT / "maisecrets" / "detection", dst / "detection",
                            ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copy(ROOT / "maisecrets" / "__init__.py", dst / "__init__.py")
            changed = 0
            for p in dst.rglob("*"):
                if p.is_file():
                    data = p.read_bytes()
                    if b"\n" in data and b"\x00" not in data:
                        p.write_bytes(data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
                        changed += 1
            self.assertGreater(changed, 20, "the premise: the rule data and the code have CRLF now")
            a, b = call(self.request()), call(self.request(), root=Path(tmp))
        self.assertEqual((a.returncode, b.returncode), (0, 0), b.stdout)
        ja, jb = json.loads(a.stdout), json.loads(b.stdout)
        self.assertEqual(ja["engine"]["ruleset"], jb["engine"]["ruleset"])
        self.assertEqual(ja["findings"], jb["findings"])


if __name__ == "__main__":
    unittest.main()
