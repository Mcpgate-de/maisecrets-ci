#!/usr/bin/env python3
"""A server that uses maisecrets.detection as a library, the way foreign code would: public names only, no home folder,
no plugin. It prints one JSON object with what it found; tests/test_library_consumer.py runs it in a fresh process.

What a request-serving process needs, and how it does it with the public API:
- one Detector per configuration, built once and used for many requests and from many threads;
- its own regions and languages (Active), no references, its own host;
- rules of its own through a Sources subclass and user_rule(); Detector.reset() to read them again;
- typed findings (Match: kind, type, value, start, end).

Run: python3 -I examples/library_consumer.py   (with the repository root on PYTHONPATH)
"""
import json
import sys
import threading
import time
import tracemalloc

from maisecrets.detection import (Active, Detector, Host, Match, NO_REFERENCES, NO_SOURCES, Sources,
                                  user_rule)

TICKET = "ACME-" + "482913"                       # a value of the consumer's own kind
MAIL = "jonas.brandt" + "@" + "posteo.de"
NANP = "(415) 382-" + "9174"                      # a North American phone number: region us only


class TenantSources(Sources):
    """The rules of one tenant. The detector asks user_rules() once per rule load: at the first scan and after
    reset()."""

    def __init__(self, rules):
        self.rules = list(rules)

    def user_rules(self):
        return list(self.rules)


def detector(regions, sources=NO_SOURCES):
    return Detector(regions=Active(regions=regions, languages=("en",), source="consumer"), sources=sources,
                    references=NO_REFERENCES, host=Host(user="svc-gateway", year=2026))


def kinds(d, text):
    return sorted({m.kind for m in d.findings(text, channel="tool")})


result = {}

# own rule: the stable constructor, and its errors
ticket_rule = user_rule("acme-ticket", "ACME_TICKET", r"ACME-[0-9]{6}", keywords=("acme",))
errors = {}
for name, kwargs in (("bad type", dict(id="x", type="lower", pattern="x")),
                     ("bad regex", dict(id="x", type="X", pattern="(")),
                     ("bad group", dict(id="x", type="X", pattern="a", secret_group=2)),
                     ("id with space", dict(id="a b", type="X", pattern="a"))):
    try:
        user_rule(**kwargs)
        errors[name] = "accepted"
    except ValueError:
        errors[name] = "ValueError"
result["user_rule_errors"] = errors

# two tenants, two configurations, side by side
tenant = TenantSources([ticket_rule])
us = detector(("generic", "us"), tenant)
generic = detector(("generic",))
text = f"Ticket {TICKET} from {MAIL}, call {NANP}."
hits = us.findings(text, channel="tool")
result["typed"] = all(isinstance(m, Match) and text[m.start:m.end] == m.value for m in hits)
result["us_kinds"] = sorted({m.kind for m in hits})
result["us_types"] = sorted({m.type for m in hits})
result["generic_kinds"] = kinds(generic, text)

# reset: a rule added to the sources counts only after reset()
tenant.rules.append(user_rule("acme-order", "ACME_ORDER", r"ORD-[0-9]{5}"))
order = "ORD-" + "55120"
result["before_reset"] = "user:acme-order" in kinds(us, order)
us.reset()
result["after_reset"] = "user:acme-order" in kinds(us, order)

# many threads on one detector, and two detectors in threads at the same time
texts = [f"row {i}: {MAIL} {TICKET} {NANP}" if i % 3 == 0 else f"row {i}: nothing to see here, build {i}.{i % 7}"
         for i in range(300)]
serial = [kinds(us, t) for t in texts]
serial_generic = [kinds(generic, t) for t in texts]
out, out_generic, failures = {}, {}, []


def work(det, store, lo, hi):
    try:
        for i in range(lo, hi):
            store[i] = kinds(det, texts[i])
    except Exception as e:  # noqa: BLE001  the consumer wants to see any error of a thread
        failures.append(repr(e))


threads = [threading.Thread(target=work, args=(us if k % 2 == 0 else generic, out if k % 2 == 0 else out_generic,
                                               (k // 2) * 75, (k // 2) * 75 + 75)) for k in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join()
result["threads_equal_serial"] = (not failures and [out[i] for i in range(300)] == serial
                                  and [out_generic[i] for i in range(300)] == serial_generic)
result["thread_errors"] = failures

# a large input
big = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 18000) + f" {MAIL} " + ("tail text. " * 1000)
t0 = time.perf_counter()
big_hits = us.findings(big, channel="tool")
result["big_chars"] = len(big)
result["big_ms"] = round((time.perf_counter() - t0) * 1000)
result["big_found_mail"] = any(m.type == "EMAIL" for m in big_hits)

# wrong input
wrong = {}
for name, value in (("None", None), ("bytes", b"x"), ("int", 3)):
    try:
        us.findings(value, channel="tool")
        wrong[name] = "accepted"
    except Exception as e:  # noqa: BLE001
        wrong[name] = type(e).__name__
result["wrong_input"] = wrong

# memory over many requests: different texts each time, after a warm-up
for i in range(200):
    us.findings(f"warm {i} {MAIL}", channel="tool")
tracemalloc.start()
base = tracemalloc.get_traced_memory()[0]
for i in range(3000):
    us.findings(f"request {i}: user{i}@posteo.de sent ticket ACME-{100000 + i} at {i % 24}:00", channel="tool")
grown = tracemalloc.get_traced_memory()[0] - base
tracemalloc.stop()
result["growth_kb_3000_requests"] = round(grown / 1024)

result["plugin_modules"] = sorted(m for m in sys.modules if m.startswith("maisecrets")
                                  and not m.startswith("maisecrets.detection") and m != "maisecrets")
print(json.dumps(result, sort_keys=True))
