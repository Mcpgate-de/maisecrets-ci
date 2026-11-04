"""CPU time of findings_by_leaf on the slack shapes for one checkout (gateway config), median of 7, one JSON line.
    python3 bench/slack_speed.py CHECKOUT (bench/slack_speed_ab.sh runs two checkouts in turns)"""
import json
import os
import random
import statistics
import sys
import tempfile
import time

home = tempfile.mkdtemp(prefix="ms-ab-")
with open(os.path.join(home, "config.json"), "w") as f:
    json.dump({"backend": "jsonfile", "allow_plaintext_store": True}, f)
os.environ["MAISECRETS" + "_HOME"] = home
sys.path.insert(0, sys.argv[1])
from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host, leaves  # noqa: E402
from maisecrets.detection.regions import resolve  # noqa: E402

full = resolve({"regions": ["de"]}, locale="en")
DET = Detector(regions=Active(regions=full.regions, languages=full.languages, source="gateway"), sources=NO_SOURCES,
               references=NO_REFERENCES, host=Host(user="", year=2026))
WORDS = ("deploy build finished log merge review pipeline green failed retry staging release ticket fixed thanks "
         "customer issue branch please check the team today tomorrow meeting notes update version rollout").split()


def prod(seed, n):
    rng = random.Random(seed)
    msgs = []
    for i in range(n):
        segs, parts = [], []
        for _ in range(rng.randint(4, 9)):
            k = rng.random()
            if k < 0.55:
                t = " ".join(rng.choice(WORDS) for _ in range(rng.randint(2, 9)))
                segs.append({"type": "text", "text": t})
                parts.append(t)
            elif k < 0.75:
                u = f"U0{rng.randrange(16 ** 8):08X}"
                segs.append({"type": "user", "user_id": u})
                parts.append(f"<@{u}>")
            elif k < 0.9:
                url = f"https://gitlab.example.com/g/p/-/merge_requests/{rng.randrange(9999)}"
                segs.append({"type": "link", "url": url, "text": f"!{rng.randrange(9999)}"})
                parts.append(f"<{url}|!1>")
            else:
                e = rng.choice(("rocket", "eyes", "tada"))
                segs.append({"type": "emoji", "name": e})
                parts.append(f":{e}:")
        if rng.random() < 0.1:
            parts.append(rng.choice(("build &amp; deploy", "if a &lt; b then")))
        msgs.append({"type": "message", "ts": f"17305{i:05d}.{i:06d}", "user": f"U0{rng.randrange(16 ** 8):08X}",
                     "text": " ".join(parts), "team": "T0ABCDEF12", "client_msg_id": f"{rng.getrandbits(128):032x}",
                     "user_profile": {"avatar_hash": f"{rng.getrandbits(48):012x}", "real_name": "Dev Team",
                                      "display_name": f"dev.{rng.choice(WORDS)}", "team": "T0ABCDEF12"},
                     "reactions": [{"name": "eyes", "count": 2, "users": [f"U0{rng.randrange(16 ** 8):08X}"]}],
                     "blocks": [{"type": "rich_text", "block_id": f"b{i:04d}",
                                 "elements": [{"type": "rich_text_section", "elements": segs}]}]})
    return {"ok": True, "messages": msgs}


def prose(seed, n):
    rng = random.Random(seed)
    msgs = []
    for i in range(n):
        t = " ".join(rng.choice(WORDS) for _ in range(50))
        msgs.append({"type": "message", "ts": f"1730{i}", "user": f"U0{rng.randrange(16 ** 8):08X}", "text": t,
                     "blocks": [{"type": "rich_text", "elements": [{"type": "text", "text": t}]}]})
    return {"ok": True, "messages": msgs}


out = {}
for name, obj in (("slack_prod_45", prod(7, 45)), ("slack_prose_90", prose(7, 90))):
    leaves.findings_by_leaf(DET, obj)
    xs = []
    for _ in range(7):
        t0 = time.process_time()
        leaves.findings_by_leaf(DET, obj)
        xs.append(time.process_time() - t0)
    chars = sum(len(x.value) for x in leaves.json_text(obj)[1])
    out[name] = round(statistics.median(xs) * 1e6 / chars, 3)        # microseconds per character
print(json.dumps(out))
