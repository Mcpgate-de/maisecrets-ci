"""/maisecrets:ner at a glance: one head line (the source and its answer state), one short line per check in the marks
and the arrow column of /maisecrets:status (status_verdict.py), and the details under `/maisecrets:ner all`.

The checks per source: local (service, image, load), url (reachable), gateway (login, quota), and for each of them
the source and today's count from ner.log. off is one line and how to turn it on. The exit codes are those of
ner_setup.report, which commands/ner.md reads: 3 (the local service needs a start), 4 (the gateway needs a login with
the name scope).
"""
from __future__ import annotations

from urllib.parse import urlsplit

from . import ner_setup
from .status_verdict import MARK, NAME_COL, Check

FACT_MAX = 38            # the arrow column of warn and FAIL lines stands after the longest such fact, up to this
# today's texts with the rules alone are a warn from this share of all texts on, and only from this count on: a few
# long command outputs are normal, a fifth of all texts is the service missing much of the work
RULES_SHARE = 0.2
RULES_MIN = 10
_WHY = {"too_long": "too long", "timeout": "too slow", "older version": "older version"}


def _cmd(text: str, client) -> str:
    """A command as the person types it: in Codex `maisecrets: ner all` for `/maisecrets:ner all`."""
    return text.replace("/maisecrets:", "maisecrets: ") if client == "codex" else text


def _host(url: str) -> str:
    try:
        parts = urlsplit(url)
        return parts.netloc or url
    except ValueError:
        return url


def _kind(conf: dict) -> str:
    """The form of the setting: gateway, local (the service of run.sh ner start) or url."""
    if conf.get("gateway"):
        return "gateway"
    return "local" if str(conf.get("url") or "").rstrip("/") == ner_setup.LOCAL_URL.rstrip("/") else "url"


def _source_fact(conf: dict) -> str:
    """The source and what it reads, short."""
    # a set source reads prompts too; "prompts": false is left only by a machine policy (home.load_config)
    fact = f"{_kind(conf)} (" + ("tool results; prompts: policy" if conf.get("prompts") is False
                                 else "tool results and prompts") + ")"
    fb = conf.get("fallback") if isinstance(conf.get("fallback"), dict) else {}
    if fb.get("url"):
        fact += f"; fallback {_host(str(fb['url']))}"
    return fact


def today_check(now: float | None = None) -> Check:
    """Today's requests from ner.log: a warn when the rules alone took a notable share (RULES_SHARE, RULES_MIN)."""
    c = ner_setup.today_counts(now)
    total = sum(c.get(k, 0) for k in ("local", "url", "gateway", "fallback", "rules"))
    if not total:
        return Check("n/a", "today", "no text yet", None, None)
    rules = c.get("rules", 0)
    whys = sorted(((v, k[4:]) for k, v in c.items() if k.startswith("why:")), reverse=True)
    top = f" ({whys[0][0]} {_WHY.get(whys[0][1], whys[0][1])})" if whys and rules else ""
    if rules >= RULES_MIN and rules >= RULES_SHARE * total:
        return Check("warn", "today", f"{rules} of {total} texts rules alone{top}", "/maisecrets:ner all", None)
    fact = f"{total - rules} of {total} texts checked by the service"
    return Check("ok", "today", fact + (f", {rules} rules alone" if rules else ""), None, None)


def _local_checks(f: dict, code: int) -> list:
    tool = f.get("tool") or "docker"
    again = f"{tool} rm -f ner, then /maisecrets:ner"
    if not f.get("answers"):
        probe = str(f.get("probe") or "")
        if code == 3:
            return [Check("FAIL", "service", "not running", f"run.sh ner start ({tool})", None)]
        if "not asked" in probe:
            return [Check("FAIL", "service", probe.split("not asked; ", 1)[-1][:FACT_MAX] or "not asked",
                          "/maisecrets:ner all", None)]
        return [Check("FAIL", "service", "not running, no docker or podman", "install one, or /maisecrets:ner off",
                      None)]
    proof = f.get("proof")
    checks = [{
        "ok": Check("ok", "service", "answers, proves its secret", None, None),
        "unchecked": Check("warn", "service", "answers, not set up by maisecrets", again, None),
        "lost": Check("FAIL", "service", "its secret cannot be read", again, None),
        "old": Check("FAIL", "service", "image too old for a secret", again, None),
        "impostor": Check("FAIL", "service", "not the maisecrets container", "stop it, then /maisecrets:ner", None),
    }.get(proof, Check("ok", "service", "answers", None, None))]
    if proof not in (None, "ok", "unchecked"):
        return checks
    kind, have, pinned = f.get("image") or ("", "", "")
    checks.append({
        "": Check("n/a", "image", "no container to check", None, None),
        "pinned": Check("ok", "image", f"{pinned}, the pinned one", None, None),
        "newer": Check("ok", "image", f"{have}, newer than the pin", None, None),
        "not_ours": Check("warn", "image", f"{have}, not updated", again, None),
        "updates_off": Check("warn", "image", f"{have}, updates off", "/maisecrets:ner updates on", None),
        "failed": Check("warn", "image", f"{have}, the update failed", "maisecrets tries again in a day", None),
        "behind": Check("warn", "image", f"{have}, behind the pin", "a new session updates it", None),
    }[kind])
    checks.append(_load_check(str(f.get("load") or "")))
    return checks


def _load_check(line: str) -> Check:
    text = line[len("load: "):] if line.startswith("load: ") else line
    if not text or text.startswith("no load data"):
        return Check("n/a", "load", "no load data", None, None)
    saturated = " (saturated" in text
    short = ", ".join(text.split(" (saturated")[0].split(", ")[:2])
    if saturated:
        return Check("warn", "load", short + ", saturated", "/maisecrets:ner all", None)
    return Check("ok", "load", short, None, None)


def _url_checks(f: dict) -> list:
    probe = str(f.get("probe") or "")
    if f.get("answers"):
        ms = probe.split("answers (", 1)[-1].split(")", 1)[0] if "answers (" in probe else ""
        return [Check("ok", "reachable", f"answers ({ms})" if ms else "answers", None, None)]
    fact = probe.replace("the service: ", "", 1) or "does not answer"
    return [Check("FAIL", "reachable", fact[:FACT_MAX], "check the address with its team", None)]


def _gateway_checks(f: dict, client) -> list:
    login = f.get("login")
    if login in ("scope", "none"):
        name = f.get("server") or ""
        fact = "lacks the name scope" if login == "scope" else "no login"
        return [Check("FAIL", "login", fact, _cmd("/maisecrets:sref login" + (" " + name if name else ""), client),
                      None)]
    if login != "ok":
        return [Check("FAIL", "gateway", str(f.get("why") or "not asked")[:FACT_MAX], "/maisecrets:ner all", None)]
    checks = [Check("ok", "login", "has the name scope", None, None)]
    doc = f.get("status") if isinstance(f.get("status"), dict) else {}
    q = doc.get("quota") if isinstance(doc.get("quota"), dict) else {}
    from .ner_gateway import _int
    left, per = _int(q.get("requests_left")), _int(q.get("requests_per_minute"))
    path = doc.get("client_path") if isinstance(doc.get("client_path"), dict) else {}
    if path.get("free") is False:
        checks.append(Check("warn", "quota", "the client slot is busy now", "try again in a minute", None))
    elif left is not None and per:
        fact = f"{left} of {per} requests this minute"
        checks.append(Check("warn", "quota", fact, "wait a minute", None) if left * 10 < per
                      else Check("ok", "quota", fact, None, None))
    else:
        checks.append(Check("n/a", "quota", "no quota data", None, None))
    if not f.get("answers"):
        checks.append(Check("FAIL", "gateway", f"no result ({f.get('why') or '?'})"[:FACT_MAX], "/maisecrets:ner all",
                            None))
    return checks


def _head(conf: dict, f: dict, code: int) -> str:
    url = str(conf.get("url") or "")
    if conf.get("gateway"):
        where = f"gateway {_host(str(conf['gateway']))}"
        if f.get("answers"):
            state = f"answers ({f.get('ms', 0):.0f} ms) with your login"
        elif code == 4:
            state = "needs a login with the name scope"
        else:
            state = "gives no result"
    else:
        where = f"{_kind(conf)} {_host(url)}"
        probe = str(f.get("probe") or "")
        if f.get("answers") and f.get("proof") in (None, "ok", "unchecked"):
            ms = probe.split("answers (", 1)[-1].split(")", 1)[0] if "answers (" in probe else ""
            state = f"answers ({ms})" if ms else "answers"
        elif f.get("answers"):
            state = "gets no text"
        else:
            state = "does not answer"
    return f"names: {where} · {state}"


def check_lines(checks: list, client=None) -> list:
    """One line per check, the marks and names of /maisecrets:status; the arrows of warn and FAIL in one column."""
    flagged = [len(c.fact) for c in checks if c.next and c.state in ("warn", "FAIL")]
    col = min(max(flagged), FACT_MAX) if flagged else 0
    out = []
    for c in checks:
        line = f" {MARK.get(c.state, '?')} {c.name:<{NAME_COL}} {c.fact}"
        if c.next and c.state in ("warn", "FAIL"):
            line = f" {MARK.get(c.state, '?')} {c.name:<{NAME_COL}} {c.fact:<{col}}  →  {_cmd(c.next, client)}"
        out.append(line)
    return out


# the lines of the details that the checks above already state
_SAID = ("start: ", "login: ", "Until it answers, ")


def render(conf, wait: float = 0.0, show_all: bool = False, client=None) -> tuple:
    """(exit code, lines) of /maisecrets:ner, and with show_all the details of /maisecrets:ner all."""
    facts: dict = {}
    code, details = ner_setup.report(conf, wait, facts)
    every = "/maisecrets:ner all"
    if not (isinstance(conf, dict) and conf.get("url")):
        lines = ["names: off (the rules alone)",
                 _cmd("to turn it on: /maisecrets:ner local, url URL or gateway URL", client)]
        if show_all:
            lines += ["", "Details", ner_setup.counts_line()]
        return code, lines
    if conf.get("gateway"):
        checks = _gateway_checks(facts, client)
    elif facts.get("local"):
        checks = _local_checks(facts, code)
    else:
        checks = _url_checks(facts)
    checks = [Check("ok", "source", _source_fact(conf), None, None)] + checks + [today_check()]
    lines = [_head(conf, facts, code), ""] + check_lines(checks, client)
    if show_all:
        lines += ["", "Details"] + [x for x in details if not x.startswith(_SAID)]
    else:
        lines += ["", "all details: " + _cmd(every, client)]
    return code, lines
