"""The filters of the vendored betterleaks rules (Expr expressions), read in Python.

betterleaks drops a finding when the rule's filter, or the global filter, is true. The filters are small programs in
the Expr language (github.com/expr-lang/expr). This module reads the subset that the vendored rules use: entropy,
tokenRatio, matchesAny, containsAny, len, comparisons, ||, && and !, over finding["secret"], finding["match"],
finding["line"] and attributes["path"]. Anything else (let bindings, slices, setConfidence) raises Unsupported, and the
loader leaves that rule out, so no rule runs without the filter its authors gave it.

tokenRatio needs the cl100k tokenizer, which the standard library does not have. betterleaks itself answers 0 when no
tokenizer is loaded (internal/exprruntime/bindings_filter.go, v1.9.0), and this module does the same: a filter
`entropy(s) < N || tokenRatio(s) >= M` then drops on the entropy alone.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from typing import Any, Callable

# equalsAnySha256 is not betterleaks: the directory version writes a matchesAny list of literal keys as their sha256,
# so it ships no key (scripts/build_release_tree.py, directory_betterleaks)
FILTER_FUNCTIONS = ("entropy", "tokenRatio", "matchesAny", "containsAny", "len", "equalsAnySha256")
_FIELDS = {("finding", "secret"): "secret", ("finding", "match"): "match", ("finding", "line"): "line",
           ("attributes", "path"): "path"}


class Unsupported(ValueError):
    """A filter form outside the subset this module reads."""


def entropy(s: str) -> float:
    """Shannon entropy over the bytes, as betterleaks computes it (bits per byte)."""
    b = s.encode("utf-8")
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in Counter(b).values())


def to_python_regex(rx: str) -> "re.Pattern[str]":
    """An RE2 pattern as Python reads it. RE2 applies an inline (?i) from its place to the end of the enclosing group;
    Python only knows it at the start or as a scoped group, so `a(?i)b` becomes `a(?i:b)`. Making the whole pattern
    case-insensitive would widen a filter that drops findings (^/Users/(?i)… in the global filter; codex review). A
    rest that holds an alternation of its group cannot be scoped faithfully and raises Unsupported. \\z is \\Z."""
    # RE2 reads \\w, \\d, \\s and \\b as ASCII; Python as Unicode. A filter drops findings, so the wider Python
    # reading would drop a value with an umlaut that betterleaks keeps (Opus review of the switch)
    return re.compile(_scope_inline_i(rx).replace(r"\z", r"\Z"), re.ASCII)


def _scope_inline_i(rx: str) -> str:
    while True:
        at = rx.find("(?i)")
        if at < 0:
            return rx
        if at == 0:
            return "(?i)" + rx[4:].replace("(?i)", "")
        depth, i, end = 0, at + 4, len(rx)
        while i < len(rx):
            c = rx[i]
            if c == "\\":
                i += 2
                continue
            if c == "[":                     # a class: its ( ) | are literal
                j = i + 1
                while j < len(rx) and rx[j] != "]":
                    j += 2 if rx[j] == "\\" else 1
                i = j + 1
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    end = i
                    break
                depth -= 1
            elif c == "|" and depth == 0:
                raise Unsupported("an inline (?i) before an alternation of its group")
            i += 1
        rx = rx[:at] + "(?i:" + rx[at + 4:end] + ")" + rx[end:]


_TOKEN_RE = re.compile(r"""\s*(?:
    (?P<num>\d+(?:\.\d+)?)
  | (?P<raw>`[^`]*`)
  | (?P<str>"(?:[^"\\]|\\.)*")
  | (?P<op>\|\||&&|<=|>=|==|!=|[<>!()\[\],.])
  | (?P<name>[A-Za-z_]\w*)
)""", re.X)


def _tokens(src: str) -> list[tuple[str, str]]:
    src = re.sub(r"(?m)^\s*//.*$", "", src).strip()
    out, pos = [], 0
    while pos < len(src):
        m = _TOKEN_RE.match(src, pos)
        if not m or m.end() == pos:
            if src[pos:].strip():
                raise Unsupported(f"token at {pos}")
            break
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, src: str):
        self.t = _tokens(src)
        self.i = 0

    def peek(self) -> tuple[str, str] | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, value: str | None = None) -> tuple[str, str]:
        tok = self.peek()
        if tok is None or (value is not None and tok[1] != value):
            raise Unsupported(f"expected {value!r} at token {self.i}")
        self.i += 1
        return tok

    def parse(self):
        node = self.or_()
        if self.peek() is not None:
            raise Unsupported(f"trailing token {self.peek()}")
        return node

    def or_(self):
        node = self.and_()
        while self.peek() == ("op", "||"):
            self.take()
            node = ("or", node, self.and_())
        return node

    def and_(self):
        node = self.not_()
        while self.peek() == ("op", "&&"):
            self.take()
            node = ("and", node, self.not_())
        return node

    def not_(self):
        return self.cmp()

    def cmp(self):
        node = self.unary()
        tok = self.peek()
        if tok and tok[0] == "op" and tok[1] in ("<", "<=", ">", ">=", "==", "!="):
            self.take()
            node = ("cmp", tok[1], node, self.unary())
        return node

    def unary(self):
        if self.peek() == ("op", "!"):           # Expr: unary ! binds tighter than a comparison
            self.take()
            return ("not", self.unary())
        return self.primary()

    def primary(self):
        tok = self.peek()
        if tok is None:
            raise Unsupported("unexpected end")
        kind, val = tok
        if kind == "num":
            self.take()
            return ("lit", float(val))
        if kind == "raw":
            self.take()
            return ("lit", val[1:-1])
        if kind == "str":
            self.take()
            try:
                return ("lit", json.loads(val))  # Expr escapes as JSON; unicode_escape broke non-ASCII text
            except ValueError:
                # an escape JSON does not know (\x41, \'): the text between the quotes as written. One odd filter
                # string must not raise for the whole ruleset, which would leave every rule out (Gate A of 0.6.15)
                return ("lit", val[1:-1])
        if val == "(":
            self.take()
            node = self.or_()
            self.take(")")
            return node
        if val == "[":
            self.take()
            items = []
            while self.peek() != ("op", "]"):
                items.append(self.or_())
                if self.peek() == ("op", ","):
                    self.take()
            self.take("]")
            return ("list", items)
        if kind == "name":
            self.take()
            if val in ("true", "false"):
                return ("lit", val == "true")
            if val in ("finding", "attributes"):
                self.take("[")
                key = self.take()
                self.take("]")
                field = _FIELDS.get((val, key[1].strip('"')))
                if key[0] != "str" or field is None:
                    raise Unsupported(f"field {val}[{key[1]}]")
                return ("field", field)
            if val == "filter" and self.peek() == ("op", "."):
                self.take()
                val = self.take()[1]
            if val in FILTER_FUNCTIONS and self.peek() == ("op", "("):
                self.take()
                args = []
                while self.peek() != ("op", ")"):
                    args.append(self.or_())
                    if self.peek() == ("op", ","):
                        self.take()
                self.take(")")
                return ("call", val, args)
            raise Unsupported(f"name {val}")
        raise Unsupported(f"token {tok}")


def _eval(node, env: dict) -> Any:
    op = node[0]
    if op == "lit":
        return node[1]
    if op == "field":
        return env.get(node[1], "")
    if op == "list":
        return [_eval(x, env) for x in node[1]]
    if op == "or":
        return bool(_eval(node[1], env)) or bool(_eval(node[2], env))
    if op == "and":
        return bool(_eval(node[1], env)) and bool(_eval(node[2], env))
    if op == "not":
        return not _eval(node[1], env)
    if op == "cmp":
        a, b = _eval(node[2], env), _eval(node[3], env)
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b, "==": a == b, "!=": a != b}[node[1]]
    if op == "call":
        args = [_eval(x, env) for x in node[2]]
        name = node[1]
        if name == "entropy":
            return entropy(args[0])
        if name == "tokenRatio":
            return 0.0                       # no tokenizer: what betterleaks answers without one
        if name == "len":
            return len(args[0])
        if name == "containsAny":
            return any(x in args[0] for x in args[1])
        if name == "matchesAny":
            return any(rx.search(args[0]) for rx in args[1].compiled())
        if name == "equalsAnySha256":
            return hashlib.sha256(args[0].encode("utf-8")).hexdigest() in args[1]
    raise Unsupported(f"node {op}")


class _Patterns:
    """The patterns of one matchesAny list, compiled on first use: a hook process loads every rule but evaluates the
    filters of the few rules that matched (2,400 patterns compiled at load cost about 20 ms per hook call)."""

    def __init__(self, patterns: list[str]):
        self.patterns = patterns
        self._compiled: list | None = None

    def compiled(self) -> list:
        if self._compiled is None:
            self._compiled = [to_python_regex(p) for p in self.patterns]
        return self._compiled


def _compile_regex_lists(node):
    """The pattern list of matchesAny compiled once, at load."""
    if node[0] == "call":
        args = [_compile_regex_lists(a) for a in node[2]]
        if node[1] == "matchesAny" and args[1][0] == "list":
            pats = []
            for item in args[1][1]:
                if item[0] != "lit" or not isinstance(item[1], str):
                    raise Unsupported("matchesAny pattern")
                _scope_inline_i(item[1])         # an alternation after (?i) raises here, at load
                pats.append(item[1])
            args[1] = ("lit", _Patterns(pats))
        return ("call", node[1], args)
    if node[0] in ("or", "and"):
        return (node[0], _compile_regex_lists(node[1]), _compile_regex_lists(node[2]))
    if node[0] == "not":
        return ("not", _compile_regex_lists(node[1]))
    if node[0] == "cmp":
        return ("cmp", node[1], _compile_regex_lists(node[2]), _compile_regex_lists(node[3]))
    if node[0] == "list":
        return ("list", [_compile_regex_lists(x) for x in node[1]])
    return node


def compile_filter(src: str) -> Callable[[dict], bool]:
    """A predicate over {secret, match, line, path}: True drops the finding. Raises Unsupported for a form outside
    the subset."""
    node = _compile_regex_lists(_Parser(src).parse())

    def drop(env: dict) -> bool:
        return bool(_eval(node, env))
    return drop
