"""A fake macOS `security` for tests/test_keychain_process.py: it runs as a real program first on PATH.

It records the argv and the stdin of each call in calls.jsonl, and keeps its items in items.json, both in
$FAKE_SECURITY_DIR. Like the real one, `-i` reads at most 4096 bytes per line and runs the rest as another
command, and `find-generic-password -w` prints a non-ASCII password as hex. FAKE_SECURITY_SLEEP ("NAME:SECONDS")
makes the command NAME wait first, as a keychain that waits for an unlock dialog does. It never calls the real tool.

`-i` exits 0 also when its command failed (the real tool may; Gate A of #75), unless FAKE_SECURITY_I_RC is set.
FAKE_SECURITY_FAIL_ADD (a regex) makes each add of a matching account fail without a write; FAKE_SECURITY_FIND_FAIL
("REGEX:RC") makes each find of a matching account fail with RC. FAKE_SECURITY_FIND_ONCE ("REGEX:RC:N") makes only the
N-th find of a matching account fail with RC, or wait 30 s when RC is "hang" (a keychain that stops answering).
FAKE_SECURITY_DELETE_FAIL ("REGEX:RC") makes each delete of a matching account fail with RC.
FAKE_SECURITY_DUMP_RC makes `dump-keychain` fail with that rc.
"""
import hashlib
import json
import os
import re
import sys
import time

LINE_LIMIT = 4096
DIR = os.environ["FAKE_SECURITY_DIR"]
ITEMS = os.path.join(DIR, "items.json")


def tokenize(line):
    """The `security -i` command reader: double quotes group, a backslash escapes inside them."""
    out, cur, quoted, i = [], None, False, 0
    while i < len(line):
        c = line[i]
        if quoted:
            if c == "\\" and i + 1 < len(line):
                cur += line[i + 1]
                i += 2
                continue
            if c == '"':
                quoted = False
            else:
                cur += c
        elif c == '"':
            quoted, cur = True, cur or ""
        elif c.isspace():
            if cur is not None:
                out.append(cur)
                cur = None
        else:
            cur = (cur or "") + c
        i += 1
    if quoted:
        raise ValueError("unterminated quote")
    if cur is not None:
        out.append(cur)
    return out


def load():
    try:
        with open(ITEMS, encoding="utf-8") as f:
            return json.load(f)
    except OSError:
        return {}


def save(items):
    with open(ITEMS, "w", encoding="utf-8") as f:
        json.dump(items, f)


def opts_of(argv):
    opts, i = {}, 0
    while i < len(argv):
        if argv[i] in ("-U", "-w") and (argv[i] == "-U" or i + 1 == len(argv) or argv[i + 1].startswith("-")):
            opts[argv[i]] = True
            i += 1
        else:
            opts[argv[i]] = argv[i + 1] if i + 1 < len(argv) else ""
            i += 2
    return opts


def slow(name):
    spec = os.environ.get("FAKE_SECURITY_SLEEP", "")
    if spec.partition(":")[0] == name:
        time.sleep(float(spec.partition(":")[2]))


def find_once(account):
    """The rc of a one-shot failed find (FAKE_SECURITY_FIND_ONCE), or None. The count of matching finds is kept per
    setting in $FAKE_SECURITY_DIR."""
    spec = os.environ.get("FAKE_SECURITY_FIND_ONCE", "")
    if not spec:
        return None
    rx, rc, n = spec.rsplit(":", 2)
    if not re.search(rx, account):
        return None
    count = os.path.join(DIR, "find-once." + hashlib.sha256(spec.encode()).hexdigest()[:12])
    try:
        with open(count, encoding="utf-8") as f:
            seen = int(f.read() or 0) + 1
    except OSError:
        seen = 1
    with open(count, "w", encoding="utf-8") as f:
        f.write(str(seen))
    if seen != int(n):
        return None
    if rc == "hang":
        time.sleep(30)
        return 0
    return int(rc)


def run(argv):
    name, opts = argv[0], opts_of(argv[1:])
    slow(name)
    items = load()
    if name == "add-generic-password":
        if opts.get("-w") is True:
            return 1, ""        # the prompt form: this fake has no terminal
        k = opts["-s"] + "\0" + opts["-a"]
        fail = os.environ.get("FAKE_SECURITY_FAIL_ADD")
        if fail and re.search(fail, opts["-a"]):
            return 25, ""
        if k in items and "-U" not in opts:
            return 45, ""
        items[k] = opts["-w"]
        save(items)
        return 0, ""
    if name == "find-generic-password":
        fail, _, rc = os.environ.get("FAKE_SECURITY_FIND_FAIL", "").rpartition(":")
        if fail and re.search(fail, opts["-a"]):
            return int(rc), ""
        once = find_once(opts["-a"])
        if once is not None:
            return once, ""
        pw = items.get(opts["-s"] + "\0" + opts["-a"])
        if pw is None:
            return 44, ""
        return 0, (pw if pw.isascii() else pw.encode("utf-8").hex()) + "\n"
    if name == "delete-generic-password":
        fail, _, rc = os.environ.get("FAKE_SECURITY_DELETE_FAIL", "").rpartition(":")
        if fail and "-a" in opts and re.search(fail, opts["-a"]):
            return int(rc), ""
        for k in list(items):
            s, _, a = k.partition("\0")
            if s == opts["-s"] and ("-a" not in opts or a == opts["-a"]):
                del items[k]
                save(items)
                return 0, ""
        return 44, ""
    if name == "dump-keychain":
        if os.environ.get("FAKE_SECURITY_DUMP_RC"):
            return int(os.environ["FAKE_SECURITY_DUMP_RC"]), ""
        out = []
        for k in items:
            s, _, a = k.partition("\0")
            out += ['keychain: "/Users/x/Library/Keychains/login.keychain-db"', 'class: "genp"', "attributes:",
                    f'    "acct"<blob>="{a}"', f'    "svce"<blob>="{s}"']
        return 0, "\n".join(out) + "\n"
    return 2, ""


def main():
    args = sys.argv[1:]
    data = sys.stdin.buffer.read() if args == ["-i"] else b""
    with open(os.path.join(DIR, "calls.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps({"argv": args, "stdin": data.decode("utf-8", "replace")}) + "\n")
    if args == ["-i"]:
        rc = 0
        for line in data.split(b"\n"):
            for i in range(0, len(line), LINE_LIMIT):
                try:
                    argv = tokenize(line[i:i + LINE_LIMIT].decode("utf-8", "replace"))
                except ValueError:
                    rc = 1
                    continue
                if argv:
                    r, _out = run(argv)
                    rc = rc or r
        return rc if os.environ.get("FAKE_SECURITY_I_RC") else 0
    rc, out = run(args)
    sys.stdout.write(out)
    return rc


if __name__ == "__main__":
    sys.exit(main())
