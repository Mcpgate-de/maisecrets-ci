"""Every test module imports this first: the vault home is a temp directory this module made.

The modules used `os.environ.setdefault("MAISECRETS_HOME", tmp)`, so a MAISECRETS_HOME set on the
machine won, and the reset helpers then deleted the index, the store and the logs in it (Codex
review of the suite, 2026-09-27). This module makes one temp home per test process, reuses it only
when it made it itself, and refuses a home that is the real ~/.maisecrets.

It also removes the environment of the client that started the tests, for this process and every
child it starts. The code reads that environment: `client_of` takes a payload without `prompt_id`
or `turn_id` for Codex when any CODEX_ variable is set, the session start reads CLAUDECODE and
CODEX_HOME, the run log reads CLAUDE_CODE_ENTRYPOINT, and CLAUDE_PLUGIN_OPTION_BACKEND overrides
the store in config.json. Inside a Codex session 28 tests failed and 5 errored, and a Claude Code
session with a plugin option could send the tests to the keychain (Codex review, 2026-09-27). A
test that needs one of these variables sets it itself, with mock.patch.dict.

The temp dir of the process is a temp directory of its own too (tempfile.tempdir and TMPDIR), with
no XDG_RUNTIME_DIR: the value FIFOs live in <tempdir>/maisecrets-<uid>, and the installed plugin on
this machine uses the real one. test_gates.py set this at its import, so only the modules imported
after it had it (Codex review, 2026-09-27); here every module has it, in any order.
"""
import os
import sys
import tempfile

_MINE = "MAISECRETS_TEST_HOME_OWNED"
_MINE_TMP = "MAISECRETS_TEST_TMP_OWNED"

# the client environment the code reads (see above); prefixes and names
CLIENT_PREFIXES = ("CODEX_", "CLAUDE_CODE_", "CLAUDE_PLUGIN_OPTION_")
CLIENT_NAMES = ("CLAUDECODE", "XDG_RUNTIME_DIR", "MAISECRETS_KEY_FILE", "MAISECRETS_DEBUG_LOG")


def client_variables(environ=os.environ) -> list[str]:
    """The names in ``environ`` that would change what the code under test does."""
    return sorted(k for k in environ if k.startswith(CLIENT_PREFIXES) or k in CLIENT_NAMES)


REMOVED = client_variables()
for _name in REMOVED:
    del os.environ[_name]
# the guard puts the resume command on the clipboard: never the real one of the person running the tests
os.environ["MAISECRETS_GUARD_CLIPBOARD"] = "off"

# the system setting decides the label languages and the "auto" region; the tests pin it, so a run
# on a German Mac and one in a C-locale container expect the same rules. A test of the lookup
# itself sets or removes MAISECRETS_LOCALE with mock.patch.dict.
os.environ["MAISECRETS_LOCALE"] = "de_DE"
# the fake clipboard tools are shell scripts; under a loaded run they took longer than the 3 s of a real one
os.environ["MAISECRETS_CLIPBOARD_TIMEOUT"] = "30"

if not os.environ.get(_MINE) or os.environ.get(_MINE) != os.environ.get("MAISECRETS_HOME"):
    home = tempfile.mkdtemp(prefix="maisecrets-test-home-")
    os.environ["MAISECRETS_HOME"] = home
    os.environ[_MINE] = home

# a runner that imported maisecrets.home before this module (detect.rules() loads the config through it) bound HOME
# to the real home, and the resets of the suite deleted the real index, vault file and key (a fork's runner,
# 2026-10-12, then through the vault). The vault takes HOME from maisecrets.home, so both are checked
for _name in ("maisecrets.home", "maisecrets.vault"):
    _mod = sys.modules.get(_name)
    if _mod is not None and os.path.realpath(str(getattr(_mod, "HOME", ""))) != os.path.realpath(
            os.environ["MAISECRETS_HOME"]):
        # the marker stays: the vault then refuses the user's home in the modules that run after this one anyway
        raise RuntimeError(f"{_name} was imported with the home {_mod.HOME}; tests/_isolate must be imported "
                           "first (before anything that imports maisecrets), or the tests reach the real store")

if not os.environ.get(_MINE_TMP) or os.environ.get(_MINE_TMP) != os.environ.get("TMPDIR"):
    tmp = tempfile.mkdtemp(prefix="maisecrets-test-tmp-")
    os.environ["TMPDIR"] = tmp
    os.environ[_MINE_TMP] = tmp
TMP = os.environ["TMPDIR"]
tempfile.tempdir = TMP
# a shortcut test that forgets its own CLAUDE_CONFIG_DIR writes here, never into ~/.claude
os.environ["CLAUDE_CONFIG_DIR"] = os.path.join(TMP, "claude-config")

# tripwires first on PATH, for this process and every child: a test that forgot to replace the
# clipboard, the browser or the store reaches a script that notes the call and fails, not the
# real tool. `_hygiene.state_problems` reports the note. The native store tools stay reachable
# where the native backend test runs on purpose (CI, MAISECRETS_NATIVE_BACKEND_TEST=1).
TRIPWIRE = os.path.join(TMP, "tripwire")
TRIPWIRE_BIN = os.path.join(TMP, "tripwire-bin")
if os.name != "nt":
    _tools = ["pbcopy", "pbpaste", "xclip", "open", "xdg-open"]
    if not (os.environ.get("CI") or os.environ.get("MAISECRETS_NATIVE_BACKEND_TEST") == "1"):
        _tools += ["security", "powershell"]
    os.makedirs(TRIPWIRE_BIN, exist_ok=True)
    for _tool in _tools:
        _path = os.path.join(TRIPWIRE_BIN, _tool)
        with open(_path, "w", encoding="utf-8") as _f:
            _f.write(f'#!/bin/sh\necho "{_tool} $*" >> "{TRIPWIRE}"\nexit 1\n')
        os.chmod(_path, 0o755)
    if not os.environ.get("PATH", "").startswith(TRIPWIRE_BIN + os.pathsep):
        os.environ["PATH"] = TRIPWIRE_BIN + os.pathsep + os.environ.get("PATH", "")

# Windows looks for clip.exe and powershell.exe in System32 before PATH, so the tripwires above
# cannot work there. A sitecustomize on PYTHONPATH installs tests/_platform_fakes.py in every Python
# child, and this process installs it too. It runs on every platform, so the mechanism is tested
# where the tests are written.
SITE = os.path.join(TMP, "site")
os.makedirs(SITE, exist_ok=True)
with open(os.path.join(SITE, "sitecustomize.py"), "w", encoding="utf-8") as _f:
    _f.write("import sys\n"
             f"sys.path.insert(0, {os.path.dirname(os.path.abspath(__file__))!r})\n"
             "import _platform_fakes\n"
             "_platform_fakes.install()\n"
             "del sys.path[0]\n"
             # only the first sitecustomize on the path runs, so this one runs the next one too:
             # Homebrew's Python adds its site-packages in its own sitecustomize, and a child
             # without it lost every installed package (coverage among them, 2026-09-27)
             "import os\n"
             "_here = os.path.dirname(os.path.abspath(__file__))\n"
             "for _d in list(sys.path):\n"
             "    _f = os.path.join(_d, 'sitecustomize.py')\n"
             "    if os.path.abspath(_d) != _here and os.path.isfile(_f):\n"
             "        with open(_f, encoding='utf-8') as _src:\n"
             "            exec(compile(_src.read(), _f, 'exec'), {'__file__': _f, '__name__': 'sitecustomize'})\n"
             "        break\n"
             "if os.environ.get('COVERAGE_PROCESS_START'):\n"
             "    try:\n"
             "        import coverage\n"
             "        coverage.process_startup()\n"
             "    except ImportError:\n"
             "        pass\n")
if SITE not in os.environ.get("PYTHONPATH", "").split(os.pathsep):
    os.environ["PYTHONPATH"] = os.pathsep.join(p for p in (SITE, os.environ.get("PYTHONPATH", "")) if p)
import _platform_fakes  # noqa: E402
_platform_fakes.install()

HOME = os.environ["MAISECRETS_HOME"]
_REAL = os.path.realpath(os.path.expanduser("~/.maisecrets"))
if os.path.realpath(HOME) == _REAL or os.path.realpath(HOME).startswith(_REAL + os.sep):
    raise SystemExit(f"refusing to run tests against the real vault home {HOME}")
