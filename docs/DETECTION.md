# The detection core

`maisecrets/detection/` is the detector: it finds secrets and personal data in text. It holds no plugin, no home
folder and no reference form of its own. The plugin gives those to it; a library caller can give its own.

## Use it as a library

`pyproject.toml` builds the core as a wheel. It holds `maisecrets/__init__.py` and `maisecrets/detection/` with its
rule data, and no module of the plugin. It needs no other package and runs on Python 3.9 and later. It is not on PyPI:

```bash
python3 -m pip wheel --no-deps -w dist .        # dist/maisecrets-<version>-py3-none-any.whl
python3 -m pip install dist/maisecrets-*.whl
```

The version is the plugin's version (`.claude-plugin/plugin.json`); a wheel from `main` or a tag has the released
one. `importlib.metadata.version("maisecrets")` gives it. Without the plugin modules, each argument left `None` takes
no config, no sources and no reference form: a detector from the wheel never reads the home folder.

```python
from maisecrets.detection import Active, Detector, Host, NO_REFERENCES, NO_SOURCES

d = Detector(
    regions=Active(regions=("generic", "de"), languages=("en", "de"), source="mine"),
    sources=NO_SOURCES,          # rules of your own, allow list, term lists, imported values: a Sources object
    references=NO_REFERENCES,    # how the caller writes a reference into text: a References object
    host=Host(user="me", year=2026),
)
for m in d.findings(text, channel="tool", path="notes.txt"):
    print(m.kind, m.type, m.start, m.end)
```

- **Each argument left `None`** takes the plugin's default when the plugin is there: the config of this computer,
  the readers of the home folder (`maisecrets/sources.py`), the placeholder form (`maisecrets/placeholder.py`), and
  this computer's user name and year.
- **A detector with all four given** reads nothing of the host and imports no module of the plugin
  (`tests/test_detection_package.py` shows this in a fresh process).
- **Two detectors in one process** keep their own rule lists, allow lists and caches, also in two threads and one
  inside a scan of the other (`tests/test_detector.py`).
- **A function given as `regions`** is asked when the rules load: the first scan and each `reset()`. A changed config
  takes effect at `reset()`. `regions()` names the regions that the rule list was loaded for.
- **`with d.activate():`** makes every function of the module in this thread use `d`, for a caller (such as a hook)
  that calls `maisecrets.detect.scan` directly.

## The API

`maisecrets.detection.__all__`:

| Name | What |
|---|---|
| `Detector` | A detector with its own configuration: `scan`, `findings`, `rules`, `allow_list`, `explain_allowed`, `regions`, `reset`, `slowest_user_rule`, `activate` |
| `Match` | One hit: `kind` (the rule id), `type`, `value`, `start`, `end` |
| `Sources`, `NO_SOURCES` | What a scan takes besides the built-in rules |
| `References`, `NO_REFERENCES` | The reference form of the caller |
| `Host`, `THIS_COMPUTER` | What a scan reads of its computer |
| `Active`, `resolve_regions` | The regions and label languages, and their resolution from a config (`locale=` to give the locale) |
| `user_rule` | A rule of your own, for `Sources.user_rules` (returns a `Rule`; `LazyRegex` is deprecated) |

The rule tables and the helpers of `core.py` are no API: they change with the rules.

## The API: the decision of 2026-10-20

The wheel (`pyproject.toml`) makes the core usable without the plugin, so its names carry a promise. Decided by the
maintainer on 2026-10-20 (merge request !160):

| Name | Promise |
|---|---|
| `Detector`, `Match` (`kind`, `type`, `value`, `start`, `end`), `Sources`, `NO_SOURCES`, `References`, `NO_REFERENCES`, `Host`, `THIS_COMPUTER`, `Active`, `resolve_regions` | **stable** |
| `user_rule(id, type, pattern, keywords=(), secret_group=0)` | **stable**: the one way for a caller to make a rule of its own. The id becomes `user:<id>`; a wrong argument raises `ValueError` |
| `Rule` | **no stable constructor**: the type that `user_rule` returns and `Detector.rules()` lists. Of its fields only `id`, `type`, `keywords` and `secret_group` are promised; the other 17 belong to the detector |
| `LazyRegex` | **deprecated**: a `DeprecationWarning` on access; importable until 0.8 at least |
| `maisecrets.detect` and the other old names | **not API**: plugin modules, not in the wheel |
| The hits themselves | **not API**: a patch version may find more or fewer values; `docs/BENCHMARKS.md` and `scripts/compare_bench.py` report how |

**Changes to a stable name go through a deprecation, also before 1.0:** the old form keeps working with a
`DeprecationWarning` for at least one minor version, the changelog says so under "API", and only then it goes. A
1.0 of the wheel would freeze the stable names. `region` and `channel` for `user_rule` come only when they are meant
to be carried as API.

**Checks that hold it:** `tests/test_detection_package.py` pins `__all__`, the parameters of `user_rule`, the stable
`Match` fields, a rule of your own found through a `Detector`, the `ValueError` of a wrong argument and the warning of
`LazyRegex`. `scripts/wheel_smoke.py` makes a rule of its own through `user_rule` in a fresh venv.

## The old names

`maisecrets.detect` and `maisecrets.checksums`, `lazy_regex`, `normalise`, `regions`, `registry`, `rulespec`,
`rule_filter` and `personal` stay. Each is the same module object as its module in `maisecrets/detection/`, so an
import or a patch through an old name reaches the core itself. The plugin and its tests use them.
`detect.scan()`, `detect.findings()` and the other functions use the default detector, which `use_regions`,
`use_sources` and `use_references` configure.

## The boundary tests

| Test | It holds |
|---|---|
| `tests/test_detection_boundary.py` | No module outside the core uses a private name of the core, by any of its names. A plain scan imports only the plugin modules on a list that may only get shorter. |
| `tests/test_scan_context.py` | A scan writes no new module state; the state left is the per-thread text index and caches that depend on no configuration. |
| `tests/test_detector.py` | Two detectors, their caches, their threads and the snapshot of a rule load. |
| `tests/test_detector_host.py` | An explicit host reads neither the user name nor the clock; an explicit detector gives one result on two hosts. |
| `tests/test_detection_package.py` | The API, the old names, the rule data, and a library caller that imports nothing of the plugin. |

`scripts/detection_fingerprint.py` records the hits of 27,337 inputs. A change that moves the code and not the rules
leaves the fingerprint byte-identical.
