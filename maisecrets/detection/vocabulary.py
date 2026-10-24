"""The published type vocabulary: every type a Match can carry, with its family and its class (types.json).

    from maisecrets.detection import TYPES
    TYPES["US_SSN"]["family"], TYPES["US_SSN"]["class"]     # "pii", "pii.national_id"

The family is `secret` or `pii`. The class is `<family>.<kind>`, or the family alone for a type that does not say
which kind it is (SECRET). docs/DETECTION.md, "The type vocabulary", says what stays and what may grow. A type of a
rule of your own (user_rule) is the caller's and is not listed."""
from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType


def _load() -> MappingProxyType:
    data = json.loads(Path(__file__).with_name("types.json").read_text(encoding="utf-8"))
    return MappingProxyType({t: MappingProxyType(dict(v)) for t, v in data["types"].items()})


TYPES = _load()
