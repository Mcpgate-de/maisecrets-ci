"""Compatibility: the module lazy_regex lives in maisecrets/detection/lazy_regex.py.

This name is the same module object, so an import or a patch through it reaches the core itself."""
import sys

from .detection import lazy_regex as _module

sys.modules[__name__] = _module
