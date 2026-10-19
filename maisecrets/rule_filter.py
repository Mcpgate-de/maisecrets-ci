"""Compatibility: the module rule_filter lives in maisecrets/detection/rule_filter.py.

This name is the same module object, so an import or a patch through it reaches the core itself."""
import sys

from .detection import rule_filter as _module

sys.modules[__name__] = _module
