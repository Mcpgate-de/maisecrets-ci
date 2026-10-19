"""Compatibility: the module regions lives in maisecrets/detection/regions.py.

This name is the same module object, so an import or a patch through it reaches the core itself."""
import sys

from .detection import regions as _module

sys.modules[__name__] = _module
