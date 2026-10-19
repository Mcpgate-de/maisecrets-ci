"""Compatibility: the detector lives in maisecrets/detection/core.py.

This name is the same module object, so an import or a patch through it reaches the core itself."""
import sys

from .detection import core as _module

sys.modules[__name__] = _module
