"""Compatibility: the module personal lives in maisecrets/detection/personal.py.

This name is the same module object, so an import or a patch through it reaches the core itself."""
import sys

from .detection import personal as _module

sys.modules[__name__] = _module
