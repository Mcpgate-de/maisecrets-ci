"""Compatibility: the module checksums lives in maisecrets/detection/checksums.py.

This name is the same module object, so an import or a patch through it reaches the core itself."""
import sys

from .detection import checksums as _module

sys.modules[__name__] = _module
