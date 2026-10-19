"""Compatibility: the module normalise lives in maisecrets/detection/normalise.py.

This name is the same module object, so an import or a patch through it reaches the core itself."""
import sys

from .detection import normalise as _module

sys.modules[__name__] = _module
