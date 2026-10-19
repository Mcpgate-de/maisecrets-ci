"""Compatibility: the module registry lives in maisecrets/detection/registry.py.

This name is the same module object, so an import or a patch through it reaches the core itself."""
import sys

from .detection import registry as _module

sys.modules[__name__] = _module
