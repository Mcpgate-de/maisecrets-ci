#!/usr/bin/env python3
"""One test file as `python -m unittest discover -s tests -p FILE -v` runs it, plus its result as JSON.

    python scripts/_unit_file.py FILE OUT.json

The console text is unittest's own. OUT.json gets {"ran": N, "ok": true|false}: scripts/run_tests_parallel.py reads
it instead of the text, where a test that runs unittest in a child prints a second "Ran ..." line of its own."""
from __future__ import annotations

import faulthandler
import json
import os
import sys
import unittest

# scripts/run_tests_parallel.py sets it: a file that runs longer prints the stack of each thread and ends, so a hang
# names its line instead of holding the job until the CI kills it without a word
STALL = "MAISECRETS_UNIT_FILE_TIMEOUT"


def main(argv: list) -> int:
    pattern, out = argv[0], argv[1]
    limit = float(os.environ.get(STALL) or 0)
    if limit > 0:
        faulthandler.dump_traceback_later(limit, exit=True)
    # the import path of `python -m unittest`: the current folder first, not this script's folder
    sys.path[0] = os.getcwd()
    suite = unittest.defaultTestLoader.discover("tests", pattern=pattern)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"ran": result.testsRun, "ok": result.wasSuccessful()}, fh)
    return 0 if result.wasSuccessful() and result.testsRun else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
