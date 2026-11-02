"""Time checks that hold on a loaded machine.

A fixed bound on the time of a call (1.0 s of wall time, 3.0 s of CPU) failed in pipelines and on loaded machines
with no change to the code (2026-10-16). The claim of such a test is about how the time grows: a scan that grows with
the square of its text, or a wait per key. So a check here measures CPU time, not wall time (other processes slow the
clock, not the call), takes the fastest of a few calls of the small case (other processes only ever add to it), and
compares two sizes: 8 times the input is 8 times the time when the call is linear and 64 times when it is quadratic.
An absolute bound stays for a cost that does not grow with the input: 3 s of CPU by default (the calls here take at
most 115 ms at load 35), the 7 s watchdog of a hook for a call that takes over 0.5 s (Gate A review: a fixed cost of
8 s passed a check of the growth alone).

The slack holds several steps of the CPU clock of Windows (about 15.6 ms each). So a check of the growth sees a part
that grows with the square of the input only when that part takes about as long as the linear work at the large size,
and at least some 70 ms (Gate B review). The fixed bounds before were not stricter.
"""
from __future__ import annotations

import time

SLACK = 0.05


def cpu_best(fn, *args, runs: int = 3) -> float:
    """The least CPU time of `runs` calls of fn(*args)."""
    best = None
    for _ in range(runs):
        t = time.process_time()
        fn(*args)
        took = time.process_time() - t
        best = took if best is None else min(best, took)
    return best


def cpu_per_call(fn, *args, runs: int = 3, batch: float = 0.05, most: int = 256) -> float:
    """The CPU time of one call of fn(*args), from batches of calls that each take at least `batch` seconds (or `most`
    calls): the least of `runs` batches. On Windows the CPU clock moves in steps of about 15.6 ms, so one short call
    read 0.0 ms, and the large input then failed the check of the growth at 62 ms (GitHub windows-latest,
    2026-10-17)."""
    calls = 1
    while True:
        t = time.process_time()
        for _ in range(calls):
            fn(*args)
        took = time.process_time() - t
        if took >= batch or calls >= most:
            break
        calls *= 4
    best = took / calls
    for _ in range(runs - 1):
        t = time.process_time()
        for _ in range(calls):
            fn(*args)
        best = min(best, (time.process_time() - t) / calls)
    return best


def assert_linear(case, run, make, n: int, *, hang: float = 3.0, wall: float = 7.0, slack: float = SLACK) -> tuple:
    """run(make(n // 8)), the fastest of three batches (cpu_per_call), and run(make(n)), the faster of two, in
    turns: at most 16 times plus the slack (linear is 8 times, quadratic 64 times), and below `hang` seconds. The
    inputs are made before the clock starts, and one call of run(make(64)) before the first measurement compiles what
    a first call compiles. One call of the large input once took 17 times its usual time (a first allocation of that
    size): so one untimed call of it first, and two timed. Returns (small, big)."""
    # CPU time does not see a wait (a sleep, a lock, blocking I/O): each call here, the first one included, stays below
    # `wall` seconds of wall time, the 7 s watchdog of a hook by default (Gate A review, rounds 2 and 3: a sum over two
    # calls let one wait of 13 s pass, and a wait in the first call only was never measured). The few calls that take
    # over 0.5 s of CPU pass wall=20.0: they took 11.8 s at load 100. A wait in detect.scan itself is caught at 7 s by
    # tests.test_scan_bounds, which uses the default
    slowest = [0.0]

    def timed(arg):
        if isinstance(arg, str) and len(arg) > 1:
            # a new object with the same text: the scan keeps the index of the last text it saw (text_index.py, by
            # identity), so the same object again measured the cached path, about a tenth of a first scan. A hook
            # scans each text once. The copy is a memcpy, small against the scan
            arg = arg[:1] + arg[1:]
        t = time.perf_counter()
        run(arg)
        slowest[0] = max(slowest[0], time.perf_counter() - t)

    timed(make(64))
    small_input, big_input = make(n // 8), make(n)
    # the two sizes in turns, so a wave of load from the other test files (CI runs four at once) meets both: one after
    # the other, an infisical near-miss case read 18 times for 8 times the input in CI and 7.95 times on a quiet laptop
    timed(big_input)   # the first call of the large size allocates for it (once 17 times its usual time); not counted
    small = cpu_per_call(timed, small_input, runs=1)
    big = None
    for _ in range(2):
        big = cpu_best(timed, big_input, runs=1) if big is None else min(big, cpu_best(timed, big_input, runs=1))
        small = min(small, cpu_per_call(timed, small_input, runs=1))
    case.assertLess(slowest[0], wall, "a call waited, not only computed")
    case.assertLess(big, 16 * small + slack, f"{small * 1000:.1f} ms, then {big * 1000:.1f} ms for 8 times the input")
    case.assertLess(big, hang)
    return small, big
