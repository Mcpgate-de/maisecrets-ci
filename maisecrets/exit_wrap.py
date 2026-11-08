"""Exit 0 for a Bash command that gets a value (a stored one or one from a server), so that its output can be masked.

Claude Code answers a command that exits non-zero with PostToolUseFailure, and a hook cannot replace that output
(anthropics/claude-code#97278): a command that printed a value a server gave and then failed showed it to the model.
For such a command only (since 0.9.1 also one with a stored value, which failed the same way), the rewrite sets an
EXIT trap: the shell ends with 0, and the real exit code is printed as text, so PostToolUse runs and masks the output.
Remove this module, and its one call in hooks._pre_bash, when the harness scenario bash_failed_output fails with
"gap closed": then the client replaces a failed output itself.
Codex sends PostToolUse for a failed command (docs/THREAT-MODEL.md, C23), so it does not get the trap.
"""
from __future__ import annotations

UPSTREAM = "anthropics/claude-code#97278"

# `trap - EXIT` first: the trap runs once. `exit 0` in an EXIT trap sets the status of the shell in bash, zsh and sh
# (measured under `eval`, as Claude Code runs a command: `false`, `exit 3`, a pipeline and a subshell all end with 0
# and print their code; a `cd` keeps its effect)
_TRAP = ("trap '__ms_rc=$?; trap - EXIT; [ \"$__ms_rc\" -eq 0 ] || printf '\"'\"'\\n[maisecrets: the command "
         "ended with exit code %s. maisecrets reports it as 0, so that it can mask a value in this "
         "output]\\n'\"'\"' \"$__ms_rc\" >&2; exit 0' EXIT")


def trap() -> str:
    """The last part of the prelude, after the value reads: a value that was not delivered still ends with 97."""
    return _TRAP
