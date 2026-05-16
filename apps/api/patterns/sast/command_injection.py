from __future__ import annotations

import re

DANGEROUS_CALLS = re.compile(
    r"\b(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen"
    r"|child_process\.exec|child_process\.execSync"
    r"|execSync|spawnSync)\s*\(",
)
SHELL_TRUE = re.compile(r"shell\s*=\s*True")
VARIABLE_IN_CALL = re.compile(
    r"(?:os\.system|os\.popen|child_process\.exec|execSync)\s*\([^)]*(?:\+|f['\"]|\$\{|\%s)",
)


def detect(source: str) -> bool:
    if VARIABLE_IN_CALL.search(source):
        return True
    if DANGEROUS_CALLS.search(source) and SHELL_TRUE.search(source):
        return True
    return False
