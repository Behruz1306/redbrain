from __future__ import annotations

import re

EVAL_CALLS = re.compile(
    r"\b(eval|Function|exec|execfile|compile)\s*\(",
)
LITERAL_ONLY = re.compile(
    r"\b(eval|Function|exec)\s*\(\s*['\"][^'\"]*['\"]\s*\)",
)


def detect(source: str) -> bool:
    matches = EVAL_CALLS.findall(source)
    if not matches:
        return False
    literals = LITERAL_ONLY.findall(source)
    return len(matches) > len(literals)
