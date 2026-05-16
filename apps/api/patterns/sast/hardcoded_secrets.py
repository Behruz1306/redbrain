from __future__ import annotations

import re

PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"),
    re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
    re.compile(r"pk_live_[A-Za-z0-9]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
    re.compile(r"(?i)(?:api_key|apikey|secret_key|auth_token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
]


def detect(source: str) -> bool:
    return any(p.search(source) for p in PATTERNS)
