from __future__ import annotations

import re

PATTERNS = [
    re.compile(r"pickle\.loads?\s*\("),
    re.compile(r"yaml\.load\s*\([^)]*(?!Loader\s*=\s*SafeLoader)"),
    re.compile(r"yaml\.load\s*\([^)]*\)\s*(?!.*SafeLoader)"),
    re.compile(r"marshal\.loads?\s*\("),
    re.compile(r"shelve\.open\s*\("),
    re.compile(r"unserialize\s*\("),
    re.compile(r"ObjectInputStream"),
    re.compile(r"node-serialize"),
    re.compile(r"serialize-javascript.*\(\s*\w"),
]

SAFE_YAML = re.compile(r"yaml\.safe_load|Loader\s*=\s*SafeLoader")


def detect(source: str) -> bool:
    for pattern in PATTERNS:
        if pattern.search(source):
            if "yaml" in pattern.pattern and SAFE_YAML.search(source):
                continue
            return True
    return False
