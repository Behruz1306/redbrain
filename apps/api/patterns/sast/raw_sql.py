from __future__ import annotations

import re

SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b", re.IGNORECASE
)
TEMPLATE_LITERAL = re.compile(r"`[^`]*\$\{[^}]+\}[^`]*`")
FSTRING_SQL = re.compile(r"f['\"].*\b(SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
CONCAT_SQL = re.compile(r"['\"].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*['\"].*\+", re.IGNORECASE)
QUERY_CALL = re.compile(r"\.(query|exec|execute|raw)\s*\(")


def detect(source: str) -> bool:
    if not SQL_KEYWORDS.search(source):
        return False
    if TEMPLATE_LITERAL.search(source) and QUERY_CALL.search(source):
        return True
    if FSTRING_SQL.search(source):
        return True
    if CONCAT_SQL.search(source) and QUERY_CALL.search(source):
        return True
    return False
