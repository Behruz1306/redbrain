from __future__ import annotations

import re

CHECK_THEN_ACT = re.compile(
    r"(?:if\s*\(.*(?:balance|stock|quantity|count|amount|available)).*(?:update|save|deduct|subtract|decrement|transfer)",
    re.DOTALL,
)
TOCTOU_FILE = re.compile(
    r"(?:exists|access|stat).*(?:open|read|write|unlink|rename)",
    re.DOTALL,
)
NO_LOCK_UPDATE = re.compile(
    r"(?:findOne|get|load|fetch)\s*\(.*(?:save|update|put|patch)\s*\(",
    re.DOTALL,
)
BALANCE_DEDUCT = re.compile(
    r"(?:balance|wallet|credit|points|stock|inventory)\s*(?:-=|=.*-|\-\s*(?:amount|quantity|price))",
)
CONCURRENT_UNSAFE = re.compile(
    r"(?:async\s+function|await)\s+.*(?:findOne|get).*(?:\.save|\.update|UPDATE)",
    re.DOTALL,
)


def detect(source: str) -> bool:
    if CHECK_THEN_ACT.search(source):
        return True
    if TOCTOU_FILE.search(source):
        return True
    if NO_LOCK_UPDATE.search(source) and BALANCE_DEDUCT.search(source):
        return True
    if CONCURRENT_UNSAFE.search(source) and BALANCE_DEDUCT.search(source):
        return True
    return False
