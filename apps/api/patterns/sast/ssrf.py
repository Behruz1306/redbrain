from __future__ import annotations

import re

URL_FROM_USER = re.compile(
    r"(?:fetch|axios|http\.get|httpx?\.(get|post|request)|urllib\.request\.urlopen|requests\.(get|post))"
    r"\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|args\.|\$\{|f['\"])",
)
URL_CONCAT = re.compile(
    r"(?:url|uri|href|endpoint|target|redirect)\s*(?:=|\+=)\s*(?:req\.|request\.|params\.|query\.|body\.)",
)
REDIRECT_PATTERN = re.compile(
    r"(?:redirect|res\.redirect|response\.redirect|location\.href)\s*(?:=|\()?\s*(?:req\.|request\.|params\.|query\.)",
)
SSRF_SINK = re.compile(
    r"(?:got|node-fetch|undici|urllib3|aiohttp)\s*\(\s*(?:url|uri|target|dest)",
)


def detect(source: str) -> bool:
    if URL_FROM_USER.search(source):
        return True
    if URL_CONCAT.search(source) and re.search(r"(?:fetch|http|request)", source):
        return True
    if REDIRECT_PATTERN.search(source):
        return True
    if SSRF_SINK.search(source):
        return True
    return False
