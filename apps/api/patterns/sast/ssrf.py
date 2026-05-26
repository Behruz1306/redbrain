from __future__ import annotations

import re

URL_FROM_USER = re.compile(
    r"(?:fetch|axios|http\.get|httpx?\.(get|post|request)|urllib\.request\.urlopen|requests\.(get|post))"
    r"\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|args\.|\$\{|f['\"])",
)
URL_CONCAT = re.compile(
    r"(?:url|uri|href|endpoint|target)\s*(?:=|\+=)\s*(?:req\.|request\.|params\.|query\.|body\.)",
)
SSRF_SINK = re.compile(
    r"(?:got|node-fetch|undici|urllib3|aiohttp)\s*\(\s*(?:url|uri|target|dest)",
)
USER_INPUT = re.compile(
    r"(?:req\.|request\.|params\.|query\.|body\.|args\.)",
    re.IGNORECASE,
)

# --- Safe-pattern exclusions ---
HARDCODED_URL = re.compile(
    r"(?:fetch|axios|http\.get|requests\.(?:get|post))\s*\(\s*['\"]https?://[^'\"]+['\"]",
)
CONSTANT_BASE_URL = re.compile(
    r"(?:BASE_URL|API_URL|INTERNAL_URL|SERVICE_URL|base_url|api_url)\s*(?:=|:)\s*['\"]https?://",
    re.IGNORECASE,
)
HARDCODED_DOMAIN_VARIABLE_PATH = re.compile(
    r"['\"]https?://[a-zA-Z0-9._-]+(?:\.[a-zA-Z]{2,})/['\"]?\s*\+",
)
CONFIG_URL = re.compile(
    r"(?:config|settings|env|process\.env|os\.environ)\s*(?:\.|\.get\(|\.?\[)\s*['\"]?\w*(?:url|uri|endpoint|host|base)",
    re.IGNORECASE,
)
# Overlap with open_redirect: don't flag redirect patterns here
REDIRECT_ONLY = re.compile(
    r"(?:redirect|res\.redirect|response\.redirect|location\.href)\s*(?:=|\()",
)


def detect(source: str) -> float:
    # Remove redirect-only patterns from SSRF (handled by open_redirect detector)
    # If the only match is a redirect pattern, skip
    has_redirect = REDIRECT_ONLY.search(source)

    # Hardcoded constant URLs are safe
    if HARDCODED_URL.search(source) and not USER_INPUT.search(source):
        return 0.0

    has_user_input = USER_INPUT.search(source)

    # Direct URL from user input to request function
    if URL_FROM_USER.search(source):
        if has_user_input:
            return 0.9
        return 0.5

    # URL built from concatenation with user input
    if URL_CONCAT.search(source):
        if has_redirect and not re.search(r"(?:fetch|http|request|axios|got)", source):
            return 0.0  # This is an open redirect, not SSRF
        if re.search(r"(?:fetch|http|request|axios|got)", source):
            return 0.8
        return 0.0

    # SSRF sink with variable URL
    if SSRF_SINK.search(source):
        if has_user_input:
            return 0.8
        return 0.4

    # URL from config/env (not directly user-controlled)
    if CONFIG_URL.search(source) and re.search(r"(?:fetch|http|request|axios)", source):
        return 0.5

    # Hardcoded domain with variable path
    if HARDCODED_DOMAIN_VARIABLE_PATH.search(source):
        return 0.2

    return 0.0
