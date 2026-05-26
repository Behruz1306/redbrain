from __future__ import annotations

import re

REDIRECT_USER_INPUT = re.compile(
    r"(?:redirect|res\.redirect|response\.redirect|location\.href|window\.location|header\s*\(\s*['\"]Location)"
    r".*(?:req\.|request\.|params\.|query\.|body\.|args\.)",
)
UNVALIDATED_URL = re.compile(
    r"(?:redirect|302|301|Location)\s*(?:=|\(|:)\s*(?:req\.(?:query|params|body)|request\.(?:args|form|GET|POST))\s*(?:\[|\.)\s*(?:['\"]?(?:url|next|redirect|return|goto|dest|continue|callback))",
)
OPEN_REDIR_HEADER = re.compile(
    r"(?:setHeader|set)\s*\(\s*['\"](?:Location|location)['\"].*(?:req\.|request\.|params\.|query\.)",
)
USER_INPUT_REDIRECT_PARAMS = re.compile(
    r"(?:req\.(?:query|params|body)|request\.(?:args|form|GET|POST))\s*(?:\.|\.get\(|\[)\s*['\"]?(?:url|next|redirect|return_to|goto|dest|continue|redirect_uri|callback|return_url|redir)['\"]?",
)

# --- Safe-pattern exclusions ---
RELATIVE_PATH_REDIRECT = re.compile(
    r"(?:redirect|res\.redirect|response\.redirect)\s*\(\s*['\"]\/[a-zA-Z]",
)
URL_WHITELIST_CHECK = re.compile(
    r"(?:allowedUrls|whitelistedDomains|allowed_hosts|ALLOWED_REDIRECT|validDomains"
    r"|trusted_urls|safe_urls|approved_domains|\.includes\(|\.indexOf\(|startsWith\("
    r"|validateUrl|isValidRedirect|isSafeUrl|checkUrl|verifyUrl|url_has_allowed_host_and_scheme)",
    re.IGNORECASE,
)
CONSTANT_REDIRECT = re.compile(
    r"(?:redirect|res\.redirect|response\.redirect)\s*\(\s*['\"](?:https?://[^'\"]+|/[^'\"]+)['\"]",
)


def detect(source: str) -> float:
    # Constant/hardcoded redirects are safe
    if CONSTANT_REDIRECT.search(source):
        if not USER_INPUT_REDIRECT_PARAMS.search(source):
            return 0.0

    # Relative path redirects starting with / are safe
    if RELATIVE_PATH_REDIRECT.search(source):
        if not USER_INPUT_REDIRECT_PARAMS.search(source):
            return 0.0

    # URL whitelist/validation check nearby
    has_validation = bool(URL_WHITELIST_CHECK.search(source))

    # Direct redirect with user-controlled query params (url, next, redirect, etc.)
    if UNVALIDATED_URL.search(source):
        if has_validation:
            return 0.3
        return 0.8

    # res.redirect(req.query.next) pattern
    if USER_INPUT_REDIRECT_PARAMS.search(source):
        if REDIRECT_USER_INPUT.search(source):
            if has_validation:
                return 0.3
            return 0.8

    # Location header with user input
    if OPEN_REDIR_HEADER.search(source):
        if has_validation:
            return 0.3
        return 0.7

    # Generic redirect with user input (lower confidence)
    if REDIRECT_USER_INPUT.search(source):
        if has_validation:
            return 0.2
        return 0.3

    return 0.0
