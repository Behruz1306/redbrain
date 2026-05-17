from __future__ import annotations

import re

REDIRECT_USER_INPUT = re.compile(
    r"(?:redirect|res\.redirect|response\.redirect|location\.href|window\.location|header\s*\(\s*['\"]Location)"
    r".*(?:req\.|request\.|params\.|query\.|body\.|args\.|url|next|return_to|goto|dest|continue|redirect_uri|callback)",
)
UNVALIDATED_URL = re.compile(
    r"(?:redirect|302|301|Location)\s*(?:=|\(|:)\s*(?:req\.(?:query|params|body)|request\.(?:args|form|GET|POST))\s*(?:\[|\.)\s*(?:['\"]?(?:url|next|redirect|return|goto|dest|continue|callback))",
)
OPEN_REDIR_HEADER = re.compile(
    r"(?:setHeader|set)\s*\(\s*['\"](?:Location|location)['\"].*(?:req\.|request\.|params\.|query\.)",
)


def detect(source: str) -> bool:
    if REDIRECT_USER_INPUT.search(source):
        return True
    if UNVALIDATED_URL.search(source):
        return True
    if OPEN_REDIR_HEADER.search(source):
        return True
    return False
