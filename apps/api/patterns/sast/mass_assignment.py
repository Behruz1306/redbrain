from __future__ import annotations

import re

SPREAD_BODY = re.compile(
    r"(?:\.create|\.update|\.insert|\.findOneAndUpdate|new\s+\w+)\s*\(\s*(?:\.\.\.|Object\.assign|req\.body|request\.body|data|body)",
)
MODEL_CREATE_BODY = re.compile(
    r"(?:Model|Schema|Repository|\.create|\.build|\.new)\s*\(\s*(?:req\.body|request\.body|ctx\.request\.body|params)",
)
UPDATE_WITHOUT_PICK = re.compile(
    r"(?:update|patch|put)\s*.*(?:req\.body|request\.body)(?!.*(?:pick|omit|allow|whitelist|permit))",
    re.DOTALL,
)
ROLE_IN_BODY = re.compile(
    r"(?:role|isAdmin|is_admin|admin|permissions|privilege)\s*(?:=|:).*(?:req\.|request\.|body\.|params\.)",
)


def detect(source: str) -> bool:
    if SPREAD_BODY.search(source):
        return True
    if MODEL_CREATE_BODY.search(source):
        return True
    if ROLE_IN_BODY.search(source):
        return True
    return False
