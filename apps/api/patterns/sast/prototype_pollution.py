from __future__ import annotations

import re

MERGE_DEEP = re.compile(
    r"(?:merge|extend|assign|deepCopy|deepMerge|defaults|defaultsDeep)\s*\(",
)
BRACKET_ASSIGN = re.compile(
    r"\w+\[[^\]]*(?:req\.|request\.|body\.|params\.|query\.|input)[^\]]*\]\s*=",
)
PROTO_ACCESS = re.compile(
    r"(?:__proto__|constructor\.prototype|Object\.assign)\s*[\[\.]",
)
RECURSIVE_MERGE = re.compile(
    r"(?:for\s*\(|Object\.keys|Object\.entries).*\[(?:key|k|prop|attr)\]\s*=.*\[(?:key|k|prop|attr)\]",
)
LODASH_VULN = re.compile(
    r"(?:_\.merge|_\.defaultsDeep|_\.set|_\.setWith)\s*\(",
)


def detect(source: str) -> bool:
    if PROTO_ACCESS.search(source):
        return True
    if BRACKET_ASSIGN.search(source):
        return True
    if MERGE_DEEP.search(source) and re.search(r"(?:req\.|request\.|body\.|input)", source):
        return True
    if RECURSIVE_MERGE.search(source):
        return True
    if LODASH_VULN.search(source) and re.search(r"(?:req\.|request\.|body\.)", source):
        return True
    return False
