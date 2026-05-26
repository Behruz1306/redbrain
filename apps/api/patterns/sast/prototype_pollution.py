from __future__ import annotations

import re

MERGE_DEEP = re.compile(
    r"(?:merge|extend|assign|deepCopy|deepMerge|defaults|defaultsDeep)\s*\(",
)
BRACKET_ASSIGN = re.compile(
    r"\w+\[[^\]]*(?:req\.|request\.|body\.|params\.|query\.|input)[^\]]*\]\s*=",
)
PROTO_ACCESS = re.compile(
    r"(?:__proto__|constructor\.prototype)\s*[\[\.]",
)
RECURSIVE_MERGE = re.compile(
    r"(?:for\s*\(|Object\.keys|Object\.entries).*\[(?:key|k|prop|attr)\]\s*=.*\[(?:key|k|prop|attr)\]",
)
LODASH_VULN = re.compile(
    r"(?:_\.merge|_\.defaultsDeep|_\.set|_\.setWith)\s*\(",
)
USER_INPUT = re.compile(
    r"(?:req\.|request\.|body\.|params\.|query\.|input)",
)

# --- Safe-pattern exclusions ---
# Object.assign({}, ...) with a new empty target is safe
SAFE_OBJECT_ASSIGN = re.compile(
    r"Object\.assign\s*\(\s*\{\s*\}",
)
# Fixed-key operations (not dynamic)
FIXED_KEY_OPERATION = re.compile(
    r"(?:Object\.assign|\.merge|\.extend)\s*\([^)]*\{\s*(?:['\"]?\w+['\"]?\s*:)",
)
# Lodash version >= 4.17.21 (patched)
LODASH_PATCHED = re.compile(
    r"""(?:lodash|_).*(?:version|@)\s*(?:=|:)?\s*['\"]?(?:4\.17\.(?:2[1-9]|[3-9]\d)|4\.1[89]|4\.[2-9]|[5-9]\.)""",
    re.IGNORECASE,
)
# Prototype key checks (hasOwnProperty, etc.)
PROTO_KEY_CHECK = re.compile(
    r"(?:hasOwnProperty|Object\.hasOwn|key\s*!==?\s*['\"](?:__proto__|constructor|prototype)['\"]"
    r"|(?:__proto__|constructor|prototype).*(?:continue|return|skip|throw|filter))",
    re.IGNORECASE,
)


def detect(source: str) -> float:
    has_user_input = bool(USER_INPUT.search(source))
    has_proto_check = bool(PROTO_KEY_CHECK.search(source))

    # Object.assign({}, ...) is safe (new target object)
    if SAFE_OBJECT_ASSIGN.search(source) and not PROTO_ACCESS.search(source):
        # If Object.assign({}, ...) is the only merge pattern, safe
        if not RECURSIVE_MERGE.search(source) and not LODASH_VULN.search(source):
            return 0.0

    best_score = 0.0

    # Direct __proto__ or constructor.prototype access
    if PROTO_ACCESS.search(source):
        if has_proto_check:
            best_score = max(best_score, 0.3)
        elif has_user_input:
            best_score = max(best_score, 0.8)
        else:
            best_score = max(best_score, 0.5)

    # Dynamic bracket assignment with user input
    if BRACKET_ASSIGN.search(source):
        if has_proto_check:
            best_score = max(best_score, 0.3)
        else:
            best_score = max(best_score, 0.7)

    # Recursive merge with user input
    if RECURSIVE_MERGE.search(source):
        if has_proto_check:
            best_score = max(best_score, 0.3)
        elif has_user_input:
            best_score = max(best_score, 0.8)
        else:
            best_score = max(best_score, 0.4)

    # Lodash merge functions
    if LODASH_VULN.search(source):
        if LODASH_PATCHED.search(source):
            return 0.0  # Patched lodash version
        if has_user_input:
            best_score = max(best_score, 0.4)
        else:
            best_score = max(best_score, 0.2)

    # Generic deep merge with user input but fixed keys
    if MERGE_DEEP.search(source) and has_user_input:
        if FIXED_KEY_OPERATION.search(source):
            return 0.0  # Fixed keys, not user-controlled
        best_score = max(best_score, 0.5)

    return best_score
