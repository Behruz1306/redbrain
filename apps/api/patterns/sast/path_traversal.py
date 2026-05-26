from __future__ import annotations

import re

FILE_FROM_USER = re.compile(
    r"(?:readFile|readFileSync|createReadStream|open|Path)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|args\.|\$\{|f['\"]|\+\s*(?:req|request|params|filename|path|file))",
)
PATH_JOIN_USER = re.compile(
    r"(?:path\.join|path\.resolve|os\.path\.join)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|filename|file_name)",
)
DOWNLOAD_ROUTE = re.compile(
    r"(?:download|sendFile|send_file|serve_file)\s*\([^)]*(?:req\.|request\.|params\.|query\.)",
)
STATIC_SERVE_DYNAMIC = re.compile(
    r"(?:express\.static|send|sendFile)\s*\([^)]*(?:\+|`\$\{)",
)
USER_INPUT = re.compile(
    r"(?:req\.|request\.|params\.|query\.|body\.|args\.)",
    re.IGNORECASE,
)

# --- Safe-pattern exclusions ---
BASENAME_SANITIZED = re.compile(
    r"(?:path\.basename|os\.path\.basename|basename)\s*\(",
    re.IGNORECASE,
)
RESOLVE_STARTSWITH = re.compile(
    r"(?:startsWith|startswith|\.indexOf\s*\(\s*(?:baseDir|base_dir|root|upload|allowed))\s*",
    re.IGNORECASE,
)
STATIC_CONSTANT_PATH = re.compile(
    r"(?:express\.static|serve_static|sendFile|send_file)\s*\(\s*['\"][^'\"]*['\"]",
)
PATH_VALIDATION = re.compile(
    r"(?:\.\.\/|\.\.\\\\|path\.normalize|realpath|path\.resolve.*startsWith"
    r"|includes\s*\(\s*['\"]\.\.['\"]\s*\)"
    r"|\.replace\s*\([^)]*\.\.|sanitize[_-]?path|safe[_-]?path|clean[_-]?path)",
    re.IGNORECASE,
)


def detect(source: str) -> float:
    # Static file serving with constant paths is safe
    if STATIC_CONSTANT_PATH.search(source) and not USER_INPUT.search(source):
        return 0.0

    # basename sanitization: user input goes through path.basename
    has_basename = BASENAME_SANITIZED.search(source)

    # resolve + startsWith check
    has_resolve_check = RESOLVE_STARTSWITH.search(source)

    # General path validation
    has_validation = PATH_VALIDATION.search(source)

    is_sanitized = has_basename or (has_resolve_check and has_validation)

    # Direct file read with user input
    if FILE_FROM_USER.search(source):
        if is_sanitized:
            return 0.2
        return 0.9

    # path.join with user input but validation nearby
    if PATH_JOIN_USER.search(source):
        if is_sanitized:
            return 0.2
        if has_resolve_check or has_validation:
            return 0.4
        return 0.7

    # Download/sendFile route with user input
    if DOWNLOAD_ROUTE.search(source):
        if is_sanitized:
            return 0.2
        return 0.8

    # Dynamic static serve
    if STATIC_SERVE_DYNAMIC.search(source):
        if is_sanitized:
            return 0.2
        return 0.6

    return 0.0
