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
NO_SANITIZE = re.compile(
    r"(?:readFile|createReadStream|open)\s*\([^)]*(?:\.\.|\%2e)",
)
STATIC_SERVE_DYNAMIC = re.compile(
    r"(?:express\.static|send|sendFile)\s*\([^)]*(?:\+|`\$\{)",
)


def detect(source: str) -> bool:
    if FILE_FROM_USER.search(source):
        return True
    if PATH_JOIN_USER.search(source):
        return True
    if DOWNLOAD_ROUTE.search(source):
        return True
    if STATIC_SERVE_DYNAMIC.search(source):
        return True
    return False
