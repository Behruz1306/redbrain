from __future__ import annotations

import re

ALG_NONE = re.compile(
    r"""(?:algorithms?\s*(?:=|:)\s*\[?[^]]*['"]none['"]|verify\s*(?:=|:)\s*(?:false|False|0))""",
)
NO_VERIFY = re.compile(
    r"(?:jwt\.decode|jsonwebtoken\.verify|jose\.jwtVerify)\s*\([^)]*(?:verify\s*(?:=|:)\s*(?:false|False)|options.*(?:ignoreExpiration|algorithms))",
)
SECRET_HARDCODED = re.compile(
    r"""(?:jwt\.sign|jwt\.encode|createToken)\s*\([^)]*['"](secret|password|key123|changeme|mysecret)['"]""",
)
WEAK_SECRET = re.compile(
    r"""(?:SECRET_KEY|JWT_SECRET|TOKEN_SECRET)\s*(?:=|:)\s*['"][^'"]{1,10}['"]""",
)
KID_INJECTION = re.compile(
    r"(?:kid|keyid|key_id).*(?:sql|query|exec|file|path|\/)",
)
RS256_TO_HS256 = re.compile(
    r"(?:algorithms?\s*(?:=|:)\s*\[.*HS256.*RS256|RS256.*HS256)",
)


def detect(source: str) -> bool:
    if ALG_NONE.search(source):
        return True
    if NO_VERIFY.search(source):
        return True
    if SECRET_HARDCODED.search(source):
        return True
    if WEAK_SECRET.search(source):
        return True
    if KID_INJECTION.search(source):
        return True
    if RS256_TO_HS256.search(source):
        return True
    return False
