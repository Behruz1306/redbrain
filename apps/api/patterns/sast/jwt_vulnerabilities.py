from __future__ import annotations

import re

ALG_NONE = re.compile(
    r"""(?:algorithms?\s*(?:=|:)\s*\[?[^]]*['"]none['"])""",
)
VERIFY_FALSE = re.compile(
    r"""verify\s*(?:=|:)\s*(?:false|False|0)""",
)
NO_VERIFY = re.compile(
    r"(?:jwt\.decode|jsonwebtoken\.verify|jose\.jwtVerify)\s*\([^)]*(?:verify\s*(?:=|:)\s*(?:false|False)|options.*(?:ignoreExpiration|algorithms))",
)
SECRET_HARDCODED = re.compile(
    r"""(?:jwt\.sign|jwt\.encode|createToken)\s*\([^)]*['"](secret|password|key123|changeme|mysecret|test|admin)['"]""",
)
WEAK_SECRET = re.compile(
    r"""(?:SECRET_KEY|JWT_SECRET|TOKEN_SECRET)\s*(?:=|:)\s*['"][^'"]{1,10}['"]""",
)
KID_INJECTION = re.compile(
    r"(?:kid|keyid|key_id).*(?:sql|query|exec|execute|raw)\s*\(",
)
KID_FILE_PATH = re.compile(
    r"(?:kid|keyid|key_id).*(?:readFile|readFileSync|open|Path|fs\.)",
)
RS256_TO_HS256 = re.compile(
    r"(?:algorithms?\s*(?:=|:)\s*\[.*HS256.*RS256|RS256.*HS256)",
)

# --- Safe-pattern exclusions ---
TEST_FILE_INDICATORS = re.compile(
    r"(?:(?:^|\n)\s*(?:describe|it|test|expect|assert|mock|jest|pytest|unittest|spec|fixture)"
    r"|\btest[_\s]|_test\b|\.test\.|\.spec\.|_spec\b|mock[_\s]|fixture|__tests__|__mocks__)",
    re.IGNORECASE,
)
ENV_SECRET = re.compile(
    r"(?:process\.env|os\.environ|os\.getenv|environ\.get|config\.|settings\.)",
    re.IGNORECASE,
)


def detect(source: str) -> float:
    # Exclude test files
    if TEST_FILE_INDICATORS.search(source):
        return 0.0

    best_score = 0.0

    # algorithm: none
    if ALG_NONE.search(source):
        best_score = max(best_score, 0.9)

    # verify = false
    if VERIFY_FALSE.search(source):
        best_score = max(best_score, 0.5)

    # jwt.decode with no verification options
    if NO_VERIFY.search(source):
        best_score = max(best_score, 0.7)

    # Hardcoded weak secret in jwt.sign/encode
    if SECRET_HARDCODED.search(source):
        best_score = max(best_score, 0.8)

    # Short/weak JWT_SECRET value
    if WEAK_SECRET.search(source):
        if ENV_SECRET.search(source):
            best_score = max(best_score, 0.3)  # From env but weak value
        else:
            best_score = max(best_score, 0.8)

    # KID injection: must have actual query/exec construction, not just word co-occurrence
    if KID_INJECTION.search(source):
        best_score = max(best_score, 0.8)

    # KID file path injection
    if KID_FILE_PATH.search(source):
        best_score = max(best_score, 0.7)

    # Algorithm confusion (RS256 to HS256)
    if RS256_TO_HS256.search(source):
        best_score = max(best_score, 0.8)

    return best_score
