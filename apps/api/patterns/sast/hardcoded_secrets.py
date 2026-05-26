from __future__ import annotations

import re

# --- Real key patterns (high-entropy, specific formats) ---
AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
JWT_TOKEN = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}")
STRIPE_LIVE = re.compile(r"sk_live_[A-Za-z0-9]{20,}")
STRIPE_PK_LIVE = re.compile(r"pk_live_[A-Za-z0-9]{20,}")
GITHUB_PAT = re.compile(r"ghp_[A-Za-z0-9]{36}")
SLACK_TOKEN = re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")

# --- Generic secret assignments ---
PASSWORD_ASSIGN = re.compile(
    r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"
)
API_KEY_ASSIGN = re.compile(
    r"(?i)(?:api_key|apikey|secret_key|auth_token|access_token|private_key)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
)

# --- Safe-pattern exclusions ---
ENV_LOOKUP = re.compile(
    r"(?:os\.environ|process\.env|os\.getenv|environ\.get|env\[|env\.get|getenv|ENV\[|System\.getenv)",
    re.IGNORECASE,
)
PLACEHOLDER_VALUES = re.compile(
    r"(?i)['\"](?:changeme|todo|xxx+|test|example|placeholder|your[_-]?(?:api[_-]?key|secret|password|token)"
    r"|replace[_-]?me|insert[_-]?here|dummy|sample|fake|mock|CHANGE_ME|<[^>]+>|\.\.\.)['\"]"
)
TEST_FILE_INDICATORS = re.compile(
    r"(?:(?:^|\n)\s*(?:describe|it|test|expect|assert|mock|jest|pytest|unittest|spec|fixture)"
    r"|\btest[_\s]|_test\b|\.test\.|\.spec\.|_spec\b|mock[_\s]|fixture|__tests__|__mocks__)",
    re.IGNORECASE,
)


def detect(source: str) -> float:
    # Exclude test/spec/mock/fixture files
    if TEST_FILE_INDICATORS.search(source):
        return 0.0

    best_score = 0.0

    # Check for real AWS keys
    if AWS_KEY.search(source) and not ENV_LOOKUP.search(source):
        return 0.95

    # Check for real JWT tokens hardcoded
    if JWT_TOKEN.search(source) and not ENV_LOOKUP.search(source):
        best_score = max(best_score, 0.8)

    # Check for real Stripe live keys
    if STRIPE_LIVE.search(source) or STRIPE_PK_LIVE.search(source):
        if not ENV_LOOKUP.search(source):
            return 0.95

    # Check for GitHub PATs
    if GITHUB_PAT.search(source) and not ENV_LOOKUP.search(source):
        return 0.95

    # Check for Slack tokens
    if SLACK_TOKEN.search(source) and not ENV_LOOKUP.search(source):
        return 0.95

    # Check for API key assignments
    if API_KEY_ASSIGN.search(source):
        if ENV_LOOKUP.search(source):
            return 0.0
        # Check if it's a placeholder
        match = API_KEY_ASSIGN.search(source)
        if match and PLACEHOLDER_VALUES.search(match.group()):
            return 0.0
        best_score = max(best_score, 0.8)

    # Check for password assignments
    if PASSWORD_ASSIGN.search(source):
        if ENV_LOOKUP.search(source):
            return 0.0
        match = PASSWORD_ASSIGN.search(source)
        if match and PLACEHOLDER_VALUES.search(match.group()):
            return 0.0
        best_score = max(best_score, 0.4)

    return best_score
