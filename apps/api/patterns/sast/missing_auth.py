from __future__ import annotations

import re

ROUTE_DEF = re.compile(
    r"(?:app|router)\s*\.\s*(?:get|post|put|delete|patch)\s*\(",
    re.IGNORECASE,
)
AUTH_DECORATORS = re.compile(
    r"(?:@requires_auth|@login_required|@authenticate|@auth_required|@jwt_required|@protected)",
    re.IGNORECASE,
)
AUTH_MIDDLEWARE = re.compile(
    r"(?:authenticate|verifyToken|requireAuth|isAuthenticated|authMiddleware|passport\.authenticate)",
    re.IGNORECASE,
)
SENSITIVE_PATHS = re.compile(
    r"['\"]\/(?:api\/)?(?:admin|user|account|profile|settings|payment|order|dashboard)",
    re.IGNORECASE,
)


def detect(source: str) -> bool:
    if not ROUTE_DEF.search(source):
        return False
    if not SENSITIVE_PATHS.search(source):
        return False
    if AUTH_DECORATORS.search(source):
        return False
    if AUTH_MIDDLEWARE.search(source):
        return False
    return True
