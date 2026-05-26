from __future__ import annotations

import re

ROUTE_DEF = re.compile(
    r"(?:app|router)\s*\.\s*(?:get|post|put|delete|patch)\s*\(",
    re.IGNORECASE,
)
AUTH_DECORATORS = re.compile(
    r"(?:@requires_auth|@login_required|@authenticate|@auth_required|@jwt_required"
    r"|@protected|@require_admin|@permission_required|@permissions_required"
    r"|@token_required|@api_key_required)",
    re.IGNORECASE,
)
AUTH_MIDDLEWARE = re.compile(
    r"(?:authenticate|verifyToken|requireAuth|isAuthenticated|authMiddleware"
    r"|passport\.authenticate|requireAdmin|checkPermission|ensureLoggedIn"
    r"|isAuthed|protect|guard|UseGuards|permission_classes|IsAuthenticated"
    r"|AllowAny|requireLogin|checkAuth|verifyAuth|requireRole|ensureAuth"
    r"|authGuard|jwtGuard|sessionGuard|apiKeyAuth|bearerAuth)",
    re.IGNORECASE,
)
SENSITIVE_PATHS = re.compile(
    r"['\"]\/(?:api\/)?(?:admin|user|account|profile|settings|payment|order|dashboard)",
    re.IGNORECASE,
)
ADMIN_PATHS = re.compile(
    r"['\"]\/(?:api\/)?(?:admin|settings|payment|billing|manage|internal)",
    re.IGNORECASE,
)
PUBLIC_ROUTES = re.compile(
    r"['\"]\/(?:api\/)?(?:login|register|signup|sign-up|sign-in|signin|health|healthz"
    r"|status|public|callback|webhook|webhooks|oauth|auth\/callback|\.well-known"
    r"|favicon|robots\.txt|sitemap|ping|version|docs|swagger|api-docs|openapi"
    r"|forgot-password|reset-password|verify-email|confirm)['\"/]?",
    re.IGNORECASE,
)
# Global auth middleware applied to router
ROUTER_USE_AUTH = re.compile(
    r"router\.use\s*\(\s*(?:auth|authenticate|requireAuth|verifyToken|protect|guard)",
    re.IGNORECASE,
)


def detect(source: str) -> float:
    if not ROUTE_DEF.search(source):
        return 0.0

    if not SENSITIVE_PATHS.search(source):
        return 0.0

    # If global auth middleware is applied to the router, skip
    if ROUTER_USE_AUTH.search(source):
        return 0.0

    # If auth decorators or middleware are present, skip
    if AUTH_DECORATORS.search(source):
        return 0.0
    if AUTH_MIDDLEWARE.search(source):
        return 0.0

    # If the route is a public route, skip
    if PUBLIC_ROUTES.search(source) and not ADMIN_PATHS.search(source):
        return 0.0

    # Admin routes without auth are highest risk
    if ADMIN_PATHS.search(source):
        return 0.7

    # Other sensitive routes without auth
    return 0.4
