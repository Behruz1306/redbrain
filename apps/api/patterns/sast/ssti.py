from __future__ import annotations

import re

# Dangerous: render_template_string (string-based template rendering)
TEMPLATE_RENDER_USER = re.compile(
    r"(?:render_template_string|Template\(|Jinja2|nunjucks\.render|ejs\.render|pug\.render|handlebars\.compile)"
    r"\s*\([^)]*(?:req\.|request\.|body\.|params\.|query\.|args\.|\$\{|f['\"]|\+)",
)
EVAL_TEMPLATE = re.compile(
    r"(?:eval|Function)\s*\(\s*[`'\"].*(?:\$\{|<%|{{|\{%)",
)
RENDER_STRING_USER = re.compile(
    r"(?:render_template_string|render_string|from_string)\s*\(\s*(?:req\.|request\.|f['\"]|data|input|body)",
)
ANGULAR_INTERPOLATION = re.compile(
    r"(?:innerHTML|\$sce\.trustAsHtml|\$compile)\s*(?:=|\().*(?:req\.|user|input|data)",
)
ERB_INJECT = re.compile(
    r"(?:ERB\.new|render\s+inline:)\s*(?:params|request|user_input)",
)

# --- Safe-pattern exclusions ---
# render_template() with file path is safe (file-based templates)
SAFE_RENDER_TEMPLATE = re.compile(
    r"render_template\s*\(\s*['\"][^'\"]+\.(?:html|jinja2?|j2|tpl)['\"]",
)
# DOMPurify or sanitize-html protects innerHTML
SANITIZED_INNERHTML = re.compile(
    r"(?:DOMPurify\.sanitize|sanitizeHtml|sanitize-html|xss\(|escape\(|escapeHtml|bleach\.clean)",
    re.IGNORECASE,
)
USER_INPUT = re.compile(
    r"(?:req\.|request\.|params\.|query\.|body\.|args\.|user_input)",
    re.IGNORECASE,
)


def detect(source: str) -> float:
    # Safe file-based render_template() calls
    if SAFE_RENDER_TEMPLATE.search(source):
        # Only file-based template rendering, no string rendering
        if not re.search(r"render_template_string|from_string|Template\(", source):
            return 0.0

    best_score = 0.0

    # render_template_string with user input = very dangerous
    if RENDER_STRING_USER.search(source):
        if USER_INPUT.search(source):
            return 0.9
        best_score = max(best_score, 0.6)

    # Template constructor with user input
    if TEMPLATE_RENDER_USER.search(source):
        if USER_INPUT.search(source):
            best_score = max(best_score, 0.9)
        else:
            best_score = max(best_score, 0.5)

    # eval with template syntax
    if EVAL_TEMPLATE.search(source):
        best_score = max(best_score, 0.8)

    # ERB injection
    if ERB_INJECT.search(source):
        best_score = max(best_score, 0.8)

    # innerHTML-based XSS (lower confidence, different from SSTI)
    if ANGULAR_INTERPOLATION.search(source):
        if SANITIZED_INNERHTML.search(source):
            return 0.0  # Sanitized, safe
        best_score = max(best_score, 0.3)

    return best_score
