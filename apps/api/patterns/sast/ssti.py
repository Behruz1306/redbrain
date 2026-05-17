from __future__ import annotations

import re

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


def detect(source: str) -> bool:
    if TEMPLATE_RENDER_USER.search(source):
        return True
    if EVAL_TEMPLATE.search(source):
        return True
    if RENDER_STRING_USER.search(source):
        return True
    if ANGULAR_INTERPOLATION.search(source):
        return True
    if ERB_INJECT.search(source):
        return True
    return False
