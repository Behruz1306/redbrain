from __future__ import annotations

import re

SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b", re.IGNORECASE
)
TEMPLATE_LITERAL = re.compile(r"`[^`]*\$\{[^}]+\}[^`]*`")
FSTRING_SQL = re.compile(r"f['\"].*\b(SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
CONCAT_SQL = re.compile(r"['\"].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*['\"].*\+", re.IGNORECASE)
QUERY_CALL = re.compile(r"\.(query|exec|execute|raw)\s*\(")

# --- Safe-pattern exclusions ---
PARAMETERIZED = re.compile(
    r"(?:\$[1-9]|\$\d{1,2}\b|\?\s*[,\)]|%s\s*[,\)]|:\w+\s*[,\)])", re.IGNORECASE
)
ORM_CHAIN = re.compile(
    r"\.(?:where|select|findOne|findAll|findById|findByPk|filter|exclude|annotate|order_by|limit|offset)\s*\(",
    re.IGNORECASE,
)
ORM_MODEL_QUERY = re.compile(
    r"(?:Model|models)\.\w+\.(?:query|objects|find|get|all)\s*\(", re.IGNORECASE
)
MIGRATION_DDL = re.compile(
    r"\b(?:CREATE\s+TABLE|ALTER\s+TABLE|ADD\s+COLUMN|DROP\s+TABLE|CREATE\s+INDEX)\b",
    re.IGNORECASE,
)
USER_INPUT_INDICATOR = re.compile(
    r"(?:req\.|request\.|params\.|query\.|body\.|args\.|user_input|user_data|form_data)",
    re.IGNORECASE,
)


def detect(source: str) -> float:
    if not SQL_KEYWORDS.search(source):
        return 0.0

    # Exclude DDL migrations without user input
    if MIGRATION_DDL.search(source) and not USER_INPUT_INDICATOR.search(source):
        return 0.0

    # Exclude parameterized queries
    if PARAMETERIZED.search(source):
        return 0.0

    # Exclude ORM method chains (safe by default)
    if ORM_CHAIN.search(source) and not CONCAT_SQL.search(source) and not FSTRING_SQL.search(source):
        return 0.0

    if ORM_MODEL_QUERY.search(source) and not CONCAT_SQL.search(source) and not FSTRING_SQL.search(source):
        return 0.0

    has_user_input = USER_INPUT_INDICATOR.search(source)

    # String concatenation with user input into a query call
    if CONCAT_SQL.search(source) and QUERY_CALL.search(source) and has_user_input:
        return 0.9

    # Template literal with user input in query
    if TEMPLATE_LITERAL.search(source) and QUERY_CALL.search(source) and has_user_input:
        return 0.9

    # f-string SQL with user input
    if FSTRING_SQL.search(source) and has_user_input:
        return 0.9

    # f-string SQL with variable but no direct user input evidence
    if FSTRING_SQL.search(source):
        return 0.6

    # Template literal in query without clear user input
    if TEMPLATE_LITERAL.search(source) and QUERY_CALL.search(source):
        return 0.6

    # Concat SQL in query without clear user input
    if CONCAT_SQL.search(source) and QUERY_CALL.search(source):
        return 0.6

    # Just a query call with a variable (lower confidence)
    if QUERY_CALL.search(source):
        return 0.3

    return 0.0
