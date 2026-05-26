from __future__ import annotations

import re

MONGO_QUERY_USER = re.compile(
    r"(?:find|findOne|findOneAndUpdate|updateOne|deleteOne|aggregate)\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.)",
)
WHERE_USER_INPUT = re.compile(
    r"""['\"]?\$where['\"]?\s*(?:=|:)\s*(?:req\.|request\.|body\.|params\.)""",
)
OPERATOR_INJECTION = re.compile(
    r"(?:find|query|filter).*\$(?:gt|gte|lt|lte|ne|in|nin|regex|where|or|and)\b.*(?:req\.|request\.|body\.)",
)
NOSQL_CONCAT = re.compile(
    r"(?:\.find|\.aggregate)\s*\(\s*(?:JSON\.parse|`|f['\"].*\$\{)",
)
UNVALIDATED_OBJECT = re.compile(
    r"(?:collection|model|db)\.\w+\s*\(\s*(?:req\.body|request\.body|data)\s*[,\)]",
)

# --- Safe-pattern exclusions ---
SIMPLE_ID_LOOKUP = re.compile(
    r"(?:findOne|findById)\s*\(\s*(?:\{\s*_id\s*:\s*(?:id|req\.params\.id|params\.id|objectId)|req\.params\.id|params\.id)\s*\}?\s*\)",
    re.IGNORECASE,
)
HARDCODED_OPERATORS = re.compile(
    r"\{\s*\$(?:gt|gte|lt|lte|ne|in|nin|regex)\s*:\s*(?:\d+|true|false|null|['\"][^'\"]*['\"])\s*\}",
)
MONGOOSE_STRICT = re.compile(
    r"(?:strict\s*:\s*true|strictQuery\s*:\s*true|new\s+Schema\s*\()",
    re.IGNORECASE,
)


def detect(source: str) -> float:
    # Simple ID lookups are safe
    if SIMPLE_ID_LOOKUP.search(source):
        # If the only query pattern is a simple ID lookup, skip
        has_other_patterns = (
            WHERE_USER_INPUT.search(source)
            or OPERATOR_INJECTION.search(source)
            or NOSQL_CONCAT.search(source)
        )
        if not has_other_patterns:
            return 0.0

    has_mongoose_strict = bool(MONGOOSE_STRICT.search(source))

    # $where with user input is most dangerous
    if WHERE_USER_INPUT.search(source):
        return 0.9

    # Operator injection
    if OPERATOR_INJECTION.search(source):
        # If operators are hardcoded (values from user is fine), lower risk
        if HARDCODED_OPERATORS.search(source):
            return 0.3
        return 0.7

    # JSON.parse or template literal in query
    if NOSQL_CONCAT.search(source):
        return 0.7

    # Unvalidated object passed to collection method
    if UNVALIDATED_OBJECT.search(source):
        if has_mongoose_strict:
            return 0.2
        return 0.5

    # Simple query with req.body
    if MONGO_QUERY_USER.search(source):
        if has_mongoose_strict:
            return 0.2
        return 0.3

    return 0.0
