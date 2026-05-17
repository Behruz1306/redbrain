from __future__ import annotations

import re

MONGO_QUERY_USER = re.compile(
    r"(?:find|findOne|findOneAndUpdate|updateOne|deleteOne|aggregate)\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.)",
)
WHERE_USER_INPUT = re.compile(
    r"\$where\s*(?:=|:)\s*(?:req\.|request\.|body\.|params\.)",
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


def detect(source: str) -> bool:
    if MONGO_QUERY_USER.search(source):
        return True
    if WHERE_USER_INPUT.search(source):
        return True
    if OPERATOR_INJECTION.search(source):
        return True
    if NOSQL_CONCAT.search(source):
        return True
    if UNVALIDATED_OBJECT.search(source):
        return True
    return False
