from __future__ import annotations

import re

# --- Core patterns (kept but refined) ---
BALANCE_DEDUCT = re.compile(
    r"(?:balance|wallet|credit|points|stock|inventory)\s*(?:-=|=.*-|\-\s*(?:amount|quantity|price))",
)

# --- Safe-pattern exclusions ---
TRANSACTION_BLOCK = re.compile(
    r"(?:BEGIN|COMMIT|ROLLBACK|START\s+TRANSACTION|startTransaction|beginTransaction"
    r"|@transaction\.atomic|transaction\.atomic|with_transaction|withTransaction"
    r"|serializable|SERIALIZABLE|FOR\s+UPDATE|LOCK\s+IN\s+SHARE\s+MODE"
    r"|\.lock\(|acquire_lock|release_lock|mutex|semaphore|synchronized"
    r"|SELECT\s+.*\s+FOR\s+UPDATE)",
    re.IGNORECASE,
)
ATOMIC_OPERATIONS = re.compile(
    r"(?:\$inc|\$set.*\$inc|findOneAndUpdate|findAndModify|atomicUpdate"
    r"|UPDATE\s+.*\s+SET\s+\w+\s*=\s*\w+\s*[\+\-]"
    r"|\.increment\(|\.decrement\(|RETURNING\b|atomic_update"
    r"|\.update_one\(.*\$inc)",
    re.IGNORECASE,
)


def _lines_between(source: str, pattern_a: re.Pattern, pattern_b: re.Pattern, max_lines: int = 10) -> bool:
    """Check if pattern_a and pattern_b matches are within max_lines of each other."""
    lines = source.split("\n")
    a_lines = []
    b_lines = []
    for i, line in enumerate(lines):
        if pattern_a.search(line):
            a_lines.append(i)
        if pattern_b.search(line):
            b_lines.append(i)

    for a in a_lines:
        for b in b_lines:
            if 0 < abs(b - a) <= max_lines:
                return True
    return False


def detect(source: str) -> float:
    # If explicit transaction/locking is present, dramatically reduce risk
    has_transaction = bool(TRANSACTION_BLOCK.search(source))

    # If using atomic operations, exclude entirely
    if ATOMIC_OPERATIONS.search(source):
        return 0.0

    best_score = 0.0

    # Check-then-act: if(balance >= amount) ... balance -= amount
    # Must be within 10 lines of each other
    CHECK_PATTERN = re.compile(
        r"if\s*\(.*(?:balance|stock|quantity|count|amount|available)",
    )
    ACT_PATTERN = re.compile(
        r"(?:update|save|deduct|subtract|decrement|transfer|balance\s*-=|balance\s*=)",
    )
    if _lines_between(source, CHECK_PATTERN, ACT_PATTERN, max_lines=10):
        if has_transaction:
            best_score = max(best_score, 0.2)
        else:
            best_score = max(best_score, 0.8)

    # TOCTOU file operations: exists/stat then open/read/write within 10 lines
    TOCTOU_CHECK = re.compile(r"(?:exists|access|stat|isFile|isDirectory)\s*\(")
    TOCTOU_ACT = re.compile(r"(?:open|read|write|unlink|rename|readFile|writeFile)\s*\(")
    if _lines_between(source, TOCTOU_CHECK, TOCTOU_ACT, max_lines=10):
        if has_transaction:
            best_score = max(best_score, 0.2)
        else:
            best_score = max(best_score, 0.8)

    # Async read-modify-write without lock: findOne/get then save/update within 10 lines
    ASYNC_READ = re.compile(r"(?:await\s+)?(?:findOne|findById|get|load|fetch)\s*\(")
    ASYNC_WRITE = re.compile(r"(?:await\s+)?(?:\.save|\.update|\.put|\.patch)\s*\(")
    if _lines_between(source, ASYNC_READ, ASYNC_WRITE, max_lines=10):
        if BALANCE_DEDUCT.search(source):
            if has_transaction:
                best_score = max(best_score, 0.2)
            else:
                best_score = max(best_score, 0.5)

    # Just having balance variable without clear check-then-act
    if BALANCE_DEDUCT.search(source) and best_score == 0.0:
        if has_transaction:
            return 0.0
        best_score = max(best_score, 0.2)

    return best_score
