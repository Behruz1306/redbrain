from __future__ import annotations

import re

EVAL_CALLS = re.compile(
    r"\b(eval|Function|exec|execfile|compile)\s*\(",
)
LITERAL_ONLY = re.compile(
    r"\b(eval|Function|exec)\s*\(\s*['\"][^'\"]*['\"]\s*\)",
)

# --- Safe-pattern exclusions ---
SAFE_COMPILE = re.compile(
    r"\b(?:re\.compile|template\.compile|webpack\.compile|babel\.compile|"
    r"sass\.compile|less\.compile|typescript\.compile|ts\.compile|"
    r"coffeescript\.compile|pug\.compile|handlebars\.compile|"
    r"stylus\.compile|postcss\.compile)\s*\(",
    re.IGNORECASE,
)
COMPILE_LITERAL_ONLY = re.compile(
    r"\bcompile\s*\(\s*['\"][^'\"]*['\"]\s*(?:,\s*['\"][^'\"]*['\"])?\s*\)",
)
JSON_PARSE = re.compile(r"\bJSON\.parse\s*\(")
USER_INPUT = re.compile(
    r"(?:req\.|request\.|params\.|query\.|body\.|args\.|user_input|user_data|form_data)",
    re.IGNORECASE,
)


def detect(source: str) -> float:
    matches = EVAL_CALLS.findall(source)
    if not matches:
        return 0.0

    # Count safe compile calls and subtract them
    safe_compiles = len(SAFE_COMPILE.findall(source))
    literal_evals = len(LITERAL_ONLY.findall(source))
    compile_literals = len(COMPILE_LITERAL_ONLY.findall(source))

    # Count JSON.parse as safe (not really eval)
    json_parses = len(JSON_PARSE.findall(source))

    # Remaining unsafe calls
    safe_count = safe_compiles + literal_evals + compile_literals + json_parses
    unsafe_count = len(matches) - safe_count

    if unsafe_count <= 0:
        return 0.0

    has_user_input = USER_INPUT.search(source)

    # eval/exec/Function with direct user input
    if has_user_input and re.search(
        r"\b(?:eval|exec|execfile)\s*\([^)]*(?:req\.|request\.|body\.|params\.|query\.)",
        source,
    ):
        return 0.9

    # eval/exec with a variable (not a literal)
    if re.search(r"\b(?:eval|exec|execfile)\s*\(\s*\w+\s*\)", source):
        return 0.5

    # Function() constructor with static args
    if re.search(r"\bFunction\s*\(\s*['\"]", source):
        return 0.2

    # Generic unsafe eval/exec usage
    if has_user_input:
        return 0.7

    return 0.3
