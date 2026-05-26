from __future__ import annotations

import re

DANGEROUS_CALLS = re.compile(
    r"\b(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen"
    r"|child_process\.exec|child_process\.execSync"
    r"|execSync|spawnSync)\s*\(",
)
SHELL_TRUE = re.compile(r"shell\s*=\s*True")
VARIABLE_IN_CALL = re.compile(
    r"(?:os\.system|os\.popen|child_process\.exec|execSync)\s*\([^)]*(?:\+|f['\"]|\$\{|\%s)",
)
USER_INPUT = re.compile(
    r"(?:req\.|request\.|params\.|query\.|body\.|args\.|user_input|user_data|form_data|sys\.argv)",
    re.IGNORECASE,
)

# --- Safe-pattern exclusions ---
# subprocess.run/call with list args (no shell interpretation)
SUBPROCESS_LIST_ARGS = re.compile(
    r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*\[",
)
# Commands with only constant strings
CONSTANT_COMMAND = re.compile(
    r"(?:os\.system|os\.popen|subprocess\.run|subprocess\.call)\s*\(\s*['\"][^'\"]*['\"]\s*\)",
)
# shlex.quote sanitized input
SHLEX_QUOTE = re.compile(
    r"shlex\.quote|pipes\.quote|escapeshellarg|shellescape",
    re.IGNORECASE,
)


def detect(source: str) -> float:
    has_dangerous = DANGEROUS_CALLS.search(source)
    if not has_dangerous:
        return 0.0

    # subprocess.run([...]) with list args and no shell=True is safe
    if SUBPROCESS_LIST_ARGS.search(source) and not SHELL_TRUE.search(source):
        # If this is the only subprocess usage, it's safe
        if not VARIABLE_IN_CALL.search(source) and not re.search(
            r"os\.(?:system|popen)\s*\(", source
        ):
            return 0.0

    # Only constant strings in the command call
    if CONSTANT_COMMAND.search(source) and not VARIABLE_IN_CALL.search(source):
        return 0.0

    # shlex.quote sanitization present
    if SHLEX_QUOTE.search(source):
        return 0.0

    has_user_input = USER_INPUT.search(source)

    # os.system/os.popen with f-string/concat and user input
    if VARIABLE_IN_CALL.search(source) and has_user_input:
        return 0.95

    # os.system/os.popen with f-string/concat but unclear input source
    if VARIABLE_IN_CALL.search(source):
        return 0.7

    # subprocess with shell=True but constant command string
    if SHELL_TRUE.search(source) and CONSTANT_COMMAND.search(source):
        return 0.6

    # subprocess with shell=True and variable
    if SHELL_TRUE.search(source):
        if has_user_input:
            return 0.85
        return 0.6

    # Generic dangerous call with user input
    if has_user_input:
        return 0.5

    return 0.2
