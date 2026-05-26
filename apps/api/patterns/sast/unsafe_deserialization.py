from __future__ import annotations

import re

PICKLE_LOAD = re.compile(r"pickle\.loads?\s*\(")
YAML_UNSAFE = re.compile(r"yaml\.load\s*\(")
MARSHAL_LOAD = re.compile(r"marshal\.loads?\s*\(")
SHELVE_OPEN = re.compile(r"shelve\.open\s*\(")
PHP_UNSERIALIZE = re.compile(r"unserialize\s*\(")
JAVA_DESER = re.compile(r"ObjectInputStream")
NODE_SERIALIZE = re.compile(r"node-serialize")
SERIALIZE_JS = re.compile(r"serialize-javascript.*\(\s*\w")

SAFE_YAML = re.compile(r"yaml\.safe_load|Loader\s*=\s*(?:SafeLoader|CSafeLoader|BaseLoader)")
SAFE_YAML_CUSTOM = re.compile(r"Loader\s*=\s*\w+SafeLoader|yaml\.(?:safe_load|CSafeLoader)")

# --- Safe-pattern exclusions ---
USER_INPUT = re.compile(
    r"(?:req\.|request\.|params\.|query\.|body\.|args\.|user_input|user_data|form_data|uploaded|upload)",
    re.IGNORECASE,
)
TRUSTED_INTERNAL = re.compile(
    r"(?:internal|cache|batch|celery|task_result|job_result|worker|queue|redis|memcache"
    r"|session_store|cache_store|_cache|cached|pipeline|serialize_model|dump_state"
    r"|checkpoint|snapshot|backup|migration)",
    re.IGNORECASE,
)


def detect(source: str) -> float:
    has_user_input = bool(USER_INPUT.search(source))
    is_trusted = bool(TRUSTED_INTERNAL.search(source))

    best_score = 0.0

    # pickle.load(s) with user input = extremely dangerous
    if PICKLE_LOAD.search(source):
        if has_user_input:
            return 0.95
        if is_trusted:
            best_score = max(best_score, 0.2)
        else:
            best_score = max(best_score, 0.5)

    # yaml.load without SafeLoader
    if YAML_UNSAFE.search(source):
        if SAFE_YAML.search(source) or SAFE_YAML_CUSTOM.search(source):
            return 0.0  # Using safe loader
        if has_user_input:
            best_score = max(best_score, 0.9)
        elif is_trusted:
            best_score = max(best_score, 0.2)
        else:
            best_score = max(best_score, 0.5)

    # marshal.load
    if MARSHAL_LOAD.search(source):
        if has_user_input:
            best_score = max(best_score, 0.9)
        elif is_trusted:
            best_score = max(best_score, 0.2)
        else:
            best_score = max(best_score, 0.5)

    # shelve.open
    if SHELVE_OPEN.search(source):
        if has_user_input:
            best_score = max(best_score, 0.8)
        elif is_trusted:
            best_score = max(best_score, 0.2)
        else:
            best_score = max(best_score, 0.4)

    # PHP unserialize
    if PHP_UNSERIALIZE.search(source):
        if has_user_input:
            best_score = max(best_score, 0.9)
        else:
            best_score = max(best_score, 0.5)

    # Java ObjectInputStream
    if JAVA_DESER.search(source):
        if has_user_input:
            best_score = max(best_score, 0.9)
        else:
            best_score = max(best_score, 0.5)

    # node-serialize
    if NODE_SERIALIZE.search(source):
        best_score = max(best_score, 0.8)

    # serialize-javascript
    if SERIALIZE_JS.search(source):
        best_score = max(best_score, 0.6)

    return best_score
