from __future__ import annotations

import re

SPREAD_BODY = re.compile(
    r"(?:\.create|\.update|\.insert|\.findOneAndUpdate|new\s+\w+)\s*\(\s*(?:\.\.\.|Object\.assign|req\.body|request\.body|data|body)",
)
MODEL_CREATE_BODY = re.compile(
    r"(?:Model|Schema|Repository|\.create|\.build|\.new)\s*\(\s*(?:req\.body|request\.body|ctx\.request\.body|params)",
)
UPDATE_WITHOUT_PICK = re.compile(
    r"(?:update|patch|put)\s*.*(?:req\.body|request\.body)",
    re.DOTALL,
)
ROLE_IN_BODY = re.compile(
    r"(?:role|isAdmin|is_admin|admin|permissions|privilege)\s*(?:=|:).*(?:req\.|request\.|body\.|params\.)",
)

# --- Safe-pattern exclusions ---
VALIDATION_LIBS = re.compile(
    r"(?:Joi\.|Yup\.|zod\.|z\.|class-validator|validate\(|@IsString|@IsEmail"
    r"|marshmallow|Schema\(\)|Pydantic|BaseModel|cerberus|Validator\(|ajv\."
    r"|superstruct|io-ts|runtypes|@ValidateNested|ValidationPipe|@Body\(\s*\w+Dto)",
    re.IGNORECASE,
)
FIELD_FILTERING = re.compile(
    r"(?:\.pick\(|\.omit\(|_\.pick|_\.omit|whitelist|allowedFields|permitParams"
    r"|strong_params|permit\(|only\(|pluck\(|select\(|fields\s*=|allowed_fields"
    r"|fillable|guarded|mass_assignment_authorizer|attr_accessible)",
    re.IGNORECASE,
)


def detect(source: str) -> float:
    # If validation libraries are present, much lower risk
    has_validation = bool(VALIDATION_LIBS.search(source))

    # If field filtering is present anywhere in the function, much lower risk
    has_filtering = bool(FIELD_FILTERING.search(source))

    if has_validation and has_filtering:
        return 0.0

    # If field filtering is applied and no direct req.body in model create/update
    # (i.e., body goes through pick/omit first, then a clean variable is used)
    if has_filtering and not re.search(
        r"(?:\.create|\.update|\.insert|\.build|\.new)\s*\(\s*(?:req\.body|request\.body|ctx\.request\.body)",
        source,
    ):
        return 0.0

    best_score = 0.0

    # Direct role/admin from body = very dangerous even with validation
    if ROLE_IN_BODY.search(source):
        if has_validation or has_filtering:
            best_score = max(best_score, 0.4)
        else:
            best_score = max(best_score, 0.8)

    # Model.create(req.body) without validation
    if MODEL_CREATE_BODY.search(source):
        if has_validation or has_filtering:
            best_score = max(best_score, 0.3)
        else:
            best_score = max(best_score, 0.8)

    # Spread/Object.assign with req.body
    if SPREAD_BODY.search(source):
        if has_validation or has_filtering:
            best_score = max(best_score, 0.4)
        else:
            best_score = max(best_score, 0.7)

    # Update with req.body (check within function scope)
    if UPDATE_WITHOUT_PICK.search(source):
        if has_validation or has_filtering:
            best_score = max(best_score, 0.3)
        else:
            best_score = max(best_score, 0.6)

    return best_score
