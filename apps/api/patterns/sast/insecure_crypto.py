from __future__ import annotations

import re

WEAK_HASH = re.compile(
    r"(?:md5|sha1|MD5|SHA1|createHash\s*\(\s*['\"](?:md5|sha1)['\"])",
)
WEAK_CIPHER = re.compile(
    r"(?:DES|RC4|RC2|Blowfish|createCipher\s*\(\s*['\"](?:des|rc4|aes-128-ecb)['\"])",
)
ECB_MODE = re.compile(
    r"(?:ECB|ecb|AES\.MODE_ECB|aes-\d+-ecb)",
)
STATIC_IV = re.compile(
    r"(?:iv|IV|nonce)\s*(?:=|:)\s*(?:['\"][0-9a-fA-F]+['\"]|Buffer\.from|b['\"]|bytes\()",
)
MATH_RANDOM_CRYPTO = re.compile(
    r"Math\.random\s*\(\s*\).*(?:token|key|secret|salt|nonce|password|session|csrf)",
)
NO_SALT_HASH = re.compile(
    r"(?:hashSync|hash)\s*\(\s*(?:password|pass)\s*[,\)](?!.*salt)",
)

# --- Safe-pattern exclusions ---
# MD5/SHA1 used for non-security purposes (checksums, etags, cache keys)
CHECKSUM_USAGE = re.compile(
    r"(?:checksum|etag|cache[_-]?key|content[_-]?hash|file[_-]?hash|digest|fingerprint|hash[_-]?key"
    r"|integrity|md5sum|shasum|hex[_-]?digest)",
    re.IGNORECASE,
)
PASSWORD_CONTEXT = re.compile(
    r"(?:password|passwd|pwd|credential|secret|token|auth|session|login|user)",
    re.IGNORECASE,
)
SENSITIVE_DATA_CONTEXT = re.compile(
    r"(?:password|passwd|pwd|credential|secret|token|auth|session|private[_-]?key|signing)",
    re.IGNORECASE,
)
BCRYPT_AUTO_SALT = re.compile(
    r"bcrypt\.(?:hashSync|hash|genSalt|compare)",
    re.IGNORECASE,
)
RANDOM_BYTES_IV = re.compile(
    r"(?:crypto\.randomBytes|os\.urandom|secrets\.token_bytes|random_bytes)\s*\(",
)


def detect(source: str) -> float:
    best_score = 0.0

    # ECB mode with sensitive data is very dangerous
    if ECB_MODE.search(source):
        if SENSITIVE_DATA_CONTEXT.search(source):
            return 0.9
        best_score = max(best_score, 0.5)

    # Weak hash (MD5/SHA1)
    if WEAK_HASH.search(source):
        # Exclude bcrypt (auto-salted, safe)
        if BCRYPT_AUTO_SALT.search(source):
            pass  # bcrypt is safe, don't flag
        elif PASSWORD_CONTEXT.search(source) and not CHECKSUM_USAGE.search(source):
            # MD5/SHA1 on passwords = bad
            best_score = max(best_score, 0.7)
        elif CHECKSUM_USAGE.search(source):
            # MD5 for checksums/etags/cache = low concern
            best_score = max(best_score, 0.3)
        else:
            # MD5 on non-sensitive, non-checksum data
            best_score = max(best_score, 0.3)

    # Weak cipher (DES, RC4, etc.)
    if WEAK_CIPHER.search(source):
        best_score = max(best_score, 0.7)

    # Static IV, but exclude crypto.randomBytes for IV generation
    if STATIC_IV.search(source):
        if RANDOM_BYTES_IV.search(source):
            pass  # randomBytes is used for IV, likely safe
        else:
            best_score = max(best_score, 0.6)

    # Math.random() for crypto purposes
    if MATH_RANDOM_CRYPTO.search(source):
        best_score = max(best_score, 0.8)

    # hash without salt
    if NO_SALT_HASH.search(source):
        if BCRYPT_AUTO_SALT.search(source):
            pass  # bcrypt auto-salts
        else:
            best_score = max(best_score, 0.6)

    return best_score
