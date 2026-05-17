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


def detect(source: str) -> bool:
    if WEAK_HASH.search(source) and re.search(r"(?:password|token|secret|session)", source, re.IGNORECASE):
        return True
    if WEAK_CIPHER.search(source):
        return True
    if ECB_MODE.search(source):
        return True
    if STATIC_IV.search(source):
        return True
    if MATH_RANDOM_CRYPTO.search(source):
        return True
    if NO_SALT_HASH.search(source):
        return True
    return False
