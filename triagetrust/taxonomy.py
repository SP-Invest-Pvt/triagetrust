"""Normalised finding categories shared by every ingester, triager and report."""
from __future__ import annotations

import re
from typing import Optional

CATEGORIES: dict[str, dict] = {
    "sqli":         {"cwe": 89,  "name": "SQL injection"},
    "xss":          {"cwe": 79,  "name": "Cross-site scripting"},
    "cmdi":         {"cwe": 78,  "name": "OS command injection"},
    "pathtraver":   {"cwe": 22,  "name": "Path traversal"},
    "ldapi":        {"cwe": 90,  "name": "LDAP injection"},
    "xpathi":       {"cwe": 643, "name": "XPath injection"},
    "weakrand":     {"cwe": 330, "name": "Weak randomness"},
    "hash":         {"cwe": 328, "name": "Weak hash"},
    "crypto":       {"cwe": 327, "name": "Weak cryptography"},
    "securecookie": {"cwe": 614, "name": "Cookie without Secure flag"},
    "trustbound":   {"cwe": 501, "name": "Trust boundary violation"},
    "other":        {"cwe": None, "name": "Other"},
}

INJECTION = {"sqli", "xss", "cmdi", "pathtraver", "ldapi", "xpathi", "trustbound"}

_CWE_TO_CAT = {v["cwe"]: k for k, v in CATEGORIES.items() if v["cwe"]}
_CWE_TO_CAT.update({564: "sqli", 80: "xss", 83: "xss", 77: "cmdi", 23: "pathtraver", 36: "pathtraver",
                    338: "weakrand", 916: "hash", 326: "crypto", 1004: "securecookie"})

_KEYWORDS = [
    (r"sql", "sqli"), (r"xss|cross.?site.?script", "xss"), (r"command|cmd|os.?injection|exec", "cmdi"),
    (r"path.?trav|directory.?trav|file.?disclosure", "pathtraver"), (r"ldap", "ldapi"), (r"xpath", "xpathi"),
    (r"random", "weakrand"), (r"hash|digest|md5|sha1", "hash"),
    (r"crypt|cipher|des_|ecb|padding|static_iv|risky", "crypto"),
    (r"cookie", "securecookie"), (r"trust.?bound", "trustbound"),
]


def category_for(cwe: Optional[int] = None, rule: str = "") -> str:
    if cwe and cwe in _CWE_TO_CAT:
        return _CWE_TO_CAT[cwe]
    r = rule.lower()
    for rx, cat in _KEYWORDS:
        if re.search(rx, r):
            return cat
    return "other"


def cwe_for(category: str) -> Optional[int]:
    return CATEGORIES.get(category, CATEGORIES["other"])["cwe"]


def display(category: str) -> str:
    return CATEGORIES.get(category, {"name": category})["name"]
