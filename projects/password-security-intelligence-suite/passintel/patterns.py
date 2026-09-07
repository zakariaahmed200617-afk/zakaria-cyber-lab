from __future__ import annotations

import re
from collections import Counter

from .models import Finding

COMMON_PASSWORDS = {
    "123456", "12345678", "123456789", "password", "password1", "qwerty",
    "qwerty123", "admin", "admin123", "letmein", "welcome", "iloveyou",
    "abc123", "111111", "000000", "dragon", "monkey", "football",
    "passw0rd", "p@ssword", "zaq12wsx", "1q2w3e4r", "qwertyuiop",
}

KEYBOARD_ROWS = (
    "1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm",
)

SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
)

LEET_TABLE = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"})


def _contains_run(value: str, source: str, minimum: int = 4) -> bool:
    low = value.lower()
    rev = source[::-1]
    for size in range(minimum, min(len(low), 10) + 1):
        for i in range(len(source) - size + 1):
            piece = source[i:i + size]
            if piece in low or piece in low[::-1] or piece in rev and piece in low:
                return True
    return False


def _repeated_substring(password: str) -> bool:
    n = len(password)
    for size in range(1, n // 2 + 1):
        if n % size == 0:
            unit = password[:size]
            if unit * (n // size) == password and n // size >= 2:
                return True
    return False


def detect_patterns(password: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    low = password.lower()
    leet = low.translate(LEET_TABLE)

    if low in COMMON_PASSWORDS or leet in COMMON_PASSWORDS:
        findings.append(Finding("common_password", "critical", "Matches a common-password pattern.", 45))

    if len(password) >= 4 and len(set(password)) == 1:
        findings.append(Finding("single_char_repeat", "critical", "Uses only one repeated character.", 45))
    elif _repeated_substring(password):
        findings.append(Finding("repeated_substring", "high", "Contains a repeated substring pattern.", 24))

    if any(_contains_run(password, seq) for seq in SEQUENCES):
        findings.append(Finding("sequential", "high", "Contains a predictable ascending/descending sequence.", 20))

    if any(_contains_run(password, row) for row in KEYBOARD_ROWS):
        findings.append(Finding("keyboard_walk", "high", "Contains a keyboard-walk pattern.", 20))

    if re.search(r"(?:19|20)\d{2}", password):
        findings.append(Finding("year_pattern", "medium", "Contains a year-like pattern.", 8))

    if re.search(r"(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)?\d{2}", password):
        findings.append(Finding("date_pattern", "medium", "Contains a date-like pattern.", 12))

    if password:
        counts = Counter(password)
        most = counts.most_common(1)[0][1]
        if most / len(password) >= 0.5 and len(password) >= 6:
            findings.append(Finding("low_distribution", "medium", "One character dominates at least half the password.", 10))

    return tuple(findings)
