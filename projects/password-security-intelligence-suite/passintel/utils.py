from __future__ import annotations

import math
import string
import unicodedata


def normalize_text(value: str) -> str:
    return unicodedata.normalize("NFKC", value)


def character_pool_size(password: str) -> int:
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if any(not c.isascii() for c in password):
        pool += 100
    if any(c.isspace() for c in password):
        pool += 1
    return pool


def naive_entropy_bits(password: str) -> float:
    pool = character_pool_size(password)
    if not password or pool <= 1:
        return 0.0
    return round(len(password) * math.log2(pool), 2)


def clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))
