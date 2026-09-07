from __future__ import annotations

import secrets
import string

WORDS = (
    "amber", "atlas", "aurora", "binary", "cipher", "comet", "delta", "ember",
    "falcon", "forest", "galaxy", "harbor", "ion", "jungle", "kernel", "lantern",
    "matrix", "nebula", "onyx", "orbit", "phoenix", "pixel", "quartz", "radar",
    "river", "rocket", "saffron", "signal", "tiger", "vector", "violet", "zenith",
)


def generate_password(length: int = 24, *, symbols: bool = True) -> str:
    if length < 12:
        raise ValueError("length must be at least 12")
    alphabet = string.ascii_letters + string.digits + (string.punctuation if symbols else "")
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if symbols:
        required.append(secrets.choice(string.punctuation))
    required.extend(secrets.choice(alphabet) for _ in range(length - len(required)))
    # Shuffle with SystemRandom, which is backed by OS cryptographic randomness.
    secrets.SystemRandom().shuffle(required)
    return "".join(required)


def generate_passphrase(words: int = 5, separator: str = "-") -> str:
    if words < 4:
        raise ValueError("use at least 4 words")
    chosen = [secrets.choice(WORDS) for _ in range(words)]
    # Add a small random numeric component so generated examples are not dictionary-only.
    chosen.append(f"{secrets.randbelow(900) + 100}")
    return separator.join(chosen)
