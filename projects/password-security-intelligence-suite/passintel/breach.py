from __future__ import annotations

import hashlib
import urllib.error
import urllib.request

RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


class BreachLookupError(RuntimeError):
    pass


def pwned_count(password: str, timeout: float = 5.0) -> int:
    """Return known breach count using HIBP Pwned Passwords k-anonymity.

    Only the first five SHA-1 hex characters are transmitted. The plaintext
    password and full hash remain local.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(
        RANGE_URL.format(prefix=prefix),
        headers={"User-Agent": "passintel/1.0", "Add-Padding": "true"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BreachLookupError("Breach service is unavailable.") from exc

    for line in payload.splitlines():
        try:
            remote_suffix, count = line.split(":", 1)
        except ValueError:
            continue
        if remote_suffix.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0
