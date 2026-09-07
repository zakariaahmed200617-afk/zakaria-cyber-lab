from __future__ import annotations

from .breach import BreachLookupError, pwned_count
from .models import AnalysisResult, Finding
from .patterns import detect_patterns
from .policy import PasswordPolicy
from .utils import character_pool_size, clamp, naive_entropy_bits, normalize_text


def _rating(score: int) -> str:
    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Fair"
    if score < 80:
        return "Strong"
    return "Very Strong"


def _recommendations(password: str, findings: tuple[Finding, ...], policy: PasswordPolicy) -> tuple[str, ...]:
    tips: list[str] = []
    if len(password) < 14:
        tips.append("Prefer 14+ characters; longer unique passwords are usually safer.")
    if any(f.code in {"common_password", "sequential", "keyboard_walk", "repeated_substring"} for f in findings):
        tips.append("Avoid common words, keyboard walks, sequences, and repeated structures.")
    if len(set(password)) < max(6, len(password) // 3):
        tips.append("Increase character diversity and reduce repetition.")
    result = policy.evaluate(password)
    tips.extend(result.violations)
    tips.append("Use a unique password for every account and store it in a reputable password manager.")
    # Preserve order while removing duplicates.
    return tuple(dict.fromkeys(tips))


def analyze_password(
    password: str,
    *,
    policy: PasswordPolicy | None = None,
    breach_check: bool = False,
) -> AnalysisResult:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    password = normalize_text(password)
    policy = policy or PasswordPolicy()

    composition = {
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digits": any(c.isdigit() for c in password),
        "symbols": any(not c.isalnum() and not c.isspace() for c in password),
        "unicode": any(not c.isascii() for c in password),
    }
    pool = character_pool_size(password)
    entropy = naive_entropy_bits(password)
    findings = list(detect_patterns(password))

    # Positive signals: length, broad character pool, and entropy ceiling.
    length_points = min(45, len(password) * 3)
    diversity_points = sum((6, 6, 6, 7)[i] for i, key in enumerate(("lowercase", "uppercase", "digits", "symbols")) if composition[key])
    entropy_points = min(30, int(entropy / 4))
    raw = min(100, length_points + diversity_points + entropy_points)

    # Direct penalties for predictable structures.
    raw -= sum(f.penalty for f in findings)
    if len(password) < 8:
        raw -= 25
    elif len(password) < 12:
        raw -= 12

    policy_result = policy.evaluate(password)
    if not policy_result.passed:
        raw -= min(20, len(policy_result.violations) * 4)

    breach_count: int | None = None
    if breach_check and password:
        try:
            breach_count = pwned_count(password)
            if breach_count > 0:
                findings.append(Finding("known_breach", "critical", f"Appears in the breach corpus {breach_count:,} time(s).", 50))
                raw -= 50
        except BreachLookupError:
            findings.append(Finding("breach_lookup_unavailable", "info", "Breach lookup could not be completed.", 0))

    score = clamp(raw)
    return AnalysisResult(
        score=score,
        rating=_rating(score),
        length=len(password),
        charset_size=pool,
        entropy_bits=entropy,
        composition=composition,
        findings=tuple(findings),
        recommendations=_recommendations(password, tuple(findings), policy),
        policy=policy_result,
        breach_count=breach_count,
    )
