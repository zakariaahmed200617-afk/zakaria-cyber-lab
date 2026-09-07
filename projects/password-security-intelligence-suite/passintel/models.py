from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    penalty: int = 0


@dataclass(frozen=True)
class PolicyResult:
    passed: bool
    violations: tuple[str, ...] = ()


@dataclass(frozen=True)
class AnalysisResult:
    score: int
    rating: str
    length: int
    charset_size: int
    entropy_bits: float
    composition: dict[str, bool]
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    recommendations: tuple[str, ...] = field(default_factory=tuple)
    policy: PolicyResult | None = None
    breach_count: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a serialization-safe result. Plaintext passwords are never stored here."""
        return asdict(self)
