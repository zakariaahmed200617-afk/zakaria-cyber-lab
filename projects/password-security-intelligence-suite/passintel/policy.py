from __future__ import annotations

from dataclasses import dataclass

from .models import PolicyResult


@dataclass(frozen=True)
class PasswordPolicy:
    min_length: int = 14
    require_lower: bool = True
    require_upper: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    max_length: int = 256

    def evaluate(self, password: str) -> PolicyResult:
        violations: list[str] = []
        if len(password) < self.min_length:
            violations.append(f"Use at least {self.min_length} characters.")
        if len(password) > self.max_length:
            violations.append(f"Use no more than {self.max_length} characters for this policy.")
        if self.require_lower and not any(c.islower() for c in password):
            violations.append("Add a lowercase letter.")
        if self.require_upper and not any(c.isupper() for c in password):
            violations.append("Add an uppercase letter.")
        if self.require_digit and not any(c.isdigit() for c in password):
            violations.append("Add a digit.")
        if self.require_symbol and not any(not c.isalnum() and not c.isspace() for c in password):
            violations.append("Add a symbol.")
        return PolicyResult(passed=not violations, violations=tuple(violations))
