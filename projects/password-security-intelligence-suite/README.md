# Password Security Intelligence Suite

A **privacy-first, defensive security** Python toolkit for analyzing password quality without storing the password itself.

It is designed as a portfolio-grade security engineering project rather than a one-file “strength checker”. The suite combines explainable heuristics, policy evaluation, secure generation, optional breach intelligence, machine-readable reporting, tests, and CI.

## Highlights

- 0–100 risk-aware strength score with explainable findings
- Character-set and approximate entropy analysis
- Detects common passwords, repeated characters/substrings, sequences, keyboard walks, dates/years, low diversity, and leetspeak-obfuscated common terms
- Configurable password policy engine
- Cryptographically secure password generator using `secrets`
- Cryptographically secure passphrase generator
- Optional Have I Been Pwned Pwned Passwords lookup using **k-anonymity**: only the first five characters of a SHA-1 hash are transmitted
- JSON reports that **never include the plaintext password**
- Hidden password input via `getpass` to avoid shell history exposure
- Standard-library only: no third-party runtime dependencies
- Automated unit tests and GitHub Actions CI

## Architecture

```text
passintel/
├── __init__.py
├── __main__.py
├── analyzer.py       # orchestration + scoring
├── breach.py         # k-anonymity breach lookup
├── cli.py            # safe command-line interface
├── generator.py      # secure password/passphrase generation
├── models.py         # typed result models
├── patterns.py       # structural pattern detection
├── policy.py         # configurable security policy
└── utils.py          # shared helpers
```

## Quick start

From this project directory:

```bash
python -m passintel analyze
```

The password is requested with hidden input.

Generate a secure password:

```bash
python -m passintel generate --length 24
```

Generate a passphrase:

```bash
python -m passintel passphrase --words 5
```

Analyze and produce redacted JSON:

```bash
python -m passintel analyze --json
```

Optionally check whether a password appears in the Pwned Passwords corpus:

```bash
python -m passintel analyze --breach-check
```

This sends only a 5-character SHA-1 prefix, never the password or full hash. Network metadata still exists, so breach checking is opt-in.

## Scoring model

The score intentionally combines positive signals and penalties. Length and diversity help; known weak structures reduce the result. The score is an **educational estimate**, not a mathematical guarantee of resistance to every cracking strategy.

Strength bands:

| Score | Rating |
|---:|---|
| 0–19 | Very Weak |
| 20–39 | Weak |
| 40–59 | Fair |
| 60–79 | Strong |
| 80–100 | Very Strong |

## Privacy model

The analyzer is local by default. It does not log, save, or return the plaintext password in result objects. Reports expose only derived metadata such as length, score, findings, and entropy estimate.

For breach checks, the suite implements the Pwned Passwords range API model: SHA-1 is calculated locally and only the first 5 hexadecimal characters are sent. The returned suffixes are compared locally.

## Security limitations

- Entropy is an approximation based on observed character pools; human-selected passwords are often more predictable than pure entropy math suggests.
- The built-in common-password set is intentionally small and demonstrative, not a replacement for a massive breached-password corpus.
- Pattern heuristics are explainable and deterministic, but no heuristic detector can model every password cracker.
- A “Very Strong” result does not make password reuse safe. Use unique passwords and a reputable password manager.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Ethical use

This project is for defensive education, password hygiene, and secure-software engineering. Do not collect other people’s credentials or use real production passwords in demos, screenshots, issues, commits, or test fixtures.

## Author

**Zakaria Al-Rawi** — Cybersecurity student and security/automation learner.
