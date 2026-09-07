from __future__ import annotations

import argparse
import getpass
import json
from typing import Sequence

from .analyzer import analyze_password
from .generator import generate_passphrase, generate_password
from .policy import PasswordPolicy


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passintel",
        description="Privacy-first password security intelligence toolkit",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a password using hidden input")
    analyze.add_argument("--breach-check", action="store_true", help="Opt in to a k-anonymity breach lookup")
    analyze.add_argument("--json", action="store_true", help="Print a redacted machine-readable report")
    analyze.add_argument("--min-length", type=int, default=14, help="Policy minimum length (default: 14)")

    generate = sub.add_parser("generate", help="Generate a cryptographically secure password")
    generate.add_argument("--length", type=int, default=24)
    generate.add_argument("--no-symbols", action="store_true")

    phrase = sub.add_parser("passphrase", help="Generate a cryptographically secure passphrase")
    phrase.add_argument("--words", type=int, default=5)
    phrase.add_argument("--separator", default="-")

    return parser


def _print_human(result) -> None:
    print("\nPassword Security Intelligence Report")
    print("=" * 37)
    print(f"Score:          {result.score}/100")
    print(f"Rating:         {result.rating}")
    print(f"Length:         {result.length}")
    print(f"Charset size:   {result.charset_size}")
    print(f"Entropy approx: {result.entropy_bits:.2f} bits")
    print(f"Policy:         {'PASS' if result.policy and result.policy.passed else 'FAIL'}")
    if result.breach_count is not None:
        print(f"Breach count:   {result.breach_count:,}")

    if result.findings:
        print("\nFindings:")
        for finding in result.findings:
            print(f"  [{finding.severity.upper():8}] {finding.message}")
    else:
        print("\nFindings: no obvious weak structural patterns detected.")

    print("\nRecommendations:")
    for tip in result.recommendations:
        print(f"  - {tip}")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    if args.command == "generate":
        print(generate_password(args.length, symbols=not args.no_symbols))
        return 0

    if args.command == "passphrase":
        print(generate_passphrase(args.words, separator=args.separator))
        return 0

    if args.command == "analyze":
        if args.min_length < 8 or args.min_length > 128:
            raise SystemExit("--min-length must be between 8 and 128")
        password = getpass.getpass("Password (hidden): ")
        policy = PasswordPolicy(min_length=args.min_length)
        result = analyze_password(password, policy=policy, breach_check=args.breach_check)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        else:
            _print_human(result)
        return 0

    return 2
