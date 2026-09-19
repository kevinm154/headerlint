"""Command-line entry point for headerlint."""

from __future__ import annotations

import argparse
import json
import sys

from .linter import lint


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="headerlint",
        description="Lint a block of raw HTTP headers and report findings by line number.",
    )
    parser.add_argument("files", nargs="+", help="header file(s) to lint, or '-' for stdin")
    parser.add_argument(
        "--lenient",
        action="store_true",
        help="check protocol correctness only; skip deprecated-header and "
             "missing-recommended-header findings",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    args = parser.parse_args(argv)

    had_error = False
    results: list[dict[str, object]] = []
    for path in args.files:
        try:
            text = _read(path)
        except OSError as exc:
            print(f"{path}: {exc.strerror}", file=sys.stderr)
            had_error = True
            continue

        findings = lint(text, lenient=args.lenient)
        if any(f.severity == "error" for f in findings):
            had_error = True

        if args.format == "json":
            results.append({
                "file": path,
                "findings": [f.to_dict() for f in findings],
            })
            continue

        if not findings:
            continue
        if len(args.files) > 1:
            print(f"{path}:")
        for finding in findings:
            print(finding)

    if args.format == "json":
        print(json.dumps(results, indent=2))

    return 1 if had_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
