#!/usr/bin/env python3
"""GuardScan CLI — deterministic detectors + optional grounded LLM explanations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

from src.scanner import scan_path, scan_source


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardscan",
        description="Scan Solidity source with deterministic detectors and grounded LLM explanations.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Solidity file to scan (omit to read source from --stdin)",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read Solidity source from stdin",
    )
    parser.add_argument(
        "--no-explain",
        action="store_true",
        help="Skip LLM / mock explanation layer",
    )
    parser.add_argument(
        "--mock-llm",
        action="store_true",
        help="Force mock explanations even if OPENROUTER_API_KEY is set",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    args = build_parser().parse_args(argv)

    explain = not args.no_explain
    use_mock = True if args.mock_llm else None

    if args.stdin or args.path is None:
        if args.path is not None and not args.stdin:
            target = Path(args.path)
            if not target.exists():
                print(f"error: file not found: {target}", file=sys.stderr)
                return 2
            report = scan_path(target, explain=explain, use_mock_llm=use_mock)
        else:
            source = sys.stdin.read()
            if not source.strip():
                print("error: empty source on stdin", file=sys.stderr)
                return 2
            report = scan_source(
                source, file_label="<stdin>", explain=explain, use_mock_llm=use_mock
            )
    else:
        target = Path(args.path)
        if not target.exists():
            print(f"error: file not found: {target}", file=sys.stderr)
            return 2
        report = scan_path(target, explain=explain, use_mock_llm=use_mock)

    indent = 2 if args.pretty else None
    print(json.dumps(report, indent=indent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
