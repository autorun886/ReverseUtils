from __future__ import annotations

import argparse
import sys
from pathlib import Path

from api import export_binary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ida-export-cli",
        description="Analyze a binary with idalib and export an offline IDA snapshot.",
    )
    parser.add_argument("INPUT", type=Path, help="binary or IDA database to analyze")
    parser.add_argument("-o", dest="output", type=Path, help="export directory")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = export_binary(args.INPUT, args.output)
    except Exception as exc:
        print(f"ida-export-cli: {exc}", file=sys.stderr)
        return 1
    print(result.output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
