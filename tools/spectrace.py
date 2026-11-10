"""Check that every rule and invariant of spec/SPEC.md is covered.

A rule counts as covered if a conformance vector names it in ``rules``, or if the docstring
of a ``test_*`` function in ``tests/`` names it (a stray mention elsewhere does not count).

Usage: python tools/spectrace.py [--root DIR] [--allow-uncovered]
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

DEFINITION = re.compile(r"(?m)^(?:- )?\*\*(SG-(?:R-[A-Z]+-[0-9]{2}|I-[0-9]{2}))\*\*")
RULE_ID = re.compile(r"SG-(?:R-[A-Z]+-[0-9]{2}|I-[0-9]{2})")


def defined_ids(root: Path) -> set[str]:
    text = (root / "spec" / "SPEC.md").read_text(encoding="utf-8")
    ids = DEFINITION.findall(text)
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise SystemExit(f"duplicate definitions: {sorted(duplicates)}")
    return set(ids)


def ids_from_vectors(root: Path) -> set[str]:
    manifest = json.loads((root / "conformance" / "manifest.json").read_text(encoding="utf-8"))
    return {rule for vector in manifest["vectors"] for rule in vector["rules"]}


def ids_from_tests(root: Path) -> set[str]:
    covered: set[str] = set()
    for path in sorted((root / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                covered.update(RULE_ID.findall(ast.get_docstring(node) or ""))
    return covered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--allow-uncovered", action="store_true")
    args = parser.parse_args(argv)

    defined = defined_ids(args.root)
    covered = ids_from_vectors(args.root) | ids_from_tests(args.root)
    missing = sorted(defined - covered)
    unknown = sorted(covered - defined)
    covered_count = len(defined) - len(missing)
    print(f"defined: {len(defined)}, covered: {covered_count}, uncovered: {len(missing)}")
    for rule in missing:
        print("uncovered:", rule)
    for rule in unknown:
        print("names a rule the spec does not define:", rule)
    return 1 if (missing and not args.allow_uncovered) or unknown else 0


if __name__ == "__main__":
    sys.exit(main())
