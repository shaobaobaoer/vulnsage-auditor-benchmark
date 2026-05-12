#!/usr/bin/env python3
"""
Fixtures ↔ Examples Sync Guard
==============================

Verify that every fixture in `fixtures/` has a corresponding example JSON in
`examples/` (and optionally vice versa). Designed to be run in CI to prevent
the "fixture added but never invoked in batch" failure mode (R0 root cause —
15/85 missed cases in the post-mortem).

Behavior
--------
- For every `fixtures/<sample-name>/meta.json` that does NOT have
  `excluded: true`, REQUIRE `examples/<sample-name>.json` to exist.
- Optionally (with `--strict-examples`), for every `examples/*.json`,
  REQUIRE the matching fixture to exist.
- Optionally (with `--auto-fix`), generate the missing example JSON files
  using the same template as `generate-examples.sh`.

Exit codes
----------
- 0  : in sync (or auto-fix succeeded)
- 1  : out of sync (orphaned fixtures or examples)
- 2  : usage error

Usage
-----
  python3 scripts/check_fixtures_examples_sync.py
  python3 scripts/check_fixtures_examples_sync.py --strict-examples
  python3 scripts/check_fixtures_examples_sync.py --auto-fix
  python3 scripts/check_fixtures_examples_sync.py --json   # machine-readable output
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BENCHMARK_DIR = SCRIPT_DIR.parent
FIXTURES_DIR = BENCHMARK_DIR / "fixtures"
EXAMPLES_DIR = BENCHMARK_DIR / "examples"


def discover_fixtures() -> dict[str, dict]:
    """Return {sample_name: meta_dict} for every non-excluded fixture."""
    fixtures: dict[str, dict] = {}
    if not FIXTURES_DIR.exists():
        return fixtures
    for child in sorted(FIXTURES_DIR.iterdir()):
        if not child.is_dir():
            continue
        meta_path = child / "meta.json"
        if not meta_path.exists():
            continue
        try:
            with meta_path.open(encoding="utf-8") as f:
                meta = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        if meta.get("excluded", False):
            continue
        fixtures[child.name] = meta
    return fixtures


def discover_examples() -> set[str]:
    """Return {sample_name} for every example JSON (basename without .json)."""
    if not EXAMPLES_DIR.exists():
        return set()
    return {p.stem for p in EXAMPLES_DIR.glob("*.json") if p.is_file()}


def auto_fix_missing(missing: list[tuple[str, dict]]) -> list[str]:
    """Create example JSON files for missing fixtures.

    Returns a list of created file paths.
    """
    created: list[str] = []
    EXAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    for sample_name, meta in missing:
        repo_url = meta.get("repo_url", "")
        vulnerable_ref = meta.get("vulnerable_ref", "")
        desc = meta.get("description") or meta.get("title") or sample_name

        if not repo_url or not vulnerable_ref:
            print(
                f"  SKIP {sample_name}: missing repo_url or vulnerable_ref in meta.json",
                file=sys.stderr,
            )
            continue

        target = f"{repo_url}.git@{vulnerable_ref}"
        out_path = EXAMPLES_DIR / f"{sample_name}.json"
        with out_path.open("w", encoding="utf-8") as f:
            json.dump({"target": target, "description": desc}, f, indent=2, ensure_ascii=False)
            f.write("\n")
        created.append(str(out_path))
        print(f"  CREATED {out_path}")
    return created


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify fixtures/ and examples/ are in sync.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--strict-examples",
        action="store_true",
        help="Also fail when examples/ has entries without matching fixture/.",
    )
    parser.add_argument(
        "--auto-fix",
        action="store_true",
        help="Generate missing example JSON files automatically (uses meta.json).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON report instead of human text.",
    )
    args = parser.parse_args()

    fixtures = discover_fixtures()
    example_names = discover_examples()
    fixture_names = set(fixtures.keys())

    missing_examples = sorted(fixture_names - example_names)  # fixture w/o example
    orphan_examples = sorted(example_names - fixture_names)   # example w/o fixture

    report = {
        "fixtures_total": len(fixture_names),
        "examples_total": len(example_names),
        "missing_examples": missing_examples,
        "orphan_examples": orphan_examples,
        "in_sync": (not missing_examples) and (not orphan_examples or not args.strict_examples),
    }

    # Auto-fix if requested
    if args.auto_fix and missing_examples:
        print("=== Auto-fixing missing examples ===")
        to_fix = [(name, fixtures[name]) for name in missing_examples]
        created = auto_fix_missing(to_fix)
        report["auto_fix_created"] = created
        # Recompute after fix
        example_names = discover_examples()
        missing_examples = sorted(fixture_names - example_names)
        orphan_examples = sorted(example_names - fixture_names)
        report["missing_examples"] = missing_examples
        report["orphan_examples"] = orphan_examples
        report["in_sync"] = (not missing_examples) and (
            not orphan_examples or not args.strict_examples
        )

    # Emit report
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=" * 70)
        print("  Fixtures ↔ Examples Sync Check")
        print("=" * 70)
        print(f"  Fixtures (non-excluded): {report['fixtures_total']}")
        print(f"  Examples:                {report['examples_total']}")
        print()

        if missing_examples:
            print(f"  ❌ {len(missing_examples)} fixtures WITHOUT matching example:")
            for name in missing_examples:
                print(f"     - {name}")
            print()
            print("  Hint: run with --auto-fix to generate the missing example JSONs.")
        else:
            print("  ✅ Every fixture has a matching example.")

        if orphan_examples:
            print()
            sev = "❌" if args.strict_examples else "⚠️ "
            print(f"  {sev} {len(orphan_examples)} examples WITHOUT matching fixture:")
            for name in orphan_examples:
                print(f"     - {name}")
            if not args.strict_examples:
                print("  (Pass --strict-examples to treat this as a failure.)")

        print()
        if report["in_sync"]:
            print("  ✅ IN SYNC")
        else:
            print("  ❌ OUT OF SYNC")

    return 0 if report["in_sync"] else 1


if __name__ == "__main__":
    sys.exit(main())
