#!/usr/bin/env python3
"""
Clone MongoDB Kingfisher and combine its provider rule YAML files.

Usage:
  python3 scripts/update_kingfisher_rules.py
  python3 scripts/update_kingfisher_rules.py --check

The generated output is a separate Kingfisher YAML artifact at
assets/kingfisher-rules.yml. It is not converted to gitleaks TOML and is not
wired into scanner loading.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


REPO_URL = "https://github.com/mongodb/kingfisher.git"
RULES_RELATIVE_PATH = Path("crates/kingfisher-rules/data/rules")
OUTPUT_PATH = Path("assets/kingfisher-rules.yml")
DEDUPE_POLICY = "first rule per stable Kingfisher rule id"


@dataclass(frozen=True)
class RuleBlock:
    """A raw Kingfisher rule block normalized for the combined output."""

    rule_id: str
    source_file: str
    body: str


def run_git(args: list[str], cwd: Path | None = None) -> str:
    """Run git and return stdout, failing with stderr context on error."""
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        raise SystemExit("git is required but was not found in PATH")
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        raise SystemExit(f"git {' '.join(args)} failed{detail}") from exc
    return completed.stdout.strip()


def clone_kingfisher(repo_url: str, parent_dir: Path) -> Path:
    """Clone Kingfisher into parent_dir and return the checkout path."""
    checkout = parent_dir / "kingfisher"
    run_git(["clone", "--depth", "1", repo_url, str(checkout)])
    return checkout


def find_rules_list_indent(lines: list[str], path: Path) -> int:
    """Find the indentation used for top-level entries under rules:."""
    for idx, line in enumerate(lines):
        if re.match(r"^rules:\s*$", line):
            for child in lines[idx + 1 :]:
                match = re.match(r"^(\s*)-\s+", child)
                if match:
                    return len(match.group(1))
            raise ValueError(f"{path}: rules list is empty")
    raise ValueError(f"{path}: missing top-level rules: key")


def extract_rule_id(block: list[str], top_indent: int, path: Path, line_no: int) -> str:
    """Extract a rule id from a top-level YAML rule block."""
    item_id = re.compile(rf"^ {{{top_indent}}}-\s*id:\s*(.*?)\s*$")
    nested_id = re.compile(rf"^ {{{top_indent + 2}}}id:\s*(.*?)\s*$")
    for line in block:
        match = item_id.match(line) or nested_id.match(line)
        if match:
            rule_id = match.group(1).strip().strip("\"'")
            if not rule_id:
                raise ValueError(f"{path}:{line_no}: empty rule id")
            return rule_id
    raise ValueError(f"{path}:{line_no}: missing rule id")


def normalize_rule_block(block: list[str], top_indent: int) -> str:
    """Normalize a rule block to two-space top-level list indentation."""
    normalized = []
    prefix = " " * top_indent
    for line in block:
        if line.startswith(prefix):
            normalized.append("  " + line[top_indent:])
        else:
            normalized.append(line)
    return "\n".join(normalized).rstrip()


def parse_rule_file(path: Path) -> list[RuleBlock]:
    """Parse one Kingfisher provider rule file into raw rule blocks."""
    lines = path.read_text(encoding="utf-8").splitlines()
    top_indent = find_rules_list_indent(lines, path)
    rule_start = re.compile(rf"^ {{{top_indent}}}-\s+")
    starts = [idx for idx, line in enumerate(lines) if rule_start.match(line)]
    blocks = []

    for offset, start in enumerate(starts):
        end = starts[offset + 1] if offset + 1 < len(starts) else len(lines)
        block = lines[start:end]
        rule_id = extract_rule_id(block, top_indent, path, start + 1)
        blocks.append(
            RuleBlock(
                rule_id=rule_id,
                source_file=path.name,
                body=normalize_rule_block(block, top_indent),
            )
        )

    return blocks


def collect_rules(rules_dir: Path) -> tuple[list[RuleBlock], list[RuleBlock]]:
    """Collect and deduplicate Kingfisher rules in deterministic path order."""
    if not rules_dir.is_dir():
        raise ValueError(f"{rules_dir}: rules directory not found")

    rules = []
    duplicates = []
    seen_ids = set()

    for path in sorted(rules_dir.glob("*.yml")):
        for block in parse_rule_file(path):
            if block.rule_id in seen_ids:
                duplicates.append(block)
                continue
            seen_ids.add(block.rule_id)
            rules.append(block)

    return rules, duplicates


def render_rules(rules: list[RuleBlock], source_commit: str) -> str:
    """Render the combined Kingfisher rules YAML."""
    header = (
        "# Generated by scripts/update_kingfisher_rules.py; do not edit by hand.\n"
        "# Source: https://github.com/mongodb/kingfisher\n"
        f"# Source path: {RULES_RELATIVE_PATH.as_posix()}\n"
        f"# Source commit: {source_commit}\n"
        f"# Deduplication: {DEDUPE_POLICY}.\n"
        f"# Rule count: {len(rules)}\n"
        "\n"
        "rules:\n"
    )
    body = "\n".join(rule.body for rule in rules)
    return f"{header}{body}\n"


def write_atomic(path: Path, content: str) -> None:
    """Write content to path using os.replace so readers never see a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def load_existing(path: Path) -> str | None:
    """Read an existing output file, or return None when it does not exist."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def build_combined_rules(repo_url: str) -> tuple[str, int, int, str]:
    """Clone Kingfisher and return combined YAML, rule count, duplicate count, commit."""
    with tempfile.TemporaryDirectory(prefix="kingfisher-rules-") as tmp:
        checkout = clone_kingfisher(repo_url, Path(tmp))
        source_commit = run_git(["rev-parse", "HEAD"], cwd=checkout)
        rules_dir = checkout / RULES_RELATIVE_PATH
        rules, duplicates = collect_rules(rules_dir)

        for duplicate in duplicates:
            print(
                f"[WARN] duplicate rule id skipped: {duplicate.rule_id} "
                f"from {duplicate.source_file}",
                file=sys.stderr,
            )

        return render_rules(rules, source_commit), len(rules), len(duplicates), source_commit


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Clone MongoDB Kingfisher, combine provider YAML rules, deduplicate "
            "by rule id, and write assets/kingfisher-rules.yml."
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report whether assets/kingfisher-rules.yml is current without writing",
    )
    return parser.parse_args()


def main() -> int:
    """Run the Kingfisher rules import."""
    args = parse_args()
    output_path = OUTPUT_PATH

    print(f"[INFO] cloning {REPO_URL}")
    content, rule_count, duplicate_count, source_commit = build_combined_rules(REPO_URL)
    existing = load_existing(output_path)

    if args.check:
        if existing == content:
            print(
                f"[OK] {output_path} is current "
                f"({rule_count} rules, source {source_commit})"
            )
            return 0
        print(
            f"[WARN] {output_path} is missing or stale "
            f"({rule_count} current rules, {duplicate_count} duplicate ids skipped)",
            file=sys.stderr,
        )
        return 1

    if existing == content:
        print(
            f"[OK] {output_path} already current "
            f"({rule_count} rules, source {source_commit})"
        )
        return 0

    write_atomic(output_path, content)
    print(
        f"[OK] wrote {output_path} "
        f"({rule_count} rules, {duplicate_count} duplicate ids skipped, "
        f"source {source_commit})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
