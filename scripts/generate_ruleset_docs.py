#!/usr/bin/env python3
"""Generate Markdown reference pages for manifest-declared rulesets."""

from __future__ import annotations

import argparse
import html
import os
import random
import re
import subprocess
import sys
import tomllib
import warnings
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
MANIFEST_PATH = REPO_ROOT / "assets" / "sources.toml"
DOCS_DIR = REPO_ROOT / "docs" / "rulesets"

sys.path.insert(0, str(SCRIPT_DIR))
from find_duplicate_rules import _example_for  # noqa: E402


def die(message: str) -> None:
    print(f"[ERROR] {message}", file=sys.stderr)
    sys.exit(1)


def info(message: str) -> None:
    print(f"[INFO]  {message}")


def ok(message: str) -> None:
    print(f"[OK]    {message}")


def load_manifest(path: Path) -> dict:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except FileNotFoundError:
        die(f"manifest not found: {path.relative_to(REPO_ROOT)}")
    except tomllib.TOMLDecodeError as exc:
        die(f"failed to parse {path.relative_to(REPO_ROOT)}: {exc}")


def load_rules(path: Path) -> list[dict]:
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError:
        die(f"ruleset not found: {path.relative_to(REPO_ROOT)}")
    except tomllib.TOMLDecodeError as exc:
        die(f"failed to parse {path.relative_to(REPO_ROOT)}: {exc}")
    return data.get("rules", [])


def slugify_source_name(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip().lower()).strip("-")
    return slug or "ruleset"


def display_name(name: str) -> str:
    if name == "spdb":
        return "secrets-patterns-db"
    return name


def markdown_code_span(value: str) -> str:
    if not value:
        return ""
    # We must escape '|' to avoid breaking the markdown table.
    # HTML <code>...</code> tag is used if '|', '<', '>', or '&' is present.
    if "|" in value or "<" in value or ">" in value or "&" in value:
        escaped = html.escape(value, quote=False)
        escaped = escaped.replace("|", "&#124;")
        escaped = escaped.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")
        return f"<code>{escaped}</code>"
    
    # If the value contains backticks, wrap it with double backticks
    if "`" in value:
        max_ticks = 0
        current_run = 0
        for ch in value:
            if ch == '`':
                current_run += 1
                max_ticks = max(max_ticks, current_run)
            else:
                current_run = 0
        ticks = '`' * (max_ticks + 1)
        space = " " if value.startswith("`") or value.endswith("`") else ""
        return f"{ticks}{space}{value}{space}{ticks}"
    
    return f"`{value}`"


def printable_example(value: str) -> str:
    return value.encode("unicode_escape").decode("ascii")


def example_cell(value: str) -> str:
    if not value:
        return ""
    return markdown_code_span(printable_example(value))


def example_for_rule(rule: dict) -> str:
    regex = rule.get("regex")
    if not regex:
        return ""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        example = _example_for(regex)
    return example or ""


def active_rule_ids(source_file: Path, known_ids: set[str]) -> set[str]:
    env = os.environ.copy()
    env["RUST_LOG"] = "error"
    cmd = [
        "cargo",
        "run",
        "--quiet",
        "--bin",
        "secrets-scanner",
        "--",
        "list-rules",
        "--rules",
        str(source_file.relative_to(REPO_ROOT)),
    ]
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        out = (proc.stdout + proc.stderr).strip()
        die(
            "failed to load active rules for "
            f"{source_file.relative_to(REPO_ROOT)}:\n{out}"
        )

    active: set[str] = set()
    ordered_ids = sorted(known_ids, key=len, reverse=True)
    for line in proc.stdout.splitlines():
        for rule_id in ordered_ids:
            if line.startswith(rule_id) and (
                len(line) == len(rule_id) or line[len(rule_id)].isspace()
            ):
                active.add(rule_id)
                break
    return active


def source_doc_path(source: dict) -> Path:
    return DOCS_DIR / f"{slugify_source_name(source.get('name', 'ruleset'))}.md"


def render_rule_cell(rule: dict) -> str:
    rule_id = rule.get("id", "")
    return markdown_code_span(rule_id)


def render_source_doc(source: dict, rules: list[dict], active_ids: set[str]) -> str:
    name = source.get("name", "ruleset")
    title = display_name(name)
    source_file = source.get("file", "")
    raw_count = len(rules)
    active_count = len(active_ids)
    unsupported_count = raw_count - active_count
    default_build = "yes" if source.get("embed") else "no"

    lines = [
        f"# {title} ruleset",
        "",
        "<!-- Generated by scripts/generate_ruleset_docs.py; do not edit by hand. -->",
        "",
        f"- Source file: `{source_file}`",
        f"- Manifest source: `{name}`",
        f"- Priority: `{source.get('priority')}`",
        f"- Default build: `{default_build}`",
        f"- Raw rules: `{raw_count}`",
        f"- Active rules: `{active_count}`",
        f"- Unsupported rules: `{unsupported_count}`",
    ]
    if source.get("update_url"):
        lines.append(f"- Upstream URL: `{source['update_url']}`")
    lines.extend(
        [
            "",
            "Status is computed by loading this source with "
            "`secrets-scanner list-rules --rules`. Active means the current "
            "scanner can compile and load the rule. Unsupported rules remain "
            "listed because they are present in the raw provider file.",
            "",
            "| Rule | Status | Example | Regex |",
            "|---|---|---|---|",
        ]
    )

    for rule in rules:
        rule_id = rule.get("id", "")
        status = "Active" if rule_id in active_ids else "Unsupported"
        lines.append(
            "| "
            + " | ".join(
                [
                    render_rule_cell(rule),
                    status,
                    example_cell(example_for_rule(rule)) or "_Unavailable_",
                    markdown_code_span(rule.get("regex", "")) or "_Unavailable_",
                ]
            )
            + " |"
        )

    lines.append("")
    return "\n".join(lines)


def render_all_docs() -> dict[Path, str]:
    manifest = load_manifest(MANIFEST_PATH)
    rendered: dict[Path, str] = {}
    random.seed(0)

    for source in manifest.get("source", []):
        file_name = source.get("file", "")
        if not file_name.endswith(".toml"):
            info(f"skipping non-TOML source {source.get('name', file_name)}")
            continue
        source_file = REPO_ROOT / file_name
        rules = load_rules(source_file)
        known_ids = {r.get("id", "") for r in rules if r.get("id")}
        info(f"loading active rules for {file_name}")
        active_ids = active_rule_ids(source_file, known_ids)
        rendered[source_doc_path(source)] = render_source_doc(source, rules, active_ids)

    return rendered


def check_docs(rendered: dict[Path, str]) -> int:
    stale = []
    for path, expected in rendered.items():
        try:
            current = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            stale.append(path)
            continue
        if current != expected:
            stale.append(path)

    if stale:
        for path in stale:
            print(
                f"[WARN] stale or missing: {path.relative_to(REPO_ROOT)}",
                file=sys.stderr,
            )
        return 1
    ok("ruleset docs are current")
    return 0


def write_docs(rendered: dict[Path, str]) -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    for path, content in rendered.items():
        path.write_text(content, encoding="utf-8")
        ok(f"wrote {path.relative_to(REPO_ROOT)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare generated docs with committed files without writing",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rendered = render_all_docs()
    if args.check:
        return check_docs(rendered)
    write_docs(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
