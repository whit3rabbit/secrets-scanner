#!/usr/bin/env python3
"""
scripts/import_secrets_patterns_db.py

Download, convert, and deduplicate rules from the mazen160/secrets-patterns-db
YAML database into gitleaks-compatible TOML for use in secrets-scanner.

Usage:
    python3 scripts/import_secrets_patterns_db.py [OPTIONS]

Options:
    --url URL    Override the download URL (default: upstream stable rules)
    --check      Dry-run: report statistics without writing any files
    --merge      Append deduplicated rules to assets/local.toml as well
    -h, --help   Show this help and exit

Output files:
    assets/secrets-patterns-db.yml   Raw downloaded YAML (unmodified)
    assets/secrets-patterns-db.toml  Converted, deduplicated TOML rules
    assets/secrets-patterns-db-dups.json  Duplicate report (JSON)
"""

import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

# ── constants ─────────────────────────────────────────────────────────────────

DEFAULT_URL = (
    "https://raw.githubusercontent.com/mazen160/secrets-patterns-db"
    "/refs/heads/master/db/rules-stable.yml"
)
REPO_ROOT = Path(__file__).parent.parent
ASSETS_DIR = REPO_ROOT / "assets"
YML_OUT = ASSETS_DIR / "secrets-patterns-db.yml"
TOML_OUT = ASSETS_DIR / "secrets-patterns-db.toml"
LOCAL_TOML = ASSETS_DIR / "local.toml"
GITLEAKS_TOML = ASSETS_DIR / "gitleaks.toml"
DUPS_JSON = ASSETS_DIR / "secrets-patterns-db-dups.json"

RULE_ID_PREFIX = "spdb-"

# ── logging ───────────────────────────────────────────────────────────────────


def info(msg: str) -> None:
    """Print an informational message to stdout."""
    print(f"[INFO]  {msg}")


def ok(msg: str) -> None:
    """Print a success message to stdout."""
    print(f"[OK]    {msg}")


def warn(msg: str) -> None:
    """Print a warning message to stderr."""
    print(f"[WARN]  {msg}", file=sys.stderr)


def die(msg: str) -> None:
    """Print an error message and exit with code 1."""
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)


# ── download ──────────────────────────────────────────────────────────────────


def download_text(url: str) -> str:
    """Download *url* and return its text content (UTF-8)."""
    info(f"Fetching: {url}")
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "secrets-scanner-import/1.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        die(f"HTTP {exc.code} fetching {url}: {exc.reason}")
    except urllib.error.URLError as exc:
        die(f"Failed to fetch {url}: {exc.reason}")
    # unreachable — die() always exits, but satisfies type checkers
    raise SystemExit(1)


# ── YAML parser ───────────────────────────────────────────────────────────────


def parse_patterns_yaml(text: str) -> list[dict]:
    """
    Parse the secrets-patterns-db YAML format into a list of pattern dicts.

    Each dict contains the keys ``name``, ``regex``, and ``confidence``.

    Expected structure::

        patterns:
          - pattern:
              name: <name>
              regex: <regex>
              confidence: high | low

    This is a hand-rolled parser intentionally kept dependency-free; it
    handles double-quoted and unquoted scalar values.
    """
    patterns: list[dict] = []
    current: dict = {}

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if stripped == "- pattern:":
            if current:
                patterns.append(current)
            current = {}
            continue

        for key in ("name", "regex", "confidence"):
            prefix = f"      {key}:"
            if line.startswith(prefix):
                val = line[len(prefix):].strip()
                # Strip outer YAML double-quotes and unescape only \\ and \"
                if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
                    val = val[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                elif len(val) >= 2 and val[0] == "'" and val[-1] == "'":
                    val = val[1:-1]
                current[key] = val
                break

    if current:
        patterns.append(current)

    return patterns


# ── existing rule loading ─────────────────────────────────────────────────────


def load_rules_from_toml(path: Path) -> list[dict]:
    """
    Load ``[[rules]]`` blocks from a gitleaks-compatible TOML file.

    Returns an empty list if the file does not exist.
    """
    if not path.exists():
        warn(f"File not found, skipping: {path}")
        return []
    try:
        import tomllib  # stdlib in Python 3.11+
    except ImportError:
        die("Python 3.11+ is required for built-in tomllib support.")
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    return data.get("rules", [])


# ── dedup utilities ───────────────────────────────────────────────────────────

_STRIP_FLAGS_ANCHORS = re.compile(
    r"\(\?[imsxu]+\)"   # inline flags: (?i), (?ms) …
    r"|\(\?-[imsxu]+\)" # negated flags: (?-i) …
    r"|\\[bB]"          # word boundaries
    r"|\^|\$"           # line anchors
)
_COLLAPSE_WS = re.compile(r"\s+")


def normalize_regex(regex: str) -> str:
    """
    Return a normalised form of *regex* for near-duplicate detection.

    Strips inline flags, word-boundary assertions, and anchors; folds case;
    and collapses all whitespace to produce a canonical comparison string.
    """
    r = _STRIP_FLAGS_ANCHORS.sub("", regex)
    r = _COLLAPSE_WS.sub("", r)
    return r.lower()


def build_dedup_index(rules: list[dict]) -> tuple[set[str], set[str]]:
    """
    Build two lookup sets from *rules* for fast duplicate detection.

    Returns:
        ``(exact_set, normalized_set)`` — raw regex strings and their
        normalised counterparts.
    """
    exact: set[str] = set()
    normalized: set[str] = set()
    for rule in rules:
        rx = rule.get("regex", "")
        if rx:
            exact.add(rx)
            normalized.add(normalize_regex(rx))
    return exact, normalized


# ── keyword extraction ────────────────────────────────────────────────────────

_NON_CAP_WORD = re.compile(r"\(\?:([a-zA-Z0-9][a-zA-Z0-9_-]*)\)")
_LITERAL_PREFIX = re.compile(r"^(?:\\b|\(\?i\))?([A-Za-z][A-Za-z0-9_]{2,})")


def extract_keywords(regex: str, name: str) -> list[str]:
    """
    Derive Aho-Corasick keyword hints from *regex* and the rule *name*.

    Priority:
    1. Literal word tokens inside ``(?:word)`` non-capturing groups.
    2. Alphanumeric prefix literal at the start of the pattern.
    3. First meaningful token of the rule name (≥3 chars).
    """
    found = _NON_CAP_WORD.findall(regex)
    if found:
        return [w.lower() for w in found[:2]]

    m = _LITERAL_PREFIX.match(regex)
    if m:
        prefix = m.group(1).lower()
        if len(prefix) >= 3:
            return [prefix]

    token = re.split(r"[\s\-_]+", name.strip())[0].lower()
    token = re.sub(r"[^a-z0-9]", "", token)
    if len(token) >= 3:
        return [token]

    return []


# ── ID generation ─────────────────────────────────────────────────────────────


def name_to_id(name: str, used: set[str]) -> str:
    """
    Convert a pattern *name* to a unique kebab-case rule ID prefixed with
    ``spdb-``.  Appends ``-2``, ``-3``, … to resolve collisions.

    The result is added to *used* before returning.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    base_id = f"{RULE_ID_PREFIX}{slug}"

    candidate = base_id
    i = 2
    while candidate in used:
        candidate = f"{base_id}-{i}"
        i += 1
    used.add(candidate)
    return candidate


# ── TOML formatting ───────────────────────────────────────────────────────────


def _toml_str(value: str) -> str:
    """Format *value* as a TOML basic (double-quoted) string."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _toml_raw_str(value: str) -> str:
    """
    Format *value* as a TOML literal (single-quoted) string.

    Uses triple literal form ``'''…'''`` unless the value contains that
    sequence, falling back to a basic double-quoted string.
    """
    if "'''" not in value:
        return f"'''{value}'''"
    return _toml_str(value)


def format_rule(
    rule_id: str,
    description: str,
    regex: str,
    keywords: list[str],
    confidence: str,
) -> str:
    """Render a single ``[[rules]]`` TOML block as a string."""
    lines: list[str] = []
    if confidence == "low":
        lines.append("# confidence: low (secrets-patterns-db)")
    lines.append("[[rules]]")
    lines.append(f"id          = {_toml_str(rule_id)}")
    lines.append(f"description = {_toml_str(description)}")
    lines.append(f"regex       = {_toml_raw_str(regex)}")
    if keywords:
        kw_list = ", ".join(f'"{k}"' for k in keywords)
        lines.append(f"keywords    = [{kw_list}]")
    return "\n".join(lines)


# ── classification ────────────────────────────────────────────────────────────


def classify_patterns(
    patterns: list[dict],
    exact_set: set[str],
    norm_set: set[str],
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Split *patterns* into three buckets.

    Returns:
        ``(new_patterns, exact_dups, near_dups)``

        - ``new_patterns`` — no match in either set → safe to import
        - ``exact_dups``   — raw regex is already present
        - ``near_dups``    — normalised regex collides (but raw differs)
    """
    new_patterns: list[dict] = []
    exact_dups: list[dict] = []
    near_dups: list[dict] = []

    for p in patterns:
        rx = p.get("regex", "")
        name = p.get("name", "")
        if not rx or not name:
            continue
        if rx in exact_set:
            exact_dups.append(p)
        elif normalize_regex(rx) in norm_set:
            near_dups.append(p)
        else:
            new_patterns.append(p)

    return new_patterns, exact_dups, near_dups


# ── output writing ────────────────────────────────────────────────────────────

_TOML_HEADER = """\
# ═══════════════════════════════════════════════════════════════════════════════
# assets/secrets-patterns-db.toml
#
# Auto-generated by scripts/import_secrets_patterns_db.py
# Source : https://github.com/mazen160/secrets-patterns-db
# Generated : {timestamp}
#
# Rules deduplicated against assets/gitleaks.toml and assets/local.toml.
# IDs are prefixed "spdb-" to avoid collisions with upstream gitleaks rules.
#
# DO NOT EDIT MANUALLY — regenerate with: make import-spdb
# ═══════════════════════════════════════════════════════════════════════════════

title = "secrets-patterns-db imported rules"
"""


def write_output_toml(
    new_patterns: list[dict],
    used_ids: set[str],
    check_only: bool,
) -> list[dict]:
    """
    Convert *new_patterns* to TOML rule dicts and (unless *check_only*)
    write them to :data:`TOML_OUT`.

    Returns the list of fully-formed rule dicts for optional downstream use.
    """
    rule_dicts: list[dict] = []
    blocks: list[str] = []

    for p in new_patterns:
        name = p["name"]
        regex = p["regex"]
        confidence = p.get("confidence", "high")
        keywords = extract_keywords(regex, name)
        rule_id = name_to_id(name, used_ids)
        description = (
            f"Detected {name} (secrets-patterns-db, confidence: {confidence})"
        )
        rule_dicts.append(
            {
                "id": rule_id,
                "description": description,
                "regex": regex,
                "keywords": keywords,
                "confidence": confidence,
            }
        )
        blocks.append(
            format_rule(rule_id, description, regex, keywords, confidence)
        )

    if check_only:
        return rule_dicts

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    content = _TOML_HEADER.format(timestamp=ts) + "\n\n".join(blocks) + "\n"
    TOML_OUT.write_text(content, encoding="utf-8")
    ok(f"Wrote {len(rule_dicts)} rules → {TOML_OUT.relative_to(REPO_ROOT)}")
    return rule_dicts


def write_dup_report(exact_dups: list[dict], near_dups: list[dict]) -> None:
    """Persist the duplicate report to :data:`DUPS_JSON` for review."""
    report = {
        "exact_duplicates": [
            {"name": p["name"], "regex": p["regex"]} for p in exact_dups
        ],
        "near_duplicates": [
            {"name": p["name"], "regex": p["regex"]} for p in near_dups
        ],
    }
    DUPS_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    info(f"Duplicate report → {DUPS_JSON.relative_to(REPO_ROOT)}")


def merge_into_local(rule_dicts: list[dict]) -> None:
    """Append *rule_dicts* as ``[[rules]]`` blocks to :data:`LOCAL_TOML`."""
    if not LOCAL_TOML.exists():
        die(f"Cannot merge: {LOCAL_TOML} not found.")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    chunks: list[str] = [
        "",
        f"# ── Imported from secrets-patterns-db on {ts} ────────────────",
    ]
    for r in rule_dicts:
        chunks.append("")
        chunks.append(
            format_rule(
                r["id"], r["description"], r["regex"],
                r["keywords"], r["confidence"],
            )
        )
    chunks.append("")

    with LOCAL_TOML.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(chunks))
    ok(f"Appended {len(rule_dicts)} rules → {LOCAL_TOML.relative_to(REPO_ROOT)}")


# ── summary ───────────────────────────────────────────────────────────────────


def print_summary(
    total: int,
    new_count: int,
    exact_count: int,
    near_count: int,
    exact_dups: list[dict],
    near_dups: list[dict],
) -> None:
    """Print a human-readable deduplication summary table."""
    skipped = total - new_count - exact_count - near_count
    bar = "─" * 52
    print(f"\n{bar}")
    print("  secrets-patterns-db import summary")
    print(bar)
    print(f"  Total patterns downloaded  : {total:4d}")
    print(f"  New (unique) rules         : {new_count:4d}")
    print(f"  Exact duplicates skipped   : {exact_count:4d}")
    print(f"  Near duplicates skipped    : {near_count:4d}")
    print(f"  Malformed / skipped        : {skipped:4d}")
    print(bar)

    if exact_dups or near_dups:
        print("\nSample duplicates (not imported):")
        for p in exact_dups[:5]:
            print(f"  [exact] {p['name']}")
        for p in near_dups[:5]:
            print(f"  [near]  {p['name']}")
        shown = min(5, len(exact_dups)) + min(5, len(near_dups))
        remaining = len(exact_dups) + len(near_dups) - shown
        if remaining > 0:
            print(f"  … and {remaining} more — see {DUPS_JSON.relative_to(REPO_ROOT)}")
    print()


# ── main ──────────────────────────────────────────────────────────────────────


def main() -> None:
    """Entry point for the import script."""
    parser = argparse.ArgumentParser(
        description="Import and deduplicate rules from secrets-patterns-db.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--url", default=DEFAULT_URL, metavar="URL",
        help="Override the upstream download URL",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Dry-run: report stats without writing any files",
    )
    parser.add_argument(
        "--merge", action="store_true",
        help="Append new rules to assets/local.toml after writing the TOML file",
    )
    args = parser.parse_args()

    # 1. Download raw YAML
    raw_yaml = download_text(args.url)
    if not args.check:
        ASSETS_DIR.mkdir(parents=True, exist_ok=True)
        YML_OUT.write_text(raw_yaml, encoding="utf-8")
        ok(f"Saved raw YAML → {YML_OUT.relative_to(REPO_ROOT)}")

    # 2. Parse upstream patterns
    patterns = parse_patterns_yaml(raw_yaml)
    info(f"Parsed {len(patterns)} patterns from upstream YAML")

    # 3. Load existing rules from both TOML files
    existing: list[dict] = []
    for toml_path in (GITLEAKS_TOML, LOCAL_TOML):
        chunk = load_rules_from_toml(toml_path)
        existing.extend(chunk)
        info(f"Loaded {len(chunk):4d} rules from {toml_path.name}")

    existing_ids: set[str] = {r["id"] for r in existing if r.get("id")}
    info(f"Total existing rules: {len(existing)}")

    # 4. Build dedup index (exact + normalised)
    exact_set, norm_set = build_dedup_index(existing)

    # 5. Classify each upstream pattern
    new_patterns, exact_dups, near_dups = classify_patterns(
        patterns, exact_set, norm_set
    )

    # 6. Convert and write deduplicated rules
    used_ids = existing_ids.copy()
    rule_dicts = write_output_toml(new_patterns, used_ids, check_only=args.check)

    # 7. Write duplicate report JSON
    if not args.check and (exact_dups or near_dups):
        write_dup_report(exact_dups, near_dups)

    # 8. Optionally merge into local.toml
    if args.merge:
        if args.check:
            warn("--merge is ignored in --check mode.")
        elif rule_dicts:
            merge_into_local(rule_dicts)

    # 9. Print summary
    print_summary(
        total=len(patterns),
        new_count=len(new_patterns),
        exact_count=len(exact_dups),
        near_count=len(near_dups),
        exact_dups=exact_dups,
        near_dups=near_dups,
    )

    if args.check:
        info("Dry-run complete. No files were written.")


if __name__ == "__main__":
    main()
