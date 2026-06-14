#!/usr/bin/env python3
"""scripts/convert_kingfisher_rules.py

Convert the MongoDB Kingfisher rule database (assets/kingfisher-rules.yml) into a
gitleaks-compatible TOML ruleset (assets/kingfisher-rules.toml) that the build
pipeline can embed.

Kingfisher rules carry several features with no gitleaks/TOML home
(pattern_requirements, validation, depends_on_rule); those are dropped. The core
detection fields (id, name, pattern, min_entropy) map directly. visible:false
helper rules — broad/low-entropy patterns that only exist to feed composite HTTP
validation — are skipped: standalone they are high-noise.

Because the converted ruleset is embedded in the *lean* default build, we keep it
small with two safety nets:

  1. Behavioral dedup (the same co-fire signal as find_duplicate_rules.py): drop a
     Kingfisher rule when an already-embedded gitleaks/local rule already detects
     its example secret. Matching is BIDIRECTIONAL on purpose — a one-directional
     test lets a broad gitleaks pattern (generic-api-key / high-entropy) swallow
     every vendor-specific rule. Pass --aggressive for one-directional.
  2. Rust-regex validation: emit only patterns the scanner's regex engine accepts.
     After generating, the script runs the `validate-rules` subcommand, drops any
     rule whose detection regex fails to compile (look-around only warns), and
     regenerates until clean. (Rust `regex` != Python `re`, so this is the
     authoritative check.)

Determinism: generate_from_ast() is randomized, so we seed RNG to keep the
committed output (and its dedup decisions) reproducible across runs.

Usage:
    python3 scripts/convert_kingfisher_rules.py [OPTIONS]

Options:
    --check          Dry-run: report the count breakdown, write nothing.
    --aggressive     One-directional dedup (existing matches Kingfisher example).
    --no-validate    Skip the Rust validate-and-drop pass (faster; unsafe for embed).
    --validate-cmd C Command prefix for validation
                     (default: "cargo run --quiet --bin secrets-scanner -- validate-rules").
    -h, --help       Show this help and exit.

Output files:
    assets/kingfisher-rules.toml        Converted, deduplicated TOML rules.
    assets/kingfisher-rules-dups.json   Drop report (behavioral dedup + invalid regex).
"""

import argparse
import json
import os
import random
import re
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml  # PyYAML; see scripts/requirements-dev.txt

# Reuse the example generator and the lookaround-tolerant compile/example helpers
# from the sibling scripts rather than reimplementing them.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generate_fixtures import generate_from_ast  # noqa: E402  (also imported by find_duplicate_rules)
from find_duplicate_rules import _compile_py, _example_for, _vendor_stem  # noqa: E402
from import_secrets_patterns_db import (  # noqa: E402
    load_rules_from_toml,
    extract_keywords,
    _toml_str,
    _toml_raw_str,
)

REPO_ROOT = Path(__file__).parent.parent
ASSETS_DIR = REPO_ROOT / "assets"
YML_IN = ASSETS_DIR / "kingfisher-rules.yml"
TOML_OUT = ASSETS_DIR / "kingfisher-rules.toml"
DUPS_JSON = ASSETS_DIR / "kingfisher-rules-dups.json"
GITLEAKS_TOML = ASSETS_DIR / "gitleaks.toml"
LOCAL_TOML = ASSETS_DIR / "local.toml"

DEFAULT_VALIDATE_CMD = "cargo run --quiet --bin secrets-scanner -- validate-rules"
# Matches the validator's per-rule error from src/rules/validation.rs.
_INVALID_RE = re.compile(r"rule '([^']+)' has invalid detection regex")


# ── logging ────────────────────────────────────────────────────────────────────
def info(msg: str) -> None:
    print(f"[INFO]  {msg}")


def ok(msg: str) -> None:
    print(f"[OK]    {msg}")


def warn(msg: str) -> None:
    print(f"[WARN]  {msg}", file=sys.stderr)


def die(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)


# ── conversion ─────────────────────────────────────────────────────────────────
def _count_capturing_groups(pattern: str) -> int:
    """Number of capturing groups in *pattern*. Uses a lookaround-tolerant Python
    compile; falls back to 0 when the pattern cannot be parsed (TOML still works,
    the whole match becomes the secret)."""
    rx = _compile_py(pattern)
    return rx.groups if rx is not None else 0


def convert_rules(raw_rules: list[dict]) -> tuple[list[dict], int, int]:
    """Map Kingfisher YAML rules to gitleaks rule dicts.

    Returns ``(rules, skipped_invisible, skipped_malformed)``. A rule dict has
    keys: id, description, regex, keywords, entropy (optional), secret_group
    (optional).
    """
    rules: list[dict] = []
    skipped_invisible = 0
    skipped_malformed = 0

    for r in raw_rules:
        if r.get("visible") is False:
            skipped_invisible += 1
            continue

        rid = r.get("id")
        pattern = r.get("pattern")
        name = r.get("name") or rid or ""
        if not rid or not pattern:
            skipped_malformed += 1
            continue

        confidence = r.get("confidence", "unknown")
        description = f"Detected {name} (kingfisher, confidence: {confidence})"

        # Keyword for the Aho-Corasick prefilter. Kingfisher ids are namespaced by
        # vendor (kingfisher.<vendor>.<n>) and the pattern keys on that same vendor
        # literal, so the id stem is the most reliable hint; fall back to the
        # regex/name extractor used by the spdb importer.
        keywords: list[str] = []
        stem = _vendor_stem({"id": rid})
        if stem:
            keywords = [stem]
        else:
            keywords = extract_keywords(pattern, name)

        rule = {
            "id": rid,
            "description": description,
            "regex": pattern,
            "keywords": keywords,
        }

        min_entropy = r.get("min_entropy")
        if isinstance(min_entropy, (int, float)):
            rule["entropy"] = float(min_entropy)

        # Kingfisher's convention is that capture group 1 is the secret. Point
        # secretGroup at it so entropy gating and reporting target the secret, not
        # the surrounding context the pattern matched.
        if _count_capturing_groups(pattern) >= 1:
            rule["secret_group"] = 1

        rules.append(rule)

    return rules, skipped_invisible, skipped_malformed


# ── behavioral dedup ───────────────────────────────────────────────────────────
def _cand(example):
    """Padding variants of an example for matching (mirrors find_duplicate_rules)."""
    if not example:
        return None
    return (example, f" {example} ", f"{example}\n")


def dedup_against_existing(
    rules: list[dict], existing: list[dict], aggressive: bool
) -> tuple[list[dict], list[dict]]:
    """Drop Kingfisher rules already covered by an *existing* (gitleaks/local) rule.

    Returns ``(kept, dropped)`` where each dropped entry records the matched
    existing rule. Fail-open: rules whose example/regex cannot be generated or
    compiled are kept.
    """
    ex_compiled = [_compile_py(e.get("regex")) for e in existing]
    ex_cand = [_cand(_example_for(e.get("regex"))) for e in existing]

    kept: list[dict] = []
    dropped: list[dict] = []

    for k in rules:
        k_rx = _compile_py(k["regex"])
        k_cand = _cand(_example_for(k["regex"]))
        matched = None
        if k_cand is not None:
            for e, e_rx, e_c in zip(existing, ex_compiled, ex_cand):
                if e_c is None or e_rx is None:
                    continue
                # existing rule fires on the Kingfisher example?
                fwd = any(e_rx.search(x) for x in k_cand)
                if not fwd:
                    continue
                if aggressive:
                    matched = e
                    break
                # bidirectional: Kingfisher rule fires on the existing example too?
                if k_rx is not None and any(k_rx.search(x) for x in e_c):
                    matched = e
                    break
        if matched is None:
            kept.append(k)
        else:
            dropped.append(
                {
                    "id": k["id"],
                    "matched_id": matched.get("id"),
                    "matched_source": matched.get("source"),
                }
            )

    return kept, dropped


# ── TOML rendering ─────────────────────────────────────────────────────────────
def render_rule(rule: dict) -> str:
    """Render one ``[[rules]]`` TOML block."""
    lines = ["[[rules]]"]
    lines.append(f"id          = {_toml_str(rule['id'])}")
    lines.append(f"description = {_toml_str(rule['description'])}")
    lines.append(f"regex       = {_toml_raw_str(rule['regex'])}")
    if rule.get("keywords"):
        kw = ", ".join(f'"{k}"' for k in rule["keywords"])
        lines.append(f"keywords    = [{kw}]")
    if "entropy" in rule:
        lines.append(f"entropy     = {rule['entropy']}")
    if "secret_group" in rule:
        lines.append(f"secretGroup = {rule['secret_group']}")
    return "\n".join(lines)


_HEADER = """\
# ═══════════════════════════════════════════════════════════════════════════════
# assets/kingfisher-rules.toml
#
# Auto-generated by scripts/convert_kingfisher_rules.py from assets/kingfisher-rules.yml
# Source : https://github.com/mongodb/kingfisher
# Generated : {timestamp}
#
# Kingfisher features without a TOML home (pattern_requirements, validation,
# depends_on_rule, references, examples) are dropped. visible:false helper rules
# are skipped. Rules already covered by gitleaks/local are removed by behavioral
# dedup. IDs keep their "kingfisher." namespace.
#
# Breakdown: {raw} raw -> -{invisible} visible:false -> -{deduped} dedup -> -{invalid} invalid-regex -> {kept} kept.
#
# DO NOT EDIT MANUALLY — regenerate with: make convert-kingfisher
# ═══════════════════════════════════════════════════════════════════════════════

title = "kingfisher imported rules"
"""


def render_toml(rules: list[dict], counts: dict) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = "\n\n".join(render_rule(r) for r in rules)
    return _HEADER.format(timestamp=ts, **counts) + "\n" + body + "\n"


# ── Rust-regex validation pass ─────────────────────────────────────────────────
def find_invalid_rule_ids(rules: list[dict], counts: dict, validate_cmd: str) -> set[str]:
    """Write *rules* to a temp TOML, run the Rust validator, and return the set of
    rule ids whose detection regex the engine rejects (non-look-around errors)."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".toml", delete=False, encoding="utf-8"
    ) as tf:
        tf.write(render_toml(rules, counts))
        tmp_path = tf.name
    try:
        proc = subprocess.run(
            shlex.split(validate_cmd) + [tmp_path],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        out = proc.stdout + proc.stderr
        return set(_INVALID_RE.findall(out))
    finally:
        os.unlink(tmp_path)


def validate_and_drop(
    rules: list[dict], counts: dict, validate_cmd: str
) -> tuple[list[dict], list[str]]:
    """Iteratively drop rules the Rust validator rejects until it is clean.

    Returns ``(clean_rules, dropped_ids)``.
    """
    dropped: list[str] = []
    current = rules
    for _ in range(5):  # convergence guard; one or two passes is typical
        bad = find_invalid_rule_ids(current, counts, validate_cmd)
        if not bad:
            return current, dropped
        info(f"[validate] dropping {len(bad)} rule(s) the regex engine rejects")
        dropped.extend(sorted(bad))
        current = [r for r in current if r["id"] not in bad]
    warn("validation did not converge after 5 passes; emitting current set")
    return current, dropped


# ── main ───────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert Kingfisher YAML rules to gitleaks-compatible TOML.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--check", action="store_true", help="Dry-run; write nothing.")
    parser.add_argument(
        "--aggressive", action="store_true",
        help="One-directional dedup (more dropping, riskier).",
    )
    parser.add_argument(
        "--no-validate", action="store_true",
        help="Skip the Rust validate-and-drop pass.",
    )
    parser.add_argument("--validate-cmd", default=DEFAULT_VALIDATE_CMD)
    args = parser.parse_args()

    # Deterministic dedup: generate_from_ast() draws from the global RNG.
    random.seed(0)

    if not YML_IN.exists():
        die(f"{YML_IN} not found. Run scripts/update_kingfisher_rules.py first.")

    info(f"Reading {YML_IN.relative_to(REPO_ROOT)}")
    data = yaml.safe_load(YML_IN.read_text(encoding="utf-8")) or {}
    raw_rules = data.get("rules", [])
    info(f"Parsed {len(raw_rules)} Kingfisher rules")

    rules, skipped_invisible, skipped_malformed = convert_rules(raw_rules)
    info(
        f"Mapped {len(rules)} rules "
        f"(skipped {skipped_invisible} visible:false, {skipped_malformed} malformed)"
    )

    # Dedup against the higher-priority embedded sources.
    existing: list[dict] = []
    for path in (GITLEAKS_TOML, LOCAL_TOML):
        src = "gitleaks" if path is GITLEAKS_TOML else "local"
        for r in load_rules_from_toml(path):
            r = dict(r)
            r["source"] = src
            existing.append(r)
    info(f"Loaded {len(existing)} existing rules (gitleaks + local) for dedup")

    kept, deduped = dedup_against_existing(rules, existing, args.aggressive)
    info(f"Behavioral dedup dropped {len(deduped)} rule(s); {len(kept)} remain")

    invalid_ids: list[str] = []
    if not args.no_validate and not args.check:
        kept, invalid_ids = validate_and_drop(
            kept,
            {
                "raw": len(raw_rules),
                "invisible": skipped_invisible,
                "deduped": len(deduped),
                "invalid": 0,
                "kept": len(kept),
            },
            args.validate_cmd,
        )
        if invalid_ids:
            info(f"Validation dropped {len(invalid_ids)} rule(s) with unsupported regex")

    counts = {
        "raw": len(raw_rules),
        "invisible": skipped_invisible,
        "deduped": len(deduped),
        "invalid": len(invalid_ids),
        "kept": len(kept),
    }

    # ── summary ──
    bar = "─" * 56
    print(f"\n{bar}")
    print("  kingfisher conversion summary")
    print(bar)
    print(f"  Raw Kingfisher rules        : {len(raw_rules):4d}")
    print(f"  Skipped visible:false       : {skipped_invisible:4d}")
    print(f"  Skipped malformed           : {skipped_malformed:4d}")
    print(f"  Behavioral-dedup dropped    : {len(deduped):4d}")
    print(f"  Invalid-regex dropped       : {len(invalid_ids):4d}")
    print(f"  Kept (written)              : {len(kept):4d}")
    print(bar)

    if args.check:
        info("Dry-run complete. No files were written.")
        return

    TOML_OUT.write_text(render_toml(kept, counts), encoding="utf-8")
    ok(f"Wrote {len(kept)} rules → {TOML_OUT.relative_to(REPO_ROOT)}")

    DUPS_JSON.write_text(
        json.dumps(
            {
                "counts": counts,
                "behavioral_dedup": deduped,
                "invalid_regex": invalid_ids,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    info(f"Drop report → {DUPS_JSON.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
