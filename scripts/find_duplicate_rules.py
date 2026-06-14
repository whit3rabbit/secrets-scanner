#!/usr/bin/env python3
"""scripts/find_duplicate_rules.py — advisory duplicate-rule finder.

Surfaces likely-duplicate rules across every source declared in the manifest
(assets/sources.toml) using two complementary signals. Both are ADVISORY: this
script NEVER edits or drops rules — it writes a report for a human to review.
The deterministic, safe dedup (id collisions and detection-equivalent exact-regex
duplicates) is done in Rust at merge time; this tool catches the fuzzier cases:

  1. Name/keyword fuzzy clusters (rapidfuzz token_set_ratio): groups rules whose
     id/description/keywords are similar, e.g. the several "openai" rules spread
     across gitleaks, local, and secrets-patterns-db.

  2. Behavioral co-fire: generate an example secret from each rule's regex, then
     group rules whose regexes match each other's examples. This catches rules
     with *different* regexes that nonetheless detect the same secret string.

Usage:
    python3 scripts/find_duplicate_rules.py \
        --manifest assets/sources.toml --out target/dup-report.md --json target/dup-report.json
"""

import argparse
import json
import os
import re
import sys
import tomllib
from collections import defaultdict

# Reuse the regex example generator from the fixtures script.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sre_parse  # noqa: E402  (stdlib, used with generate_from_ast)
from generate_fixtures import generate_from_ast  # noqa: E402

DEFAULT_MANIFEST = "assets/sources.toml"
DEFAULT_THRESHOLD = 90


# ── union-find ────────────────────────────────────────────────────────────────
class UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def groups_from_uf(uf, rules, min_size=2):
    buckets = defaultdict(list)
    for i in range(len(rules)):
        buckets[uf.find(i)].append(i)
    out = []
    for members in buckets.values():
        if len(members) >= min_size:
            out.append([rules[i] for i in members])
    # Largest, most interesting clusters first.
    out.sort(key=len, reverse=True)
    return out


# ── loading ───────────────────────────────────────────────────────────────────
def load_sources(manifest_path):
    """Load every TOML source's rules from the manifest. Skips non-TOML sources
    (e.g. kingfisher YAML) and missing files with a warning."""
    with open(manifest_path, "rb") as f:
        manifest = tomllib.load(f)
    rules = []
    for src in manifest.get("source", []):
        path = src.get("file", "")
        name = src.get("name", path)
        if not path.endswith(".toml"):
            print(f"[dup] skipping non-TOML source '{name}' ({path})", file=sys.stderr)
            continue
        if not os.path.exists(path):
            print(f"[dup] skipping missing source '{name}' ({path})", file=sys.stderr)
            continue
        with open(path, "rb") as fh:
            cfg = tomllib.load(fh)
        for r in cfg.get("rules", []):
            rid = r.get("id")
            if not rid:
                continue
            rules.append(
                {
                    "source": name,
                    "id": rid,
                    "regex": r.get("regex"),
                    "keywords": [k.lower() for k in r.get("keywords", [])],
                    "description": r.get("description", "") or "",
                }
            )
    return rules


# ── signal 1: cross-source vendor clusters ────────────────────────────────────
# Generic words that don't identify the vendor/service a rule targets. Stripping
# these leaves the distinctive stem (e.g. "openai", "github", "stripe").
_STEM_STOPWORDS = {
    "api", "apikey", "key", "keys", "token", "tokens", "secret", "secrets",
    "access", "accesskey", "client", "server", "password", "passwd", "auth",
    "oauth", "personal", "project", "bot", "id", "credential", "credentials",
    "private", "public", "prod", "production", "test", "sandbox", "service",
    "services", "app", "application", "user", "registration", "integration",
    "webhook", "temporary", "session", "bearer", "refresh", "signing",
    "signature", "cloud", "config", "account", "management", "live", "stable",
    "spdb", "kingfisher", "v1", "v2", "v3",
}


def _vendor_stem(rule):
    """Distinctive vendor/service stem of a rule id (source prefix and generic
    words removed). Returns None if nothing distinctive remains."""
    ident = rule["id"].lower()
    for sep in "-_.":
        ident = ident.replace(sep, " ")
    toks = [t for t in ident.split() if t and t not in _STEM_STOPWORDS and not t.isdigit()]
    return toks[0] if toks else None


def vendor_clusters(rules, threshold):
    """Group rules by vendor stem, then report only clusters that span MORE THAN
    ONE source — those are the actionable cross-source duplicate candidates
    (e.g. an `openai` rule in gitleaks, local, and secrets-patterns-db). Same-
    source vendor groups (e.g. buildkite's many distinct real tokens) are not
    duplicates and are intentionally omitted.

    rapidfuzz, when available, additionally merges near-identical stems
    (e.g. `openai`/`open-ai`); otherwise exact stems are used.
    """
    stems = [_vendor_stem(r) for r in rules]
    idx_by_stem = defaultdict(list)
    for i, stem in enumerate(stems):
        if stem:
            idx_by_stem[stem].append(i)

    # Optionally fold near-identical stems together (short strings → low blowup).
    canon = {s: s for s in idx_by_stem}
    try:
        from rapidfuzz import fuzz

        uniq = list(idx_by_stem)
        for a in range(len(uniq)):
            for b in range(a + 1, len(uniq)):
                if fuzz.ratio(uniq[a], uniq[b]) >= max(threshold, 92):
                    canon[uniq[b]] = canon[uniq[a]]
    except ImportError:
        print(
            "[dup] rapidfuzz not installed; using exact vendor stems "
            "(pip install rapidfuzz for fuzzy stem merging).",
            file=sys.stderr,
        )

    merged = defaultdict(list)
    for stem, members in idx_by_stem.items():
        merged[canon[stem]].extend(members)

    clusters = []
    for members in merged.values():
        sources = {rules[i]["source"] for i in members}
        if len(members) >= 2 and len(sources) >= 2:
            clusters.append([rules[i] for i in members])
    clusters.sort(key=len, reverse=True)
    return clusters


# ── signal 2: behavioral co-fire ──────────────────────────────────────────────
def _compile_py(regex):
    """Compile a rule regex under Python's `re`, cleaning the look-around forms
    used by the local rules so they parse (mirrors generate_fixtures)."""
    if not regex:
        return None
    flags = re.IGNORECASE if "(?i)" in regex else 0
    clean = regex.replace("(?<![A-Za-z0-9_])", r"(?<!\w)").replace(
        "(?![A-Za-z0-9_])", r"(?!\w)"
    )
    try:
        return re.compile(clean, flags)
    except re.error:
        return None


def _example_for(regex):
    if not regex:
        return None
    try:
        return generate_from_ast(sre_parse.parse(regex))
    except Exception:
        return None


def behavioral_clusters(rules):
    """Group rules whose regexes BIDIRECTIONALLY match each other's generated
    examples. Bidirectionality matters: a broad pattern (e.g. generic JWT/hex)
    will match a narrow rule's example one-way, but the narrow rule won't match
    the broad example back — so requiring both directions avoids collapsing every
    JWT-shaped rule into one giant false cluster, while still catching genuinely
    interchangeable rules."""
    compiled = [_compile_py(r["regex"]) for r in rules]
    examples = [_example_for(r["regex"]) for r in rules]
    cands = [(ex, f" {ex} ", f"{ex}\n") if ex else None for ex in examples]

    def matches(rule_idx, example_idx):
        rx = compiled[rule_idx]
        c = cands[example_idx]
        return rx is not None and c is not None and any(rx.search(x) for x in c)

    uf = UnionFind(len(rules))
    for i in range(len(rules)):
        if cands[i] is None:
            continue
        for j in range(i + 1, len(rules)):
            if cands[j] is None:
                continue
            if matches(j, i) and matches(i, j):
                uf.union(i, j)
    return groups_from_uf(uf, rules)


# ── reporting ─────────────────────────────────────────────────────────────────
def cluster_to_dict(cluster):
    return [
        {"source": r["source"], "id": r["id"], "description": r["description"]}
        for r in cluster
    ]


def write_markdown(path, name_clusters, behav_clusters, total_rules):
    lines = ["# Duplicate-rule report (advisory)", ""]
    lines.append(f"Scanned **{total_rules}** rules across manifest sources.")
    lines.append("")
    lines.append(
        "These are CANDIDATES for human review only. Nothing was changed. "
        "Safe dedup (id collisions, detection-equivalent exact-regex) already "
        "happens deterministically at merge time."
    )

    def section(title, clusters):
        lines.append("")
        lines.append(f"## {title} ({len(clusters)} cluster(s))")
        if not clusters:
            lines.append("")
            lines.append("_None found._")
            return
        for n, cluster in enumerate(clusters, 1):
            lines.append("")
            lines.append(f"### Cluster {n} ({len(cluster)} rules)")
            for r in cluster:
                desc = f" — {r['description']}" if r["description"] else ""
                lines.append(f"- `{r['id']}` ({r['source']}){desc}")

    section("Cross-source vendor clusters", name_clusters)
    section("Behavioral co-fire clusters", behav_clusters)
    lines.append("")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(description="Advisory duplicate-rule finder.")
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST)
    ap.add_argument("--out", default="target/dup-report.md", help="Markdown report path")
    ap.add_argument("--json", default="target/dup-report.json", help="JSON report path")
    ap.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                    help="rapidfuzz token_set_ratio threshold (0-100)")
    ap.add_argument("--no-fuzzy", action="store_true", help="skip name/keyword clustering")
    ap.add_argument("--no-behavioral", action="store_true", help="skip behavioral co-fire")
    args = ap.parse_args()

    if not os.path.exists(args.manifest):
        print(f"Error: manifest {args.manifest} not found.", file=sys.stderr)
        sys.exit(1)

    rules = load_sources(args.manifest)
    print(f"[dup] loaded {len(rules)} rules from manifest sources")

    name_clusters = [] if args.no_fuzzy else vendor_clusters(rules, args.threshold)
    behav_clusters = [] if args.no_behavioral else behavioral_clusters(rules)

    print(f"[dup] cross-source vendor clusters: {len(name_clusters)}")
    print(f"[dup] behavioral co-fire clusters: {len(behav_clusters)}")

    report = {
        "total_rules": len(rules),
        "name_clusters": [cluster_to_dict(c) for c in name_clusters],
        "behavioral_clusters": [cluster_to_dict(c) for c in behav_clusters],
    }
    os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    write_markdown(args.out, name_clusters, behav_clusters, len(rules))
    print(f"[dup] wrote {args.out} and {args.json}")


if __name__ == "__main__":
    main()
