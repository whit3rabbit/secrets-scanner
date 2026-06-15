#!/usr/bin/env python3
"""
scripts/generate_fixtures.py
Generates positive test cases (mock secrets) matching the regexes defined in assets/local.toml.
To satisfy the scanner's Aho-Corasick pre-filter, each test case includes a test_content field
that pairs the generated secret with one of the rule's keywords (e.g., "keyword = secret").
"""

import os
import re
import sys
import random
import string
import tomllib
import sre_parse

def generate_from_ast(node_list):
    res = []
    for item in node_list:
        op = item[0]
        args = item[1]
        if op == sre_parse.LITERAL:
            res.append(chr(args))
        elif op == sre_parse.SUBPATTERN:
            res.append(generate_from_ast(args[3]))
        elif op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
            min_val, max_val, child = args
            count = max(min_val, min(max_val, 32))
            for _ in range(count):
                res.append(generate_from_ast(child))
        elif op == sre_parse.IN:
            res.append(generate_from_in(args))
        elif op == sre_parse.BRANCH:
            # Randomly select a branch
            branch = random.choice(args[1])
            res.append(generate_from_ast(branch))
        elif op in (sre_parse.ASSERT, sre_parse.ASSERT_NOT):
            # Zero-width assertions, do not generate characters
            pass
        elif op == sre_parse.AT:
            # Word boundaries or anchors
            pass
        elif op == sre_parse.ANY:
            res.append(random.choice(string.ascii_letters + string.digits))
        elif op == sre_parse.NOT_LITERAL:
            c = chr(args)
            choices = [x for x in string.ascii_letters + string.digits if x != c]
            res.append(random.choice(choices))
        elif op == sre_parse.CATEGORY:
            if args == sre_parse.CATEGORY_DIGIT:
                res.append(random.choice(string.digits))
            else:
                res.append(random.choice(string.ascii_letters + string.digits))
    return "".join(res)

def generate_from_in(choices):
    negate = False
    flat_choices = []
    for op, args in choices:
        if op == sre_parse.NEGATE:
            negate = True
            continue
        if op == sre_parse.LITERAL:
            flat_choices.append(chr(args))
        elif op == sre_parse.RANGE:
            start, end = args
            for val in range(start, end + 1):
                flat_choices.append(chr(val))
        elif op == sre_parse.CATEGORY:
            if args == sre_parse.CATEGORY_SPACE:
                flat_choices.extend(list(string.whitespace))
            elif args == sre_parse.CATEGORY_DIGIT:
                flat_choices.extend(list(string.digits))
    
    if negate:
        pool = string.ascii_letters + string.digits + " =:_\"'\t"
        candidates = [c for c in pool if c not in flat_choices]
        if candidates:
            word_chars = [c for c in candidates if c.isalnum() or c == "_"]
            non_word_chars = [c for c in candidates if not (c.isalnum() or c == "_")]
            if non_word_chars and random.random() < 0.5:
                return random.choice(non_word_chars)
            elif word_chars:
                return random.choice(word_chars)
            else:
                return random.choice(candidates)
        else:
            return "A"
    else:
        if not flat_choices:
            return "A"
        return random.choice(flat_choices)

def main():
    toml_path = "assets/local.toml"
    output_path = "tests/local_rules_fixtures.json"

    if not os.path.exists(toml_path):
        print(f"Error: {toml_path} not found.", file=sys.stderr)
        sys.exit(1)

    print(f"Reading rules from {toml_path}...")
    with open(toml_path, "rb") as f:
        cfg = tomllib.load(f)

    rules = cfg.get("rules", [])
    print(f"Loaded {len(rules)} rules.")

    fixtures = {}
    failed = []

    for r in rules:
        rule_id = r.get("id")
        pat = r.get("regex")
        keywords = r.get("keywords", [])
        if not rule_id or not pat:
            continue

        flags = re.IGNORECASE if "(?i)" in pat else 0
        # Clean regex lookarounds for python re compatibility
        clean_pat = pat.replace("(?<![A-Za-z0-9_])", r"(?<!\w)").replace("(?![A-Za-z0-9_])", r"(?!\w)")

        ok = False
        generated_secret = ""
        for _ in range(100):
            try:
                ast = sre_parse.parse(pat)
                gen = generate_from_ast(ast)
                # Test different padding configurations to satisfy lookarounds
                for candidate in (gen, f" {gen} ", f"{gen}\n"):
                    if re.search(clean_pat, candidate, flags):
                        # Ensure we store the exact matched secret substring
                        match = re.search(clean_pat, candidate, flags)
                        generated_secret = match.group(0)
                        ok = True
                        break
            except Exception:
                pass
            if ok:
                break

        if ok:
            # Build the test content that includes the keyword if present
            if keywords:
                # Use the first keyword, ensuring it is separated from the secret
                test_content = f"{keywords[0]} = {generated_secret}"
            else:
                test_content = generated_secret

            fixtures[rule_id] = {
                "secret": generated_secret,
                "test_content": test_content
            }
        else:
            failed.append(rule_id)

    print(f"Successfully generated fixtures: {len(fixtures)} / {len(rules)}")
    if failed:
        print(f"Failed to generate fixtures for {len(failed)} rules:", file=sys.stderr)
        for rule_id in failed:
            print(f"  - {rule_id}", file=sys.stderr)
        sys.exit(1)

    # Save to JSON
    import json
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(fixtures, f, indent=2)
    print(f"Saved fixtures to {output_path}")

if __name__ == "__main__":
    main()
