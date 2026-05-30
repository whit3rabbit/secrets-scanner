The pipeline
```
File bytes
   │
   ▼
[memchr SIMD]  ← rejects files with no relevant byte classes at all
   │
   ▼
[Aho-Corasick] ← single O(n) pass, finds ALL prefix hits simultaneously
   │
   ▼
[Entropy check] ← rejects "password = changeme", keeps high-randomness strings
   │
   ▼
[Regex]        ← validates structure on a tiny 120-char window only
   │
   ▼
Finding { file, line, matched (redacted), entropy }
```
Key design decisions

AhoCorasick is built once, shared across threads — it's Send + Sync so rayon can use it from every worker without cloning.
Regex only runs on a 120-char window, never the full file. This is why regex is fast here despite being the "slow" layer — it barely does any work.
memchr is the outermost gate — it uses AVX2/SSE2 under the hood to scan for key bytes at near-RAM-bandwidth speed, rejecting whole files before AC even runs.
rayon::par_iter gives you work-stealing parallelism across all CPU cores with zero boilerplate — scanning 10k files uses all your cores automatically.


## Database

Pull rules from:

- CLI should be able to download rules from a URL
https://raw.githubusercontent.com/gitleaks/gitleaks/refs/heads/master/config/gitleaks.toml

- We should maintain our own custom rules in same format for compatibility with gitleaks. (TOML Format)
- After downloading merge into one rule set
- We shold be able to parse that one rule set


## SQLite vs TOML for Regex Rules in Rust

For **loading into memory**, the comparison looks like this:

### Cold Read (disk → memory)

| Method | Speed | Why |
|---|---|---|
| TOML file | **Faster** | Single sequential read + parse; no query overhead |
| SQLite | Slower | Database engine init, page parsing, B-tree traversal |

### Already-in-Memory Lookup

| Method | Speed | Why |
|---|---|---|
| `HashMap<String, Regex>` | **Fastest** | O(1) hash lookup |
| `Vec<(String, Regex)>` | Fast | O(n) linear scan, but cache-friendly for small sets |
| SQLite in-memory (`:memory:`) | Slowest | SQL parsing + query planner overhead per lookup |

---

## Fastest Approach for Rust

**Load from TOML at startup → compile regexes → store in a `HashMap`.**

```toml
# rules.toml
[rules]
email = "^[\\w.+-]+@[\\w-]+\\.[\\w.]+$"
phone = "^\\+?[1-9]\\d{1,14}$"
zip   = "^\\d{5}(-\\d{4})?$"
```

```rust
use std::collections::HashMap;
use regex::Regex;
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    rules: HashMap<String, String>,
}

struct RuleEngine {
    patterns: HashMap<String, Regex>,
}

impl RuleEngine {
    fn load(path: &str) -> Self {
        let content = std::fs::read_to_string(path).unwrap();
        let config: Config = toml::from_str(&content).unwrap();

        let patterns = config.rules
            .into_iter()
            .map(|(name, pattern)| {
                let re = Regex::new(&pattern).expect("Invalid regex");
                (name, re)
            })
            .collect();

        Self { patterns }
    }

    fn matches(&self, rule: &str, input: &str) -> Option<bool> {
        self.patterns.get(rule).map(|re| re.is_match(input))
    }
}
```

---

## When SQLite *Would* Make Sense

Use SQLite if you need:
- **Dynamic updates** at runtime (add/remove rules without restart)
- **Large rule sets** (thousands) where you only load a subset at a time
- **Metadata** alongside rules (priority, tags, owner, enabled flag)
- **Concurrent writers** from multiple processes

---

## Summary Recommendation

| Scenario | Use |
|---|---|
| Rules are static / change with deploys | **TOML → HashMap\<String, Regex\>** |
| Rules are dynamic / admin-editable | SQLite → load subset into HashMap on demand |
| Sub-millisecond lookup after load | **Compiled `Regex` in HashMap** — the file format doesn't matter once in memory |

The bottleneck in regex workflows is almost never the lookup — it's the **`Regex::new()` compilation cost**. Compile once at startup, reuse forever.