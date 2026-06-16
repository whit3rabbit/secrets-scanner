//! Stable fingerprints for findings.
//!
//! New findings use versioned SHA-256 fingerprints for baseline suppression and
//! SARIF `partialFingerprints`. A fingerprint derived from a secret is still an
//! offline guessing target for low-entropy secrets, so generated baselines should
//! be treated as sensitive metadata even though they do not store raw secrets.
//!
//! Setting `SECRETS_SCANNER_FINGERPRINT_KEY` switches every fingerprint to a
//! keyed HMAC-SHA256 (`hmac-sha256:` prefix), which removes that guessing target
//! and makes baselines unlinkable across keys. Changing the key changes all
//! fingerprints, so baselines must be regenerated when it changes.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Read the optional fingerprint key from `SECRETS_SCANNER_FINGERPRINT_KEY`.
///
/// An empty or unset var disables keying (plain SHA-256). Read fresh on each
/// call rather than cached in a `OnceLock`: the binding is embedded in
/// long-lived host processes (the Node binding, a redaction proxy) that may
/// build many scanners and set/rotate the key after the first fingerprint was
/// computed; a process-global cache would silently freeze the key at its first
/// observed value and key later baselines with the wrong (or no) key. The cost
/// is one `getenv` per finding — negligible beside the regex scan that produced
/// the finding, and fingerprints are not computed in the per-line hot loop.
fn current_key() -> Option<Vec<u8>> {
    match std::env::var_os("SECRETS_SCANNER_FINGERPRINT_KEY") {
        Some(v) if !v.is_empty() => Some(v.into_encoded_bytes()),
        _ => None,
    }
}

/// Compute a hex-encoded 64-bit FNV-1a hash over `parts`, inserting a NUL byte
/// between adjacent parts so `["a", "bc"]` and `["ab", "c"]` hash differently.
///
/// The bare-NUL separator is unambiguous ONLY because no non-final part contains
/// a NUL: a NUL in the last part cannot shift bytes across an earlier boundary,
/// but `["a\0b"]` would otherwise collide with `["a", "b"]`. Both call sites hold
/// to this: `finding_fingerprint`'s only NUL-capable part is the trailing
/// `secret`, and `location_fingerprint` hashes only NUL-free strings. A new
/// caller passing a NUL-bearing non-final part must length-prefix instead.
///
/// Legacy helper kept for callers that used the original v1 fingerprint utility.
/// Scanner-generated fingerprints no longer use FNV.
pub fn fnv1a_hex(parts: &[&[u8]]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            hash = fnv_mix(hash, 0);
        }
        for &b in *part {
            hash = fnv_mix(hash, b);
        }
    }
    format!("{hash:016x}")
}

#[inline]
fn fnv_mix(hash: u64, b: u8) -> u64 {
    (hash ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3)
}

/// Compute a finding/location digest over length-prefixed `parts`.
///
/// `None` key → `sha256:<hex>` (unkeyed, the default). `Some(key)` →
/// `hmac-sha256:<hex>` via HMAC-SHA256, which makes fingerprints unlinkable
/// across baselines and removes the offline-guessing target for low-entropy
/// secrets. Both schemes share identical length-prefixed framing, so the only
/// difference is the keyed MAC versus the bare hash. The distinct prefix keeps
/// keyed and unkeyed baselines from cross-matching.
fn fingerprint_digest(key: Option<&[u8]>, parts: &[&[u8]]) -> String {
    match key {
        Some(k) => {
            // HMAC accepts a key of any length, so `new_from_slice` is infallible
            // here; the `expect` documents that contract rather than a reachable
            // error path.
            let mut mac =
                HmacSha256::new_from_slice(k).expect("HMAC-SHA256 accepts a key of any length");
            for part in parts {
                mac.update(&(part.len() as u64).to_le_bytes());
                mac.update(part);
            }
            format!("hmac-sha256:{}", hex::encode(mac.finalize().into_bytes()))
        }
        None => {
            let mut hasher = Sha256::new();
            for part in parts {
                hasher.update((part.len() as u64).to_le_bytes());
                hasher.update(part);
            }
            format!("sha256:{}", hex::encode(hasher.finalize()))
        }
    }
}

fn sha256_fingerprint(parts: &[&[u8]]) -> String {
    fingerprint_digest(current_key().as_deref(), parts)
}

/// Line-tolerant fingerprint of a finding: identifies the same secret across
/// line moves by hashing the rule id, file path, and raw secret bytes. The line
/// number is deliberately excluded so editing lines above a finding does not
/// make it re-surface as "new" against a baseline.
pub fn finding_fingerprint(rule_id: &str, file: &str, secret: &[u8]) -> String {
    sha256_fingerprint(&[
        b"secrets-scanner/finding/v2",
        rule_id.as_bytes(),
        file.as_bytes(),
        secret,
    ])
}

/// Location-based fallback fingerprint for findings that lack a secret-derived
/// [`finding_fingerprint`] (e.g. one deserialized from a pre-fingerprint
/// baseline). Hashes the rule id, repo-relative uri, and byte offsets. Kept here
/// so every finding-hash recipe lives in one module and the SARIF and baseline
/// layers cannot silently diverge.
pub fn location_fingerprint(
    rule_id: &str,
    uri: &str,
    start_offset: usize,
    end_offset: usize,
) -> String {
    let start = start_offset.to_string();
    let end = end_offset.to_string();
    sha256_fingerprint(&[
        b"secrets-scanner/location/v2",
        rule_id.as_bytes(),
        uri.as_bytes(),
        start.as_bytes(),
        end.as_bytes(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separator_disambiguates_parts() {
        assert_ne!(
            fnv1a_hex(&[b"a", b"bc"]),
            fnv1a_hex(&[b"ab", b"c"]),
            "NUL separator must distinguish part boundaries"
        );
    }

    #[test]
    fn finding_fingerprint_is_line_independent_and_secret_sensitive() {
        let a = finding_fingerprint("aws", "src/x.rs", b"AKIA0000000000000000");
        let b = finding_fingerprint("aws", "src/x.rs", b"AKIA0000000000000000");
        let c = finding_fingerprint("aws", "src/x.rs", b"AKIA1111111111111111");
        assert!(a.starts_with("sha256:"));
        assert_eq!(a.len(), "sha256:".len() + 64);
        assert_eq!(a, b, "same inputs must produce same fingerprint");
        assert_ne!(
            a, c,
            "different secrets must produce different fingerprints"
        );
    }

    #[test]
    fn keyed_digest_differs_and_is_prefixed() {
        // Exercises the pure keyed path directly; the env+OnceLock wiring is left
        // out of unit tests to avoid process-global state flakiness.
        let parts: &[&[u8]] = &[b"rule", b"file", b"secret"];
        let unkeyed = fingerprint_digest(None, parts);
        let keyed = fingerprint_digest(Some(b"k1"), parts);
        let keyed_other = fingerprint_digest(Some(b"k2"), parts);
        assert!(unkeyed.starts_with("sha256:"));
        assert!(keyed.starts_with("hmac-sha256:"));
        assert_eq!(keyed.len(), "hmac-sha256:".len() + 64);
        assert_ne!(unkeyed, keyed, "keyed digest must differ from unkeyed");
        assert_ne!(
            keyed, keyed_other,
            "different keys must produce different digests"
        );
        assert_eq!(
            keyed,
            fingerprint_digest(Some(b"k1"), parts),
            "same key must be deterministic"
        );
    }

    #[test]
    fn location_fingerprint_uses_sha256_v2() {
        let fp = location_fingerprint("path-only", "src/config.env", 10, 20);
        assert!(fp.starts_with("sha256:"));
        assert_eq!(fp.len(), "sha256:".len() + 64);
    }
}
