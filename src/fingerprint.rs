//! Stable, dependency-free fingerprints for findings.
//!
//! Uses 64-bit FNV-1a so the lean default build needs no crypto-hash dependency.
//! These fingerprints are for deduplication and tracking (baseline suppression,
//! SARIF `partialFingerprints`), NOT a security primitive: FNV is not collision-
//! resistant, and a fingerprint derived from a secret is a weak (non-reversible
//! but brute-forceable) identifier, the same trade-off detect-secrets makes when
//! it stores hashed secrets in a baseline.

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
/// Do NOT change this scheme casually: its output is persisted in baseline files
/// and SARIF `partialFingerprints`, so any change invalidates every committed
/// baseline (findings re-surface as "new") and breaks fingerprint continuity.
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

/// Line-tolerant fingerprint of a finding: identifies the same secret across
/// line moves by hashing the rule id, file path, and raw secret bytes. The line
/// number is deliberately excluded so editing lines above a finding does not
/// make it re-surface as "new" against a baseline.
pub fn finding_fingerprint(rule_id: &str, file: &str, secret: &[u8]) -> String {
    fnv1a_hex(&[rule_id.as_bytes(), file.as_bytes(), secret])
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
    fnv1a_hex(&[
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
        assert_eq!(a, b, "same inputs must produce same fingerprint");
        assert_ne!(
            a, c,
            "different secrets must produce different fingerprints"
        );
    }
}
