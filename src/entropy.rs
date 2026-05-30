/// Shannon entropy calculation for secret detection.
///
/// High-entropy strings (> ~3.5 bits/byte) are likely real secrets.
/// Low-entropy strings like `password = "changeme"` are filtered out.

/// Default minimum entropy threshold when a rule does not specify one.
pub const DEFAULT_MIN_ENTROPY: f64 = 3.2;

/// Compute Shannon entropy of a byte string.
///
/// Returns bits per byte — real secrets typically score > 3.5,
/// while dictionary words and placeholders score < 3.0.
///
/// # Examples
///
/// ```
/// use secrets_scanner::entropy::shannon_entropy;
///
/// assert!(shannon_entropy("IOSFODNN7EXAMPLE") > 3.0);
/// assert!(shannon_entropy("aaaaaaaaaaaaaaaa") < 2.0);
/// assert_eq!(shannon_entropy(""), 0.0);
/// ```
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_has_zero_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn single_char_repeated_has_zero_entropy() {
        assert_eq!(shannon_entropy("aaaaaaaaaaaaaaaa"), 0.0);
    }

    #[test]
    fn low_entropy_rejects_placeholders() {
        assert!(shannon_entropy("changeme11111111") < DEFAULT_MIN_ENTROPY);
    }

    #[test]
    fn high_entropy_accepts_real_secrets() {
        // Real AWS-style key material
        assert!(shannon_entropy("IOSFODNN7EXAMPLE") > 3.0);
        assert!(
            shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") > DEFAULT_MIN_ENTROPY
        );
    }
}
