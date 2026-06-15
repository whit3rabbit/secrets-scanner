//! rules/validation/helpers.rs — Regex compilation and escaping helpers.

const REGEX_SIZE_LIMIT: usize = 100 * 1024 * 1024;

/// Helper to compile a regex pattern using the scanner's standard builder.
///
/// Valid Rust regex syntax is compiled unchanged. For compatibility with loose
/// upstream rules, this falls back to escaping unescaped literal braces only when
/// the original compile error is brace-related.
pub fn compile_regex(pattern: &str) -> Result<regex::Regex, regex::Error> {
    match build_regex(pattern) {
        Ok(regex) => Ok(regex),
        Err(original) => {
            let escaped = escape_literal_braces(pattern);
            if escaped == pattern || !is_literal_brace_compile_error(&original) {
                return Err(original);
            }
            build_regex(&escaped)
        }
    }
}

/// Helper to compile a regex pattern for matching raw byte slices.
///
/// Valid Rust regex syntax is compiled unchanged. For compatibility with loose
/// upstream rules, this falls back to escaping unescaped literal braces only when
/// the original compile error is brace-related.
#[allow(dead_code)]
pub fn compile_bytes_regex(pattern: &str) -> Result<regex::bytes::Regex, regex::Error> {
    match build_bytes_regex(pattern) {
        Ok(regex) => Ok(regex),
        Err(original) => {
            let escaped = escape_literal_braces(pattern);
            if escaped == pattern || !is_literal_brace_compile_error(&original) {
                return Err(original);
            }
            build_bytes_regex(&escaped)
        }
    }
}

/// Helper to preprocess and compile a regex set for matching raw byte slices.
///
/// This uses the same valid-first, literal-brace fallback posture as
/// [`compile_bytes_regex`].
#[allow(dead_code)]
pub fn compile_bytes_regex_set(
    patterns: &[String],
) -> Result<regex::bytes::RegexSet, regex::Error> {
    match build_bytes_regex_set(patterns) {
        Ok(set) => Ok(set),
        Err(original) => {
            if !is_literal_brace_compile_error(&original) {
                return Err(original);
            }
            let repaired: Vec<String> = patterns
                .iter()
                .map(|pattern| repair_literal_braces_for_set(pattern))
                .collect();
            if repaired.iter().zip(patterns).all(|(a, b)| a == b) {
                return Err(original);
            }
            build_bytes_regex_set(&repaired)
        }
    }
}

/// Escapes unescaped `{` and `}` characters that are not part of valid repetition quantifiers (e.g. `{n}`, `{n,}`, `{n,m}`).
pub fn escape_literal_braces(pattern: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            result.push('\\');
            if i + 1 < chars.len() {
                result.push(chars[i + 1]);
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }

        if c == '{' {
            if let Some(len) = get_quantifier_len(&chars[i..]) {
                for k in 0..len {
                    result.push(chars[i + k]);
                }
                i += len;
            } else {
                result.push('\\');
                result.push('{');
                i += 1;
            }
        } else if c == '}' {
            result.push('\\');
            result.push('}');
            i += 1;
        } else {
            result.push(c);
            i += 1;
        }
    }
    result
}

fn get_quantifier_len(slice: &[char]) -> Option<usize> {
    if slice.is_empty() || slice[0] != '{' {
        return None;
    }
    let mut idx = 1;
    let mut has_digits1 = false;
    while idx < slice.len() && slice[idx].is_ascii_digit() {
        has_digits1 = true;
        idx += 1;
    }
    if !has_digits1 {
        return None;
    }
    if idx < slice.len() && slice[idx] == ',' {
        idx += 1;
        while idx < slice.len() && slice[idx].is_ascii_digit() {
            idx += 1;
        }
    }
    if idx < slice.len() && slice[idx] == '}' {
        Some(idx + 1)
    } else {
        None
    }
}

fn build_regex(pattern: &str) -> Result<regex::Regex, regex::Error> {
    let mut builder = regex::RegexBuilder::new(pattern);
    builder.size_limit(REGEX_SIZE_LIMIT);
    builder.build()
}

fn build_bytes_regex(pattern: &str) -> Result<regex::bytes::Regex, regex::Error> {
    let mut builder = regex::bytes::RegexBuilder::new(pattern);
    builder.size_limit(REGEX_SIZE_LIMIT);
    builder.build()
}

fn build_bytes_regex_set(patterns: &[String]) -> Result<regex::bytes::RegexSet, regex::Error> {
    let mut builder = regex::bytes::RegexSetBuilder::new(patterns);
    builder.size_limit(REGEX_SIZE_LIMIT);
    builder.build()
}

// Classifies a compile error as "a literal `{`/`}` the author meant verbatim,
// not a counted-repetition quantifier" by matching `regex::Error`'s message text.
// `regex::Error` is `#[non_exhaustive]` and exposes only `Syntax(String)` — there
// is no structured brace-error kind to match on, so substring matching is the only
// available signal. It is coupled to the regex crate's wording; a crate bump that
// rewords these would make a repairable rule fail to compile and be dropped. The
// `escaped == pattern` short-circuit at the call sites bounds the blast radius:
// repair is attempted only when escaping actually changes the pattern.
fn is_literal_brace_compile_error(e: &regex::Error) -> bool {
    let msg = e.to_string();
    msg.contains("repetition")
        || msg.contains("counted repetition")
        || msg.contains("invalid decimal digit")
}

fn repair_literal_braces_for_set(pattern: &str) -> String {
    match build_bytes_regex(pattern) {
        Ok(_) => pattern.to_string(),
        Err(e) if is_literal_brace_compile_error(&e) => {
            let escaped = escape_literal_braces(pattern);
            if escaped == pattern {
                pattern.to_string()
            } else {
                escaped
            }
        }
        Err(_) => pattern.to_string(),
    }
}

/// Check if a regex compilation error is due to an unsupported feature in Rust's regex engine (e.g. look-around).
#[allow(dead_code)]
pub fn is_unsupported_regex_error(e: &regex::Error) -> bool {
    let msg = e.to_string();
    msg.contains("look-around") || msg.contains("look-ahead") || msg.contains("look-behind")
}
