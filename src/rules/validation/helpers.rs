//! rules/validation/helpers.rs — Regex compilation and escaping helpers.

/// Helper to preprocess and compile a regex pattern using the scanner's standard builder.
///
/// This automatically escapes unescaped braces that are not valid repetition quantifiers,
/// and configures a larger compilation size limit (100MB) to support complex rulesets.
pub fn compile_regex(pattern: &str) -> Result<regex::Regex, regex::Error> {
    let escaped = escape_literal_braces(pattern);
    let mut builder = regex::RegexBuilder::new(&escaped);
    builder.size_limit(100 * 1024 * 1024);
    builder.build()
}

/// Helper to preprocess and compile a regex pattern for matching raw byte slices.
///
/// This automatically escapes unescaped braces that are not valid repetition quantifiers,
/// and configures a larger compilation size limit (100MB) to support complex rulesets.
#[allow(dead_code)]
pub fn compile_bytes_regex(pattern: &str) -> Result<regex::bytes::Regex, regex::Error> {
    let escaped = escape_literal_braces(pattern);
    let mut builder = regex::bytes::RegexBuilder::new(&escaped);
    builder.size_limit(100 * 1024 * 1024);
    builder.build()
}

/// Helper to preprocess and compile a regex set for matching raw byte slices.
///
/// This uses the same literal-brace escaping and size limit as
/// [`compile_bytes_regex`], so the set prefilter has the same compilation
/// posture as individual detection regexes.
#[allow(dead_code)]
pub fn compile_bytes_regex_set(
    patterns: &[String],
) -> Result<regex::bytes::RegexSet, regex::Error> {
    let escaped: Vec<String> = patterns
        .iter()
        .map(|pattern| escape_literal_braces(pattern))
        .collect();
    let mut builder = regex::bytes::RegexSetBuilder::new(escaped);
    builder.size_limit(100 * 1024 * 1024);
    builder.build()
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

/// Check if a regex compilation error is due to an unsupported feature in Rust's regex engine (e.g. look-around).
#[allow(dead_code)]
pub fn is_unsupported_regex_error(e: &regex::Error) -> bool {
    let msg = e.to_string();
    msg.contains("look-around") || msg.contains("look-ahead") || msg.contains("look-behind")
}
