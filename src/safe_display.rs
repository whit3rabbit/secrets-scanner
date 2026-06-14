//! Shared terminal display sanitization.

/// Replace control characters with visible `\xNN` escapes for terminal output.
pub(crate) fn sanitize_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let code = c as u32;
        if code < 0x20 || code == 0x7f {
            out.push_str(&format!("\\x{code:02x}"));
        } else {
            out.push(c);
        }
    }
    out
}
