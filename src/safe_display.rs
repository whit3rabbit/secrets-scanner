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

#[cfg(test)]
mod tests {
    use super::sanitize_display;

    #[test]
    fn escapes_control_and_del_bytes() {
        assert_eq!(sanitize_display("\x00"), "\\x00");
        assert_eq!(sanitize_display("\x1b"), "\\x1b");
        assert_eq!(sanitize_display("\x7f"), "\\x7f");
        assert_eq!(sanitize_display("a\nb\tc"), "a\\x0ab\\x09c");
    }

    #[test]
    fn passes_through_printable_and_multibyte() {
        assert_eq!(sanitize_display("hello.txt"), "hello.txt");
        // Printable Unicode (>= 0x20) is preserved verbatim.
        assert_eq!(sanitize_display("café—π"), "café—π");
    }

    #[test]
    fn no_raw_control_byte_survives() {
        let out = sanitize_display("x\x01\x02\x1f\x7fy");
        assert!(!out.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f));
    }
}
