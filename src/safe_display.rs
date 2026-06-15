//! Shared terminal display sanitization.

/// Replace log-spoofing controls with visible escapes for terminal output.
pub(crate) fn sanitize_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let code = c as u32;
        if should_escape(c) {
            if code <= 0xff {
                out.push_str(&format!("\\x{code:02x}"));
            } else {
                out.push_str(&format!("\\u{{{code:x}}}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn should_escape(c: char) -> bool {
    let code = c as u32;
    code < 0x20
        || code == 0x7f
        || (0x80..=0x9f).contains(&code)
        || matches!(
            code,
            0x061c
                | 0x200e
                | 0x200f
                | 0x202a..=0x202e
                | 0x2066..=0x2069
        )
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
        // Printable Unicode that does not reorder text is preserved verbatim.
        assert_eq!(sanitize_display("café—π"), "café—π");
    }

    #[test]
    fn no_raw_control_byte_survives() {
        let out = sanitize_display("x\x01\x02\x1f\x7fy");
        assert!(!out.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f));
    }

    #[test]
    fn escapes_c1_and_bidi_controls() {
        assert_eq!(sanitize_display("a\u{0085}b"), "a\\x85b");
        assert_eq!(sanitize_display("safe\u{202e}txt"), "safe\\u{202e}txt");
        assert_eq!(
            sanitize_display("x\u{2066}y\u{2069}z"),
            "x\\u{2066}y\\u{2069}z"
        );
    }
}
