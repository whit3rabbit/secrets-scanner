use super::*;

/// Build a `Finding` differing only in `commit`/`line` (serde defaults fill the
/// rest); `file`/offsets/`rule_id` are held constant to collide on the legacy key.
fn finding(commit: &str, line: usize) -> Finding {
    serde_json::from_value(serde_json::json!({
        "file": "a", "line": line, "end_line": line,
        "col": 1, "end_col": 5, "rule_id": "r", "description": "d",
        "matched": "m", "entropy": 0.0,
        "start_offset": 0, "end_offset": 4,
        "secret_start_offset": 0, "secret_end_offset": 4,
        "commit": commit,
    }))
    .expect("finding")
}

#[test]
fn sort_is_deterministic_for_same_offset_cross_commit_findings() {
    // History offsets are buffer-relative, so these three share
    // (file, start_offset, end_offset, rule_id). Before commit+line entered the
    // key, the unstable sort left them in arbitrary order. The expected order is
    // by commit then line.
    let expected = vec![
        Some("aaa".to_string()),
        Some("bbb".to_string()),
        Some("ccc".to_string()),
    ];

    for mut input in [
        vec![finding("ccc", 9), finding("aaa", 3), finding("bbb", 7)],
        vec![finding("bbb", 7), finding("ccc", 9), finding("aaa", 3)],
        vec![finding("aaa", 3), finding("bbb", 7), finding("ccc", 9)],
    ] {
        sort_findings(&mut input);
        let order: Vec<_> = input.iter().map(|f| f.commit.clone()).collect();
        assert_eq!(order, expected, "sort order must be commit-deterministic");
    }
}
