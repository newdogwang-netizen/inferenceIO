use std::io;

pub const MAX_JSON_NESTING_DEPTH: usize = 64;
pub const MAX_JSON_STRUCTURAL_TOKENS: usize = 100_000;
pub const MAX_STORED_JSON_NESTING_DEPTH: usize = MAX_JSON_NESTING_DEPTH + 16;
pub const MAX_STORED_JSON_STRUCTURAL_TOKENS: usize = MAX_JSON_STRUCTURAL_TOKENS + 4_096;

/// Reject JSON inputs whose shape can amplify a bounded byte buffer into an
/// unbounded `serde_json::Value` allocation. Full syntax validation remains
/// the responsibility of the JSON parser that follows this preflight pass.
pub fn validate_json_complexity(bytes: &[u8]) -> io::Result<()> {
    validate_json_complexity_with_limits(bytes, MAX_JSON_NESTING_DEPTH, MAX_JSON_STRUCTURAL_TOKENS)
}

/// Stored envelopes add bounded recorder metadata around already-preflighted
/// payloads, so readers and writers share a small explicit overhead budget.
pub fn validate_stored_json_complexity(bytes: &[u8]) -> io::Result<()> {
    validate_json_complexity_with_limits(
        bytes,
        MAX_STORED_JSON_NESTING_DEPTH,
        MAX_STORED_JSON_STRUCTURAL_TOKENS,
    )
}

fn validate_json_complexity_with_limits(
    bytes: &[u8],
    maximum_depth: usize,
    maximum_tokens: usize,
) -> io::Result<()> {
    let mut in_string = false;
    let mut escaped = false;
    let mut depth = 0_usize;
    let mut tokens = 0_usize;

    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > maximum_depth {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("JSON exceeds the {maximum_depth}-level nesting safety limit"),
                    ));
                }
                tokens = tokens.saturating_add(1);
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            b',' | b':' => tokens = tokens.saturating_add(1),
            _ => {}
        }
        if tokens > maximum_tokens {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("JSON exceeds the {maximum_tokens}-token structural safety limit"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complexity_scan_ignores_delimiters_inside_strings_and_rejects_amplification() {
        validate_json_complexity_with_limits(br#"{"text":"[{:,,}]\\\""}"#, 2, 3).unwrap();
        assert!(validate_json_complexity_with_limits(b"[[[]]]", 2, 10).is_err());
        assert!(validate_json_complexity_with_limits(b"[0,1,2,3]", 2, 3).is_err());
    }

    #[test]
    fn stored_json_reserves_depth_only_for_bounded_recorder_wrappers() {
        let payload = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_NESTING_DEPTH),
            "]".repeat(MAX_JSON_NESTING_DEPTH)
        );
        validate_json_complexity(payload.as_bytes()).unwrap();
        let wrapped = format!("{{\"normalized\":{payload}}}");
        assert!(validate_json_complexity(wrapped.as_bytes()).is_err());
        validate_stored_json_complexity(wrapped.as_bytes()).unwrap();

        let excessive = format!(
            "{}0{}",
            "[".repeat(MAX_STORED_JSON_NESTING_DEPTH + 1),
            "]".repeat(MAX_STORED_JSON_NESTING_DEPTH + 1)
        );
        assert!(validate_stored_json_complexity(excessive.as_bytes()).is_err());
    }
}
