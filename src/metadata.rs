use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) const MAX_NORMALIZED_STRING_BYTES: usize = 1024;

/// Keep ordinary metadata compact and terminal-safe while retaining a stable
/// equality token for oversized or control-bearing values.
pub(crate) fn bounded_string(value: &str) -> String {
    if value.len() <= MAX_NORMALIZED_STRING_BYTES && !value.chars().any(char::is_control) {
        value.to_owned()
    } else {
        format!(
            "[HASHED_METADATA sha256:{} bytes={}]",
            hex::encode(Sha256::digest(value.as_bytes())),
            value.len()
        )
    }
}

pub(crate) fn value_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(bounded_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_oversized_and_control_bearing_metadata_deterministically() {
        let oversized = "sensitive".repeat(129);
        let first = bounded_string(&oversized);
        assert_eq!(first, bounded_string(&oversized));
        assert!(first.starts_with("[HASHED_METADATA sha256:"));
        assert!(!first.contains("sensitivesensitive"));
        assert!(first.len() < 128);

        let control = bounded_string("value\u{1b}[31m");
        assert!(!control.contains('\u{1b}'));
        assert!(control.starts_with("[HASHED_METADATA sha256:"));
    }
}
