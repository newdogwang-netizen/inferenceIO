use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

// Keep the matrix embedded so every support claim is tied to the executable.
const EMBEDDED_MATRIX: &str = include_str!("../support-matrix.v1.json");
const MAX_CELLS: usize = 10_000;
const MAX_EVIDENCE_PER_CELL: usize = 64;
const MAX_PROTOCOLS_PER_CELL: usize = 32;
const MAX_TEXT_BYTES: usize = 1_024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityMatrix {
    pub schema_version: u32,
    pub claim_policy: String,
    pub default_status: CompatibilityStatus,
    pub cells: Vec<CompatibilityCell>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityCell {
    pub id: String,
    pub agent: String,
    pub runtime: String,
    pub tls: String,
    pub protocols: Vec<String>,
    pub capture_path: String,
    pub status: CompatibilityStatus,
    #[serde(default)]
    pub evidence: Vec<CompatibilityEvidence>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Verified,
    Experimental,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityEvidence {
    pub kind: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

pub fn load() -> Result<CompatibilityMatrix, String> {
    let matrix: CompatibilityMatrix = serde_json::from_str(EMBEDDED_MATRIX)
        .map_err(|error| format!("compatibility matrix is invalid JSON: {error}"))?;
    matrix.validate()?;
    Ok(matrix)
}

impl CompatibilityMatrix {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.claim_policy != "exact-cells-only"
            || self.default_status != CompatibilityStatus::Unknown
        {
            return Err("compatibility matrix policy header is invalid".to_owned());
        }
        if self.cells.is_empty() || self.cells.len() > MAX_CELLS {
            return Err("compatibility matrix cell count is invalid".to_owned());
        }
        let mut ids = BTreeSet::new();
        for cell in &self.cells {
            for (name, value) in [
                ("cell ID", cell.id.as_str()),
                ("agent", cell.agent.as_str()),
                ("runtime", cell.runtime.as_str()),
                ("TLS", cell.tls.as_str()),
                ("capture path", cell.capture_path.as_str()),
            ] {
                validate_text(name, value)?;
            }
            if !ids.insert(&cell.id) {
                return Err("compatibility matrix contains a duplicate cell ID".to_owned());
            }
            if cell.protocols.is_empty() || cell.protocols.len() > MAX_PROTOCOLS_PER_CELL {
                return Err(format!(
                    "compatibility cell {} has invalid protocols",
                    cell.id
                ));
            }
            for protocol in &cell.protocols {
                validate_text("protocol", protocol)?;
            }
            if cell.evidence.len() > MAX_EVIDENCE_PER_CELL
                || cell.limitations.len() > MAX_EVIDENCE_PER_CELL
            {
                return Err(format!(
                    "compatibility cell {} exceeds its list bounds",
                    cell.id
                ));
            }
            for limitation in &cell.limitations {
                validate_text("limitation", limitation)?;
            }
            for evidence in &cell.evidence {
                if !matches!(
                    evidence.kind.as_str(),
                    "test" | "artifact" | "documentation"
                ) {
                    return Err(format!(
                        "compatibility cell {} has unknown evidence",
                        cell.id
                    ));
                }
                validate_relative_path(&evidence.path)?;
                if let Some(symbol) = &evidence.symbol {
                    validate_text("evidence symbol", symbol)?;
                }
                if let Some(digest) = &evidence.sha256
                    && (digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
                {
                    return Err(format!("compatibility cell {} has invalid digest", cell.id));
                }
                if evidence.kind == "artifact" && evidence.sha256.is_none() {
                    return Err(format!(
                        "compatibility cell {} has an unpinned artifact",
                        cell.id
                    ));
                }
            }
            if cell.status == CompatibilityStatus::Verified {
                if cell.evidence.is_empty()
                    || !cell
                        .evidence
                        .iter()
                        .any(|evidence| matches!(evidence.kind.as_str(), "test" | "artifact"))
                {
                    return Err(format!(
                        "verified compatibility cell {} has no executable evidence",
                        cell.id
                    ));
                }
                if [
                    cell.agent.as_str(),
                    cell.runtime.as_str(),
                    cell.tls.as_str(),
                ]
                .iter()
                .any(|value| matches!(*value, "any" | "unknown"))
                {
                    return Err(format!(
                        "verified compatibility cell {} contains a wildcard",
                        cell.id
                    ));
                }
            }
            if cell.status != CompatibilityStatus::Verified && cell.limitations.is_empty() {
                return Err(format!(
                    "non-verified compatibility cell {} has no limitation",
                    cell.id
                ));
            }
        }
        Ok(())
    }
}

fn validate_text(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(format!("compatibility matrix {name} is invalid"));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), String> {
    validate_text("evidence path", value)?;
    let path = std::path::Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        return Err("compatibility matrix evidence path is unsafe".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn verified_support_cells_have_present_repository_evidence() {
        let matrix = load().unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for cell in matrix.cells {
            for evidence in cell.evidence {
                let path = root.join(&evidence.path);
                let bytes = fs::read(&path).unwrap_or_else(|error| {
                    panic!(
                        "compatibility evidence {} for {} is unavailable: {error}",
                        evidence.path, cell.id
                    )
                });
                if let Some(expected) = evidence.sha256 {
                    assert_eq!(
                        hex::encode(Sha256::digest(&bytes)),
                        expected,
                        "compatibility artifact changed for {}",
                        cell.id
                    );
                }
                if let Some(symbol) = evidence.symbol {
                    let text = std::str::from_utf8(&bytes).unwrap_or_else(|error| {
                        panic!(
                            "compatibility evidence {} for {} is not UTF-8: {error}",
                            evidence.path, cell.id
                        )
                    });
                    assert!(
                        text.contains(&symbol),
                        "compatibility evidence symbol {symbol} is missing for {}",
                        cell.id
                    );
                }
            }
        }
    }

    #[test]
    fn real_agent_cli_qualification_is_exact_and_complete() {
        let matrix = load().unwrap();
        for expected_cells in [
            (
                "gemini-cli-0.60.0-controlled-generate-content-sse",
                "gemini",
                "0.60.0",
                "fdff028b293149897b948a23b5d8da9e622127182a523be46d82cf267e7816f2",
            ),
            (
                "codex-0.154.0-controlled-responses-sse",
                "codex",
                "0.154.0",
                "3188814c35471432d4123203e0eb38e5bddc60226e3d7ddf0e59e649ea140022",
            ),
            (
                "claude-native-2.1.273-controlled-anthropic-sse",
                "claude",
                "2.1.273",
                "6c752e2cc7c110c9df15f26d8d134d438c5ae95dbd610efc1a308bf7f9c5f6c1",
            ),
            (
                "hermes-0.19.0-controlled-openai-http1-sse",
                "hermes",
                "0.19.0",
                "f248dbd7ccf01dc83187a553a62b476b6877c423f227a469e44138814c7d4d21",
            ),
        ] {
            let cell = matrix
                .cells
                .iter()
                .find(|cell| cell.id == expected_cells.0)
                .unwrap_or_else(|| {
                    panic!("missing real Agent qualification cell {}", expected_cells.0)
                });
            assert_eq!(cell.status, CompatibilityStatus::Verified);
            assert!(
                cell.evidence.iter().any(|evidence| {
                    evidence.kind == "test"
                        && evidence.path == "src/support_matrix.rs"
                        && evidence.symbol.as_deref()
                            == Some("real_agent_cli_qualification_is_exact_and_complete")
                }) && cell.evidence.iter().any(|evidence| {
                    evidence.kind == "documentation"
                        && evidence.path
                            == "benchmarks/2026-09-16-real-agent-cli-transport-linux-x86_64.json"
                        && evidence.symbol.as_deref()
                            == Some("qualified_four_exact_agent_cli_cells_transport_complete")
                }),
                "real Agent cell {} is not bound to its executable test and qualification report",
                expected_cells.0
            );

            let root = Path::new(env!("CARGO_MANIFEST_DIR"));
            let report: serde_json::Value = serde_json::from_slice(
                &fs::read(
                    root.join("benchmarks/2026-09-16-real-agent-cli-transport-linux-x86_64.json"),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                report["artifacts"]["agent_executables"][expected_cells.1]["version"],
                expected_cells.2
            );
            assert_eq!(
                report["artifacts"]["agent_executables"][expected_cells.1]["sha256"],
                expected_cells.3
            );
        }

        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let report: serde_json::Value = serde_json::from_slice(
            &fs::read(
                root.join("benchmarks/2026-09-16-real-agent-cli-transport-linux-x86_64.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            report["status"],
            "qualified_four_exact_agent_cli_cells_transport_complete"
        );
        assert_eq!(report["aggregate_result"]["agents_qualified"], 4);
        assert_eq!(report["aggregate_result"]["model_attempts"], 5);
        assert_eq!(report["aggregate_result"]["model_attempts_matched"], 5);
        assert_eq!(report["aggregate_result"]["missing_from_wire"], 0);
        assert_eq!(report["aggregate_result"]["extra_on_wire"], 0);
        assert_eq!(report["aggregate_result"]["unresolved_correlations"], 0);
        assert_eq!(report["aggregate_result"]["capture_drops"], 0);
        assert_eq!(report["aggregate_result"]["successful_unknown_egress"], 0);
        assert_eq!(
            report["aggregate_result"]["all_transport_audits_complete"],
            true
        );
    }
}
