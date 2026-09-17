use std::{collections::BTreeSet, io};

use serde::{Deserialize, Serialize};

use crate::{doctor::DoctorReport, manifest::CommandMetadata, probe_policy::ProbeHelperEvidence};

pub const PROBE_PLAN_VERSION: u32 = 1;
const MAX_CANDIDATES: usize = 32;
const MAX_LIST_ITEMS: usize = 128;
const MAX_TEXT_BYTES: usize = 1_024;

#[derive(Debug, Clone, Default)]
// These values describe independently selectable recorder layers rather than
// mutually exclusive states.
#[allow(clippy::struct_excessive_bools)]
pub struct ProbePlannerConfig {
    pub endpoint_proxy: bool,
    pub http2_prior_knowledge: bool,
    pub tls_keylog: bool,
    pub pcap: bool,
    pub python_injection: bool,
    pub node_injection: bool,
    pub privileged_helper: bool,
    pub helper_selection: Option<ProbeHelperEvidence>,
    pub task_cgroup: bool,
    pub task_netns: bool,
    pub transparent_proxy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbePlan {
    pub schema_version: u32,
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(default)]
    pub executable_tls_surfaces: Vec<String>,
    #[serde(default)]
    pub intended_protocols: Vec<String>,
    #[serde(default)]
    pub candidates: Vec<ProbeCandidate>,
    #[serde(default)]
    pub selected: Vec<String>,
    pub independent_observer_selected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_selection: Option<ProbeHelperEvidence>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeCandidate {
    pub id: String,
    pub status: String,
    pub priority: u8,
    pub selected: bool,
    pub independent_observer: bool,
    pub reason: String,
}

impl ProbePlan {
    #[must_use]
    pub fn build(
        command: &CommandMetadata,
        config: &ProbePlannerConfig,
        doctor: &DoctorReport,
    ) -> Self {
        let mut candidates = Vec::new();
        let mut limitations = Vec::new();
        let runtime = command.runtime.as_deref();
        let surfaces = command
            .executable_tls_surfaces
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let has_supported_tls_marker = surfaces.iter().any(|surface| {
            surface.contains("openssl")
                || surface.contains("boringssl")
                || surface.contains("go-crypto-tls")
        });
        let has_rustls_marker = surfaces.iter().any(|surface| surface.contains("rustls"));

        candidates.push(candidate(
            "endpoint_proxy",
            if config.endpoint_proxy {
                "available"
            } else {
                "not_selected"
            },
            10,
            config.endpoint_proxy,
            false,
            if config.endpoint_proxy {
                "configured loopback endpoint proxy records application-visible HTTP, SSE, and WebSocket traffic"
            } else {
                "no upstream endpoint was configured, so the built-in proxy is inactive"
            },
        ));

        let python_applicable = runtime == Some("python");
        candidates.push(candidate(
            "python_runtime",
            if python_applicable {
                "experimental"
            } else {
                "not_applicable"
            },
            20,
            config.python_injection,
            false,
            if python_applicable {
                "Python target can use the sitecustomize OpenAI/httpx/requests observer"
            } else {
                "target was not passively identified as Python"
            },
        ));

        let node_applicable = runtime == Some("node");
        candidates.push(candidate(
            "node_runtime",
            if node_applicable {
                "experimental"
            } else {
                "not_applicable"
            },
            20,
            config.node_injection,
            false,
            if node_applicable {
                "Node.js target can use the CommonJS/ESM OpenAI and HTTP observer"
            } else if runtime == Some("bun") {
                "Bun does not honor the supported Node.js preload mechanism"
            } else {
                "target was not passively identified as Node.js"
            },
        ));

        let keylog_status = match runtime {
            Some("python" | "node") => "experimental",
            Some("bun") => "unavailable",
            _ => "unknown",
        };
        candidates.push(candidate(
            "nss_tls_keylog",
            keylog_status,
            30,
            config.tls_keylog,
            false,
            match runtime {
                Some("node") => "Node.js can receive a recorder-controlled --tls-keylog destination",
                Some("python") => "Python default TLS contexts can honor SSLKEYLOGFILE; custom contexts can bypass it",
                Some("bun") => "Bun does not expose the supported NSS key-log mechanism",
                _ => "the detected runtime is not qualified to honor the NSS key-log contract",
            },
        ));

        let pcap_mode = doctor.capture_modes.get("pcap");
        candidates.push(candidate(
            "pcap_upstream_snapshot",
            if config.endpoint_proxy && !config.task_netns {
                pcap_mode.map_or("unavailable", |mode| mode.status)
            } else {
                "unavailable"
            },
            40,
            config.pcap && !config.task_netns,
            true,
            if config.task_netns {
                "task-network isolation replaces the shared-host upstream snapshot with task-egress pcap"
            } else if config.endpoint_proxy {
                pcap_mode.map_or("packet-capture prerequisites were not reported", |mode| {
                    mode.reason.as_str()
                })
            } else {
                "upstream packet capture requires a configured endpoint proxy and resolved provider addresses"
            },
        ));

        let task_netns_mode = doctor.capture_modes.get("task_netns");
        candidates.push(candidate(
            "pcap_task_netns_proxy_only",
            task_netns_mode.map_or("unavailable", |mode| mode.status),
            45,
            config.task_netns && !config.transparent_proxy,
            true,
            task_netns_mode.map_or(
                "rootless task-network prerequisites were not reported",
                |mode| mode.reason.as_str(),
            ),
        ));

        candidates.push(candidate(
            "transparent_task_netns_proxy",
            task_netns_mode.map_or("unavailable", |_| "experimental"),
            46,
            config.transparent_proxy,
            false,
            if config.transparent_proxy {
                "exact launch-time model sockets are selected for rootless DNAT with a private read-only hosts snapshot and per-run TLS identity"
            } else {
                "transparent model-socket interception was not selected"
            },
        ));

        let helper_reason = config.helper_selection.as_ref().map_or_else(
            || {
                if config.privileged_helper {
                    "an explicitly selected helper will be gated by ready/final/drop protocol evidence"
                        .to_owned()
                } else {
                    "the protocol boundary is built in, but no qualified bridge executable was selected"
                        .to_owned()
                }
            },
            |selection| {
                format!(
                    "{} helper {} selected{} with executable SHA-256 {}",
                    selection.mode,
                    selection.helper_kind,
                    selection
                        .rule_id
                        .as_deref()
                        .map_or_else(String::new, |rule| format!(" by rule {rule}")),
                    selection.helper_sha256
                )
            },
        );
        candidates.push(candidate(
            "privileged_probe_helper",
            if config.privileged_helper {
                "experimental"
            } else {
                "bridge_required"
            },
            50,
            config.privileged_helper,
            true,
            &helper_reason,
        ));

        let ebpf_status = doctor
            .capture_modes
            .get("ebpf")
            .map_or("unavailable", |mode| mode.status);
        let ecapture_available = doctor
            .tools
            .get("ecapture")
            .is_some_and(|tool| tool.available);
        let ecapture_selected = config
            .helper_selection
            .as_ref()
            .is_some_and(|selection| selection.helper_kind == "ecapture");
        let ecapture_reason = if ecapture_selected {
            "a digest-pinned eCapture bridge was selected by the trusted probe policy"
        } else if ecapture_available && ebpf_status != "unavailable" && has_supported_tls_marker {
            "eCapture and kernel privilege are present with a candidate TLS marker, but no qualified iorec bridge was selected"
        } else if has_rustls_marker && !has_supported_tls_marker {
            "the discovered rustls marker is outside the qualified eCapture TLS matrix"
        } else {
            "eCapture, required kernel privilege, or a compatible TLS marker is absent"
        };
        candidates.push(candidate(
            "ecapture_bridge",
            if ecapture_selected {
                "experimental"
            } else if ecapture_available && ebpf_status != "unavailable" && has_supported_tls_marker
            {
                "bridge_required"
            } else if has_rustls_marker && !has_supported_tls_marker {
                "not_applicable"
            } else {
                "unavailable"
            },
            60,
            ecapture_selected,
            true,
            ecapture_reason,
        ));

        let agentsight_available = doctor
            .tools
            .get("agentsight")
            .is_some_and(|tool| tool.available);
        let agentsight_selected = config
            .helper_selection
            .as_ref()
            .is_some_and(|selection| selection.helper_kind == "agentsight");
        candidates.push(candidate(
            "agentsight_bridge",
            if agentsight_selected {
                "experimental"
            } else if agentsight_available && ebpf_status != "unavailable" {
                "bridge_required"
            } else {
                "unavailable"
            },
            70,
            agentsight_selected,
            true,
            if agentsight_selected {
                "a digest-pinned AgentSight bridge was selected by the trusted probe policy"
            } else if agentsight_available && ebpf_status != "unavailable" {
                "AgentSight and kernel privilege are present, but no qualified iorec bridge was selected"
            } else {
                "AgentSight or required kernel privilege is absent"
            },
        ));

        if surfaces.is_empty() {
            limitations.push(
                "static executable inspection found no TLS marker; the active TLS surface must be learned after launch"
                    .to_owned(),
            );
        } else {
            limitations.push(
                "executable TLS strings are planner hints, not proof that a surface is active or probe-compatible"
                    .to_owned(),
            );
        }
        if has_rustls_marker {
            limitations.push(
                "rustls has no bundled plaintext probe; independent validation requires an explicitly qualified helper"
                    .to_owned(),
            );
        }
        if config.task_cgroup {
            limitations.push(
                "the selected cgroup boundary scopes task descendants but does not itself capture or block traffic"
                    .to_owned(),
            );
        }
        if config.task_netns {
            limitations.push(
                "proxy-only task network isolation blocks DNS and every non-loopback destination except the recorder proxy; non-model network dependencies are intentionally unavailable"
                    .to_owned(),
            );
        }
        let independent_observer_selected = candidates.iter().any(|candidate| {
            candidate.selected
                && candidate.independent_observer
                && matches!(candidate.status.as_str(), "available" | "experimental")
        });
        if !independent_observer_selected {
            limitations.push(
                "no independent packet or privileged observer is selected; runtime/proxy agreement cannot rule out bypasses"
                    .to_owned(),
            );
        }
        limitations.push(
            "protocol entries are intended preflight paths; observed protocols and active TLS libraries are finalized from run evidence"
                .to_owned(),
        );

        let selected = candidates
            .iter()
            .filter(|candidate| candidate.selected)
            .map(|candidate| candidate.id.clone())
            .collect();
        let intended_protocols = if config.endpoint_proxy {
            let http = if config.http2_prior_knowledge {
                "http/2-prior-knowledge"
            } else {
                "http/1.1-or-negotiated-http/2"
            };
            vec![http.to_owned(), "sse".to_owned(), "websocket".to_owned()]
        } else {
            vec!["unknown".to_owned()]
        };
        Self {
            schema_version: PROBE_PLAN_VERSION,
            phase: "preflight".to_owned(),
            runtime: command.runtime.clone(),
            executable_tls_surfaces: surfaces.into_iter().collect(),
            intended_protocols,
            candidates,
            selected,
            independent_observer_selected,
            helper_selection: config.helper_selection.clone(),
            limitations,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != PROBE_PLAN_VERSION || self.phase != "preflight" {
            return Err("unsupported probe plan schema or phase".to_owned());
        }
        validate_optional_text("probe plan runtime", self.runtime.as_deref())?;
        validate_list("probe plan TLS surface", &self.executable_tls_surfaces)?;
        validate_list("probe plan protocol", &self.intended_protocols)?;
        validate_list("probe plan selection", &self.selected)?;
        validate_list("probe plan limitation", &self.limitations)?;
        if self.candidates.len() > MAX_CANDIDATES {
            return Err("probe plan has too many candidates".to_owned());
        }
        let mut ids = BTreeSet::new();
        let mut selected_candidates = BTreeSet::new();
        let mut computed_independent = false;
        for candidate in &self.candidates {
            validate_text("probe candidate ID", &candidate.id)?;
            validate_text("probe candidate status", &candidate.status)?;
            validate_text("probe candidate reason", &candidate.reason)?;
            if !matches!(
                candidate.status.as_str(),
                "available"
                    | "experimental"
                    | "unknown"
                    | "unavailable"
                    | "not_applicable"
                    | "not_selected"
                    | "bridge_required"
            ) {
                return Err("probe candidate has an unsupported status".to_owned());
            }
            if !ids.insert(candidate.id.as_str()) {
                return Err("probe plan has duplicate candidate IDs".to_owned());
            }
            if candidate.selected {
                selected_candidates.insert(candidate.id.as_str());
                computed_independent |= candidate.independent_observer
                    && matches!(candidate.status.as_str(), "available" | "experimental");
            }
        }
        let selected = self
            .selected
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if selected.len() != self.selected.len() || selected != selected_candidates {
            return Err("probe plan selection summary is inconsistent".to_owned());
        }
        if self.independent_observer_selected != computed_independent {
            return Err("probe plan independent-observer summary is inconsistent".to_owned());
        }
        if let Some(selection) = &self.helper_selection {
            selection.validate()?;
            if !selected_candidates.contains("privileged_probe_helper") {
                return Err("probe helper evidence exists without a selected helper".to_owned());
            }
            if matches!(selection.helper_kind.as_str(), "ecapture" | "agentsight")
                && !selected_candidates.contains(match selection.helper_kind.as_str() {
                    "ecapture" => "ecapture_bridge",
                    _ => "agentsight_bridge",
                })
            {
                return Err(
                    "probe helper evidence disagrees with the concrete bridge selection".to_owned(),
                );
            }
        }
        Ok(())
    }
}

pub fn write_human(plan: &ProbePlan, mut output: impl io::Write) -> io::Result<()> {
    writeln!(
        output,
        "runtime: {}",
        plan.runtime.as_deref().unwrap_or("unknown")
    )?;
    writeln!(
        output,
        "TLS hints: {}",
        if plan.executable_tls_surfaces.is_empty() {
            "none".to_owned()
        } else {
            plan.executable_tls_surfaces.join(", ")
        }
    )?;
    writeln!(
        output,
        "intended protocols: {}",
        plan.intended_protocols.join(", ")
    )?;
    writeln!(
        output,
        "independent observer selected: {}",
        if plan.independent_observer_selected {
            "yes"
        } else {
            "no"
        }
    )?;
    writeln!(output, "candidates:")?;
    for candidate in &plan.candidates {
        writeln!(
            output,
            "  {:>3} {} [{}{}] — {}",
            candidate.priority,
            candidate.id,
            candidate.status,
            if candidate.selected { ", selected" } else { "" },
            candidate.reason
        )?;
    }
    if !plan.limitations.is_empty() {
        writeln!(output, "limitations:")?;
        for limitation in &plan.limitations {
            writeln!(output, "  - {limitation}")?;
        }
    }
    Ok(())
}

fn candidate(
    id: &str,
    status: &str,
    priority: u8,
    selected: bool,
    independent_observer: bool,
    reason: &str,
) -> ProbeCandidate {
    ProbeCandidate {
        id: id.to_owned(),
        status: status.to_owned(),
        priority,
        selected,
        independent_observer,
        reason: reason.to_owned(),
    }
}

fn validate_list(name: &str, values: &[String]) -> Result<(), String> {
    if values.len() > MAX_LIST_ITEMS {
        return Err(format!("{name} list has too many items"));
    }
    for value in values {
        validate_text(name, value)?;
    }
    Ok(())
}

fn validate_optional_text(name: &str, value: Option<&str>) -> Result<(), String> {
    value.map_or(Ok(()), |value| validate_text(name, value))
}

fn validate_text(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(format!("{name} is empty, too long, or contains controls"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::{
        doctor::{CapabilityReport, CaptureModeReport, DoctorReport, ToolReport},
        manifest::CommandMetadata,
    };

    use super::*;

    fn doctor(pcap: &'static str, ebpf: &'static str, tools: &[&str]) -> DoctorReport {
        let tools = ["agentsight", "ecapture"]
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    ToolReport {
                        available: tools.contains(&name),
                        path: None,
                    },
                )
            })
            .collect();
        DoctorReport {
            os: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            kernel_release: None,
            effective_uid: Some(1000),
            cgroup_v2: true,
            capabilities: CapabilityReport {
                effective_mask: None,
                effective: BTreeSet::new(),
            },
            tools,
            capture_modes: BTreeMap::from([
                (
                    "pcap".to_owned(),
                    CaptureModeReport {
                        status: pcap,
                        reason: "fixture pcap".to_owned(),
                    },
                ),
                (
                    "ebpf".to_owned(),
                    CaptureModeReport {
                        status: ebpf,
                        reason: "fixture ebpf".to_owned(),
                    },
                ),
                (
                    "task_netns".to_owned(),
                    CaptureModeReport {
                        status: "experimental",
                        reason: "fixture task netns".to_owned(),
                    },
                ),
            ]),
            notes: Vec::new(),
        }
    }

    fn command(runtime: &str, surfaces: &[&str]) -> CommandMetadata {
        CommandMetadata {
            argv: vec![runtime.to_owned()],
            cwd: "/tmp".into(),
            executable: None,
            executable_sha256: None,
            agent: None,
            agent_version: None,
            runtime: Some(runtime.to_owned()),
            executable_tls_surfaces: surfaces.iter().map(|value| (*value).to_owned()).collect(),
            environment: BTreeMap::new(),
        }
    }

    #[test]
    fn selects_configured_layers_without_treating_hints_as_proof() {
        let plan = ProbePlan::build(
            &command("python", &["openssl-dynamic-dependency"]),
            &ProbePlannerConfig {
                endpoint_proxy: true,
                tls_keylog: true,
                pcap: true,
                python_injection: true,
                task_cgroup: true,
                ..ProbePlannerConfig::default()
            },
            &doctor("available", "experimental", &["ecapture"]),
        );
        assert_eq!(
            plan.selected,
            vec![
                "endpoint_proxy",
                "python_runtime",
                "nss_tls_keylog",
                "pcap_upstream_snapshot"
            ]
        );
        assert!(plan.independent_observer_selected);
        assert!(
            plan.candidates
                .iter()
                .any(|candidate| candidate.id == "ecapture_bridge"
                    && candidate.status == "bridge_required")
        );
        plan.validate().unwrap();
        let mut inconsistent = plan.clone();
        inconsistent.selected.pop();
        assert!(inconsistent.validate().is_err());
        let mut inconsistent = plan.clone();
        inconsistent.independent_observer_selected = false;
        assert!(inconsistent.validate().is_err());
    }

    #[test]
    fn rustls_without_a_bridge_remains_an_explicit_planner_limit() {
        let plan = ProbePlan::build(
            &command("rust", &["rustls-binary-marker"]),
            &ProbePlannerConfig {
                pcap: true,
                ..ProbePlannerConfig::default()
            },
            &doctor("unavailable", "unavailable", &[]),
        );
        assert!(!plan.independent_observer_selected);
        assert!(
            plan.limitations
                .iter()
                .any(|limitation| limitation.contains("rustls"))
        );
        assert!(
            plan.candidates
                .iter()
                .any(|candidate| candidate.id == "ecapture_bridge"
                    && candidate.status == "not_applicable")
        );
        plan.validate().unwrap();
        let mut rendered = Vec::new();
        write_human(&plan, &mut rendered).unwrap();
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.contains("rustls"));
        assert!(rendered.contains("independent observer selected: no"));
    }

    #[test]
    fn task_namespace_capture_is_selected_without_host_pcap_capability() {
        let plan = ProbePlan::build(
            &command("native-elf", &[]),
            &ProbePlannerConfig {
                endpoint_proxy: true,
                tls_keylog: true,
                pcap: true,
                task_netns: true,
                ..ProbePlannerConfig::default()
            },
            &doctor("unavailable", "unavailable", &[]),
        );
        assert_eq!(
            plan.selected,
            vec![
                "endpoint_proxy",
                "nss_tls_keylog",
                "pcap_task_netns_proxy_only"
            ]
        );
        assert!(plan.independent_observer_selected);
        assert!(!plan.selected.contains(&"pcap_upstream_snapshot".to_owned()));
        plan.validate().unwrap();
    }

    #[test]
    fn policy_selected_bridge_is_recorded_as_a_concrete_candidate() {
        let evidence = ProbeHelperEvidence {
            mode: "policy".to_owned(),
            rule_id: Some("hermes-openssl".to_owned()),
            helper_kind: "ecapture".to_owned(),
            helper_path: "/usr/local/libexec/iorec/ecapture-bridge".into(),
            helper_sha256: "a".repeat(64),
            target_executable_sha256: None,
            matched_tls_surface: Some("openssl-dynamic-dependency".to_owned()),
        };
        let plan = ProbePlan::build(
            &command("python", &["openssl-dynamic-dependency"]),
            &ProbePlannerConfig {
                privileged_helper: true,
                helper_selection: Some(evidence.clone()),
                task_cgroup: true,
                ..ProbePlannerConfig::default()
            },
            &doctor("unavailable", "experimental", &["ecapture"]),
        );
        assert!(
            plan.selected
                .contains(&"privileged_probe_helper".to_owned())
        );
        assert!(plan.selected.contains(&"ecapture_bridge".to_owned()));
        assert_eq!(
            plan.helper_selection.as_ref().unwrap().rule_id,
            evidence.rule_id
        );
        assert!(plan.independent_observer_selected);
        plan.validate().unwrap();
    }
}
