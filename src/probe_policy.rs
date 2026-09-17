//! Policy-approved automatic selection of privileged probe helpers.
//!
//! Discovery never executes a helper found on `PATH`. An operator supplies a
//! trusted, bounded JSON policy whose rules bind an exact helper digest to an
//! OS/architecture and either a target executable digest or a TLS fingerprint.

use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    doctor::DoctorReport,
    input::validate_json_complexity,
    manifest::CommandMetadata,
    probe_helper,
    secure_fs::{open_regular_read, read_regular_limited},
};

pub const PROBE_POLICY_VERSION: u32 = 1;
const MAX_POLICY_BYTES: usize = 256 * 1024;
const MAX_RULES: usize = 128;
const MAX_RULE_LIST_ITEMS: usize = 128;
const MAX_LABEL_BYTES: usize = 128;
const MAX_HELPER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FAILURE_REASONS: usize = 8;

#[derive(Debug, Clone)]
pub struct ProbeHelperSelection {
    helper_path: PathBuf,
    evidence: ProbeHelperEvidence,
    rule: Option<ProbeRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeHelperEvidence {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub helper_kind: String,
    pub helper_path: PathBuf,
    pub helper_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_executable_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_tls_surface: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbePolicy {
    schema_version: u32,
    rules: Vec<ProbeRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeRule {
    id: String,
    priority: u16,
    helper_kind: String,
    helper_path: PathBuf,
    helper_sha256: String,
    os: String,
    architecture: String,
    #[serde(default)]
    runtime: Option<String>,
    #[serde(default)]
    any_tls_surfaces: Vec<String>,
    #[serde(default)]
    target_executable_sha256: Option<String>,
    #[serde(default = "default_true")]
    require_ebpf: bool,
    #[serde(default = "default_true")]
    require_task_cgroup: bool,
}

const fn default_true() -> bool {
    true
}

impl ProbeHelperSelection {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.helper_path
    }

    #[must_use]
    pub fn evidence(&self) -> &ProbeHelperEvidence {
        &self.evidence
    }

    pub fn revalidate(&self) -> Result<()> {
        let canonical = probe_helper::validate_helper(&self.helper_path)
            .context("revalidate selected probe helper")?;
        anyhow::ensure!(
            canonical == self.helper_path && self.evidence.helper_path == self.helper_path,
            "selected probe helper path changed"
        );
        let digest = helper_sha256(&canonical)?;
        anyhow::ensure!(
            digest == self.evidence.helper_sha256,
            "selected probe helper digest changed"
        );
        self.evidence.validate().map_err(anyhow::Error::msg)
    }

    pub fn revalidate_for(
        &self,
        command: &CommandMetadata,
        doctor: &DoctorReport,
        task_cgroup_selected: bool,
    ) -> Result<()> {
        self.revalidate()?;
        if let Some(rule) = &self.rule {
            rule_matches(rule, command, doctor, task_cgroup_selected).map_err(|reason| {
                anyhow::anyhow!(
                    "selected probe policy rule {} no longer matches: {reason}",
                    rule.id
                )
            })?;
            let target_digest = rule
                .target_executable_sha256
                .as_ref()
                .and(command.executable_sha256.clone());
            anyhow::ensure!(
                self.evidence.target_executable_sha256 == target_digest,
                "selected probe target digest evidence changed"
            );
            let matched_surface = matched_tls_surface(rule, command);
            anyhow::ensure!(
                self.evidence.matched_tls_surface == matched_surface,
                "selected probe TLS fingerprint evidence changed"
            );
        }
        Ok(())
    }
}

impl ProbeHelperEvidence {
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.mode.as_str(), "explicit" | "policy") {
            return Err("probe helper selection mode is invalid".to_owned());
        }
        validate_label("probe helper kind", &self.helper_kind)?;
        if !matches!(
            self.helper_kind.as_str(),
            "external" | "ecapture" | "agentsight"
        ) {
            return Err("probe helper kind is unsupported".to_owned());
        }
        if self.mode == "policy" {
            validate_label(
                "probe policy rule ID",
                self.rule_id
                    .as_deref()
                    .ok_or_else(|| "policy selection has no rule ID".to_owned())?,
            )?;
            if self.target_executable_sha256.is_none() && self.matched_tls_surface.is_none() {
                return Err("policy selection has no persisted target fingerprint".to_owned());
            }
        } else if self.rule_id.is_some() {
            return Err("explicit probe selection unexpectedly has a rule ID".to_owned());
        }
        validate_sha256(&self.helper_sha256, false)?;
        if let Some(digest) = &self.target_executable_sha256 {
            validate_sha256(digest, true)?;
        }
        if let Some(surface) = &self.matched_tls_surface {
            validate_label("matched TLS surface", surface)?;
        }
        if !self.helper_path.is_absolute() || self.helper_path.as_os_str().len() > 4_096 {
            return Err("probe helper evidence path is invalid".to_owned());
        }
        Ok(())
    }
}

pub fn inspect_explicit_helper(path: &Path) -> Result<ProbeHelperSelection> {
    let helper_path = probe_helper::validate_helper(path).context("validate probe helper")?;
    let evidence = ProbeHelperEvidence {
        mode: "explicit".to_owned(),
        rule_id: None,
        helper_kind: "external".to_owned(),
        helper_path: helper_path.clone(),
        helper_sha256: helper_sha256(&helper_path)?,
        target_executable_sha256: None,
        matched_tls_surface: None,
    };
    Ok(ProbeHelperSelection {
        helper_path,
        evidence,
        rule: None,
    })
}

pub fn select_probe_helper(
    policy_path: &Path,
    command: &CommandMetadata,
    doctor: &DoctorReport,
    task_cgroup_selected: bool,
) -> Result<ProbeHelperSelection> {
    let policy_path = validate_policy_path(policy_path)?;
    let bytes = read_regular_limited(&policy_path, MAX_POLICY_BYTES)?;
    validate_json_complexity(&bytes)?;
    let policy: ProbePolicy = serde_json::from_slice(&bytes).context("parse probe policy")?;
    validate_policy(&policy)?;

    let mut matches = Vec::new();
    let mut failures = Vec::new();
    for rule in &policy.rules {
        match rule_matches(rule, command, doctor, task_cgroup_selected) {
            Ok(()) => matches.push(rule),
            Err(reason) if failures.len() < MAX_FAILURE_REASONS => {
                failures.push(format!("{}: {reason}", rule.id));
            }
            Err(_) => {}
        }
    }
    matches.sort_by_key(|rule| (rule.priority, rule.id.as_str()));
    let Some(selected) = matches.first() else {
        let detail = if failures.is_empty() {
            "policy contains no selectable rule".to_owned()
        } else {
            failures.join("; ")
        };
        anyhow::bail!("probe policy found no matching helper ({detail})");
    };
    if matches
        .get(1)
        .is_some_and(|next| next.priority == selected.priority)
    {
        anyhow::bail!(
            "probe policy is ambiguous at priority {} between rules {} and {}",
            selected.priority,
            selected.id,
            matches[1].id
        );
    }
    let helper_path = probe_helper::validate_helper(&selected.helper_path)
        .with_context(|| format!("validate helper selected by probe rule {}", selected.id))?;
    let digest = helper_sha256(&helper_path)?;
    anyhow::ensure!(
        digest == selected.helper_sha256,
        "probe policy helper digest mismatch for rule {}",
        selected.id
    );
    let evidence = ProbeHelperEvidence {
        mode: "policy".to_owned(),
        rule_id: Some(selected.id.clone()),
        helper_kind: selected.helper_kind.clone(),
        helper_path: helper_path.clone(),
        helper_sha256: digest,
        target_executable_sha256: selected
            .target_executable_sha256
            .as_ref()
            .and(command.executable_sha256.clone()),
        matched_tls_surface: matched_tls_surface(selected, command),
    };
    evidence.validate().map_err(anyhow::Error::msg)?;
    Ok(ProbeHelperSelection {
        helper_path,
        evidence,
        rule: Some((*selected).clone()),
    })
}

fn validate_policy(policy: &ProbePolicy) -> Result<()> {
    anyhow::ensure!(
        policy.schema_version == PROBE_POLICY_VERSION,
        "unsupported probe policy schema"
    );
    anyhow::ensure!(
        !policy.rules.is_empty() && policy.rules.len() <= MAX_RULES,
        "probe policy rule count is invalid"
    );
    let mut ids = BTreeSet::new();
    for rule in &policy.rules {
        validate_label("probe policy rule ID", &rule.id).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            ids.insert(rule.id.as_str()),
            "duplicate probe policy rule ID"
        );
        validate_label("probe helper kind", &rule.helper_kind).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            matches!(
                rule.helper_kind.as_str(),
                "ecapture" | "agentsight" | "external"
            ),
            "probe policy helper kind is unsupported"
        );
        validate_label("probe policy OS", &rule.os).map_err(anyhow::Error::msg)?;
        validate_label("probe policy architecture", &rule.architecture)
            .map_err(anyhow::Error::msg)?;
        if let Some(runtime) = &rule.runtime {
            validate_label("probe policy runtime", runtime).map_err(anyhow::Error::msg)?;
        }
        anyhow::ensure!(
            rule.any_tls_surfaces.len() <= MAX_RULE_LIST_ITEMS,
            "probe policy TLS surface list is too large"
        );
        for surface in &rule.any_tls_surfaces {
            validate_label("probe policy TLS surface", surface).map_err(anyhow::Error::msg)?;
        }
        if let Some(digest) = &rule.target_executable_sha256 {
            validate_sha256(digest, true).map_err(anyhow::Error::msg)?;
        }
        validate_sha256(&rule.helper_sha256, false).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            rule.helper_path.is_absolute() && rule.helper_path.as_os_str().len() <= 4_096,
            "probe policy helper path is invalid"
        );
        anyhow::ensure!(
            !rule.any_tls_surfaces.is_empty() || rule.target_executable_sha256.is_some(),
            "probe policy rule must bind a TLS surface or exact target executable digest"
        );
    }
    Ok(())
}

fn rule_matches(
    rule: &ProbeRule,
    command: &CommandMetadata,
    doctor: &DoctorReport,
    task_cgroup_selected: bool,
) -> Result<(), &'static str> {
    if rule.os != doctor.os {
        return Err("operating system does not match");
    }
    if rule.architecture != doctor.architecture {
        return Err("architecture does not match");
    }
    if rule
        .runtime
        .as_deref()
        .is_some_and(|runtime| command.runtime.as_deref() != Some(runtime))
    {
        return Err("runtime does not match");
    }
    if !rule.any_tls_surfaces.is_empty()
        && !rule.any_tls_surfaces.iter().any(|required| {
            command
                .executable_tls_surfaces
                .iter()
                .any(|observed| observed == required)
        })
    {
        return Err("none of the policy TLS fingerprints were observed");
    }
    if rule.target_executable_sha256.is_some()
        && rule.target_executable_sha256.as_deref() != command.executable_sha256.as_deref()
    {
        return Err("target executable digest does not match");
    }
    if rule.require_task_cgroup && !task_cgroup_selected {
        return Err("task cgroup is required by policy");
    }
    if rule.require_ebpf
        && doctor
            .capture_modes
            .get("ebpf")
            .is_none_or(|mode| !matches!(mode.status, "available" | "experimental"))
    {
        return Err("eBPF prerequisites are unavailable");
    }
    Ok(())
}

fn matched_tls_surface(rule: &ProbeRule, command: &CommandMetadata) -> Option<String> {
    rule.any_tls_surfaces.iter().find_map(|required| {
        command
            .executable_tls_surfaces
            .iter()
            .find(|observed| *observed == required)
            .cloned()
    })
}

fn validate_policy_path(path: &Path) -> Result<PathBuf> {
    anyhow::ensure!(path.is_absolute(), "probe policy path must be absolute");
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "probe policy must be a regular non-symlink file"
    );
    let effective_uid = fs::metadata("/proc/self")?.uid();
    anyhow::ensure!(
        matches!(metadata.uid(), 0) || metadata.uid() == effective_uid,
        "probe policy is owned by an untrusted user"
    );
    anyhow::ensure!(
        metadata.permissions().mode() & 0o022 == 0,
        "probe policy must not be group/other writable"
    );
    let canonical = path.canonicalize()?;
    anyhow::ensure!(canonical == path, "probe policy path must be canonical");
    validate_ancestors(&canonical, effective_uid)?;
    Ok(canonical)
}

fn validate_ancestors(path: &Path, effective_uid: u32) -> Result<()> {
    let mut parent = path.parent();
    while let Some(directory) = parent {
        let metadata = fs::symlink_metadata(directory)?;
        let mode = metadata.permissions().mode();
        let root_sticky = metadata.uid() == 0 && mode & 0o1000 != 0;
        anyhow::ensure!(
            metadata.file_type().is_dir(),
            "probe policy has a non-directory ancestor"
        );
        anyhow::ensure!(
            matches!(metadata.uid(), 0) || metadata.uid() == effective_uid,
            "probe policy has an ancestor owned by an untrusted user"
        );
        anyhow::ensure!(
            mode & 0o022 == 0 || root_sticky,
            "probe policy has a writable non-sticky ancestor: {}",
            directory.display()
        );
        parent = directory.parent();
    }
    Ok(())
}

fn helper_sha256(path: &Path) -> Result<String> {
    let mut input = open_regular_read(path)?;
    let before = input.metadata()?;
    anyhow::ensure!(
        before.len() <= MAX_HELPER_BYTES,
        "probe helper exceeds the fingerprint size limit"
    );
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut total = 0_u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        digest.update(&buffer[..read]);
    }
    let after = input.metadata()?;
    anyhow::ensure!(
        total == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "probe helper changed while it was fingerprinted"
    );
    Ok(hex::encode(digest.finalize()))
}

fn validate_label(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_LABEL_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':')
        })
    {
        return Err(format!("{name} is invalid"));
    }
    Ok(())
}

fn validate_sha256(value: &str, prefixed: bool) -> Result<(), String> {
    let value = if prefixed {
        value
            .strip_prefix("sha256:")
            .ok_or_else(|| "target digest has no sha256 prefix".to_owned())?
    } else {
        value
    };
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("SHA-256 digest is not 64 lowercase hex characters".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        os::unix::fs::PermissionsExt,
    };

    use serde_json::json;

    use crate::doctor::{CapabilityReport, CaptureModeReport, ToolReport};

    use super::*;

    fn doctor() -> DoctorReport {
        DoctorReport {
            os: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            kernel_release: Some("fixture".to_owned()),
            effective_uid: Some(1000),
            cgroup_v2: true,
            capabilities: CapabilityReport {
                effective_mask: None,
                effective: BTreeSet::new(),
            },
            tools: BTreeMap::from([(
                "ecapture".to_owned(),
                ToolReport {
                    available: true,
                    path: None,
                },
            )]),
            capture_modes: BTreeMap::from([(
                "ebpf".to_owned(),
                CaptureModeReport {
                    status: "experimental",
                    reason: "fixture".to_owned(),
                },
            )]),
            notes: Vec::new(),
        }
    }

    fn command() -> CommandMetadata {
        CommandMetadata {
            argv: vec!["python".to_owned()],
            cwd: "/tmp".into(),
            executable: Some("/usr/bin/python".into()),
            executable_sha256: Some(format!("sha256:{}", "a".repeat(64))),
            agent: Some("hermes".to_owned()),
            agent_version: Some("0.19.0".to_owned()),
            runtime: Some("python".to_owned()),
            executable_tls_surfaces: vec!["openssl-dynamic-dependency".to_owned()],
            environment: BTreeMap::new(),
        }
    }

    fn write_private(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn trusted_policy_selects_and_revalidates_an_exact_helper_digest() {
        let temporary = tempfile::Builder::new()
            .prefix("iorec-probe-policy-")
            .tempdir_in("/tmp")
            .unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let helper = temporary.path().join("ecapture-bridge");
        write_private(&helper, b"#!/bin/sh\nexit 0\n", 0o700);
        let helper = helper.canonicalize().unwrap();
        let digest = helper_sha256(&helper).unwrap();
        let policy = temporary.path().join("policy.json");
        write_private(
            &policy,
            &serde_json::to_vec(&json!({
                "schema_version": PROBE_POLICY_VERSION,
                "rules": [{
                    "id": "hermes-openssl",
                    "priority": 10,
                    "helper_kind": "ecapture",
                    "helper_path": helper,
                    "helper_sha256": digest,
                    "os": "linux",
                    "architecture": "x86_64",
                    "runtime": "python",
                    "any_tls_surfaces": ["openssl-dynamic-dependency"],
                    "require_ebpf": true,
                    "require_task_cgroup": true
                }]
            }))
            .unwrap(),
            0o600,
        );
        let policy = policy.canonicalize().unwrap();
        let selection = select_probe_helper(&policy, &command(), &doctor(), true).unwrap();
        assert_eq!(selection.path(), helper);
        assert_eq!(selection.evidence().mode, "policy");
        assert_eq!(
            selection.evidence().rule_id.as_deref(),
            Some("hermes-openssl")
        );
        assert_eq!(selection.evidence().helper_kind, "ecapture");
        selection
            .revalidate_for(&command(), &doctor(), true)
            .unwrap();
        let mut changed = command();
        changed.executable_tls_surfaces = vec!["boringssl-binary-marker".to_owned()];
        assert!(selection.revalidate_for(&changed, &doctor(), true).is_err());

        write_private(&helper, b"#!/bin/sh\nexit 1\n", 0o700);
        assert!(selection.revalidate().is_err());
    }

    #[test]
    fn policy_mismatch_and_equal_priority_ambiguity_fail_before_launch() {
        let temporary = tempfile::Builder::new()
            .prefix("iorec-probe-policy-")
            .tempdir_in("/tmp")
            .unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let helper = temporary.path().join("bridge");
        write_private(&helper, b"#!/bin/sh\nexit 0\n", 0o700);
        let helper = helper.canonicalize().unwrap();
        let digest = helper_sha256(&helper).unwrap();
        let policy = temporary.path().join("policy.json");
        let rule = |id: &str, surface: &str| {
            json!({
                "id": id,
                "priority": 10,
                "helper_kind": "external",
                "helper_path": helper,
                "helper_sha256": digest,
                "os": "linux",
                "architecture": "x86_64",
                "any_tls_surfaces": [surface],
                "require_ebpf": false,
                "require_task_cgroup": false
            })
        };
        write_private(
            &policy,
            &serde_json::to_vec(&json!({
                "schema_version": PROBE_POLICY_VERSION,
                "rules": [rule("wrong", "boringssl-binary-marker")]
            }))
            .unwrap(),
            0o600,
        );
        let policy = policy.canonicalize().unwrap();
        let error = select_probe_helper(&policy, &command(), &doctor(), false).unwrap_err();
        assert!(error.to_string().contains("TLS fingerprints"));

        write_private(
            &policy,
            &serde_json::to_vec(&json!({
                "schema_version": PROBE_POLICY_VERSION,
                "rules": [
                    rule("first", "openssl-dynamic-dependency"),
                    rule("second", "openssl-dynamic-dependency")
                ]
            }))
            .unwrap(),
            0o600,
        );
        let error = select_probe_helper(&policy, &command(), &doctor(), false).unwrap_err();
        assert!(error.to_string().contains("ambiguous"));
    }
}
