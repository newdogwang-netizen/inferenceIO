use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs, io,
    path::{Path, PathBuf},
};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub os: String,
    pub architecture: String,
    pub kernel_release: Option<String>,
    pub effective_uid: Option<u32>,
    pub cgroup_v2: bool,
    pub capabilities: CapabilityReport,
    pub tools: BTreeMap<String, ToolReport>,
    pub capture_modes: BTreeMap<String, CaptureModeReport>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CapabilityReport {
    pub effective_mask: Option<String>,
    pub effective: BTreeSet<String>,
}

impl CapabilityReport {
    fn contains(&self, capability: &str) -> bool {
        self.effective.contains(capability)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolReport {
    pub available: bool,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureModeReport {
    pub status: &'static str,
    pub reason: String,
}

#[must_use]
pub fn inspect() -> DoctorReport {
    let process_status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let capabilities = parse_capabilities(&process_status);
    let effective_uid = parse_effective_uid(&process_status);
    let tcpdump = crate::pcap::trusted_tcpdump_path();
    let tshark = find_executable("tshark");
    let dumpcap = find_executable("dumpcap");
    let agentsight = find_executable("agentsight");
    let ecapture = find_executable("ecapture");
    let task_netns_ready = crate::task_netns::TaskNetnsTools::discover().is_ok();
    let is_root = effective_uid == Some(0);
    let pcap_ready = tcpdump.is_some() && (is_root || capabilities.contains("CAP_NET_RAW"));
    let ebpf_ready =
        is_root || (capabilities.contains("CAP_BPF") && capabilities.contains("CAP_PERFMON"));

    let mut tools = BTreeMap::new();
    for (name, path) in [
        ("agentsight", agentsight),
        ("dumpcap", dumpcap),
        ("ecapture", ecapture),
        ("tcpdump", tcpdump.clone()),
        ("tshark", tshark),
    ] {
        tools.insert(
            name.to_owned(),
            ToolReport {
                available: path.is_some(),
                path,
            },
        );
    }

    let mut capture_modes = BTreeMap::new();
    capture_modes.insert(
        "endpoint_proxy".to_owned(),
        CaptureModeReport {
            status: "available",
            reason: "built into iorec; provider/agent endpoint compatibility is still required"
                .to_owned(),
        },
    );
    capture_modes.insert(
        "nss_tls_keylog".to_owned(),
        CaptureModeReport {
            status: "experimental",
            reason: "requires --key-file and a TLS runtime that honors SSLKEYLOGFILE".to_owned(),
        },
    );
    capture_modes.insert(
        "pcap".to_owned(),
        CaptureModeReport {
            status: if pcap_ready {
                "available"
            } else {
                "unavailable"
            },
            reason: if pcap_ready {
                "trusted system tcpdump and packet-capture privilege detected".to_owned()
            } else {
                "requires a root-owned, non-writable tcpdump in a fixed system path plus root or CAP_NET_RAW"
                    .to_owned()
            },
        },
    );
    capture_modes.insert(
        "task_netns".to_owned(),
        CaptureModeReport {
            status: if task_netns_ready {
                "experimental"
            } else {
                "unavailable"
            },
            reason: if task_netns_ready {
                "trusted rootless user/net namespace, subordinate-ID mapping, slirp4netns sandbox/seccomp, nftables, sysctl, nsenter, setpriv, and task-local tcpdump prerequisites detected"
                    .to_owned()
            } else {
                "requires a non-root Linux recorder, enabled unprivileged user namespaces, subordinate UID/GID ranges, setuid newuidmap/newgidmap, and trusted fixed-path unshare/slirp4netns/nsenter/nft/sysctl/setpriv/tcpdump tools"
                    .to_owned()
            },
        },
    );
    capture_modes.insert(
        "ebpf".to_owned(),
        CaptureModeReport {
            status: if ebpf_ready {
                "experimental"
            } else {
                "unavailable"
            },
            reason: if ebpf_ready {
                "kernel privilege detected; a bridge implementing the versioned privileged-probe protocol is still required"
                    .to_owned()
            } else {
                "requires root or CAP_BPF plus CAP_PERFMON and a versioned probe-helper bridge"
                    .to_owned()
            },
        },
    );
    capture_modes.insert(
        "privileged_probe_helper".to_owned(),
        CaptureModeReport {
            status: "available",
            reason: "built-in protocol, readiness barrier, bounded encrypted ingestion, and drop/final gate; bridge executable must be explicitly selected and independently qualified"
                .to_owned(),
        },
    );

    DoctorReport {
        os: env::consts::OS.to_owned(),
        architecture: env::consts::ARCH.to_owned(),
        kernel_release: read_trimmed("/proc/sys/kernel/osrelease"),
        effective_uid,
        cgroup_v2: Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
        capabilities,
        tools,
        capture_modes,
        notes: vec![
            "availability is a prerequisite check, not a completeness claim".to_owned(),
            "unknown TLS libraries or egress still force best-effort coverage".to_owned(),
        ],
    }
}

fn parse_capabilities(status: &str) -> CapabilityReport {
    let encoded = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"));
    let mask = encoded.and_then(|value| u64::from_str_radix(value.trim(), 16).ok());
    let effective = [
        ("CAP_NET_ADMIN", 12),
        ("CAP_NET_RAW", 13),
        ("CAP_PERFMON", 38),
        ("CAP_BPF", 39),
    ]
    .into_iter()
    .filter(|(_, bit)| has_capability(mask, *bit))
    .map(|(name, _)| name.to_owned())
    .collect();
    CapabilityReport {
        effective_mask: encoded.map(str::trim).map(str::to_owned),
        effective,
    }
}

fn parse_effective_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:\t"))?
        .split_ascii_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn has_capability(mask: Option<u64>, bit: u32) -> bool {
    mask.is_some_and(|mask| mask & (1_u64 << bit) != 0)
}

fn find_executable(name: &str) -> Option<PathBuf> {
    env::split_paths(&env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    let value = fs::read_to_string(path).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

pub fn write_human(report: &DoctorReport, mut output: impl io::Write) -> io::Result<()> {
    writeln!(
        output,
        "platform: {} {} (kernel {})",
        report.os,
        report.architecture,
        report.kernel_release.as_deref().unwrap_or("unknown")
    )?;
    writeln!(output, "cgroup v2: {}", yes_no(report.cgroup_v2))?;
    writeln!(
        output,
        "capabilities: net_raw={} net_admin={} bpf={} perfmon={}",
        yes_no(report.capabilities.contains("CAP_NET_RAW")),
        yes_no(report.capabilities.contains("CAP_NET_ADMIN")),
        yes_no(report.capabilities.contains("CAP_BPF")),
        yes_no(report.capabilities.contains("CAP_PERFMON")),
    )?;
    for (name, mode) in &report.capture_modes {
        writeln!(output, "{name}: {} — {}", mode.status, mode.reason)?;
    }
    Ok(())
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_effective_uid_and_linux_capability_bits() {
        let status = "Uid:\t1000\t1001\t1000\t1000\nCapEff:\t000000c000003000\n";
        assert_eq!(parse_effective_uid(status), Some(1001));
        let capabilities = parse_capabilities(status);
        assert!(capabilities.contains("CAP_NET_ADMIN"));
        assert!(capabilities.contains("CAP_NET_RAW"));
        assert!(capabilities.contains("CAP_PERFMON"));
        assert!(capabilities.contains("CAP_BPF"));
    }
}
