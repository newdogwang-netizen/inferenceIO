use std::{
    ffi::{OsStr, OsString},
    fmt::Write as _,
    fs,
    io::{self, Read},
    net::SocketAddr,
    os::unix::{fs::MetadataExt, fs::PermissionsExt, io::AsRawFd, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use nix::{
    errno::Errno,
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use serde::Serialize;
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::oneshot,
    task::JoinHandle,
};

use crate::pcap::trusted_root_executable;

const START_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const READER_TIMEOUT: Duration = Duration::from_secs(3);
const OUTPUT_LIMIT: usize = 64 * 1024;
const PROC_LIMIT: u64 = 1024 * 1024;
const SLIRP_CIDR: &str = "10.0.2.0/24";
pub const GUEST_ADDRESS: &str = "10.0.2.100";
pub const HOST_GATEWAY: &str = "10.0.2.2";
const NFT_TABLE: &str = "iorec";
const NFT_CHAIN: &str = "output";
const NFT_NAT_TABLE: &str = "iorec_nat";
const MAX_TRANSPARENT_ENDPOINTS: usize = 64;

const FIRST_STAGE_SCRIPT: &str = concat!(
    "kill -STOP $$ || exit 125; ",
    "priv=$1; shell=$2; target_path=$3; shift 3; ",
    "exec \"$priv\" --no-new-privs --bounding-set=-all --inh-caps=-all ",
    "--ambient-caps=-all ",
    "--securebits=+noroot,+noroot_locked,+no_setuid_fixup,+no_setuid_fixup_locked ",
    "--pdeathsig SIGKILL \"$shell\" -c ",
    "'target_path=$1; shift; kill -STOP $$ || exit 125; PATH=$target_path; export PATH; exec \"$@\"' ",
    "iorec-confined \"$target_path\" \"$@\"",
);

const TRANSPARENT_FIRST_STAGE_SCRIPT: &str = concat!(
    "priv=$1; shell=$2; mount=$3; hosts=$4; target_path=$5; target_uid=$6; target_gid=$7; shift 7; ",
    "\"$mount\" --make-rprivate / || exit 125; ",
    "\"$mount\" --bind \"$hosts\" /etc/hosts || exit 125; ",
    "\"$mount\" -o remount,bind,ro /etc/hosts || exit 125; ",
    "kill -STOP $$ || exit 125; ",
    "exec \"$priv\" --reuid \"$target_uid\" --regid \"$target_gid\" --clear-groups ",
    "--no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all ",
    "--securebits=+noroot,+noroot_locked,+no_setuid_fixup,+no_setuid_fixup_locked ",
    "--pdeathsig SIGKILL \"$shell\" -c ",
    "'target_path=$1; shift; kill -STOP $$ || exit 125; PATH=$target_path; export PATH; exec \"$@\"' ",
    "iorec-confined \"$target_path\" \"$@\"",
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskNetnsPolicy {
    ProxyOnly,
    Transparent {
        endpoints: Vec<SocketAddr>,
        hosts_path: PathBuf,
    },
}

impl TaskNetnsPolicy {
    pub fn transparent(endpoints: &[SocketAddr], hosts_path: &Path) -> io::Result<Self> {
        let mut endpoints = endpoints.to_vec();
        endpoints.sort_unstable();
        endpoints.dedup();
        if endpoints.is_empty()
            || endpoints.len() > MAX_TRANSPARENT_ENDPOINTS
            || endpoints.iter().any(|endpoint| {
                let std::net::IpAddr::V4(address) = endpoint.ip() else {
                    return true;
                };
                address.is_unspecified()
                    || address.is_loopback()
                    || address.is_multicast()
                    || address.is_broadcast()
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transparent task-network policy requires 1 to 64 unique, usable, non-loopback IPv4 endpoints",
            ));
        }
        if !hosts_path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transparent hosts snapshot path must be absolute",
            ));
        }
        Ok(Self::Transparent {
            endpoints,
            hosts_path: hosts_path.to_owned(),
        })
    }

    #[must_use]
    pub const fn mode(&self) -> &'static str {
        match self {
            Self::ProxyOnly => "proxy_only",
            Self::Transparent { .. } => "transparent",
        }
    }

    #[must_use]
    pub fn endpoints(&self) -> &[SocketAddr] {
        match self {
            Self::ProxyOnly => &[],
            Self::Transparent { endpoints, .. } => endpoints,
        }
    }

    fn hosts_path(&self) -> Option<&Path> {
        match self {
            Self::ProxyOnly => None,
            Self::Transparent { hosts_path, .. } => Some(hosts_path),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaskNetnsTools {
    unshare: PathBuf,
    setpriv: PathBuf,
    shell: PathBuf,
    slirp4netns: PathBuf,
    nsenter: PathBuf,
    nft: PathBuf,
    sysctl: PathBuf,
    tcpdump: PathBuf,
    newuidmap: PathBuf,
    newgidmap: PathBuf,
    mount: PathBuf,
    current_uid: u32,
    current_gid: u32,
    subordinate_uid: u32,
    subordinate_gid: u32,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct NamespaceIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct FirewallCounters {
    pub loopback_packets: u64,
    pub proxy_packets: u64,
    pub transparent_packets: u64,
    pub denied_packets: u64,
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct TargetConfinementReport {
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub capabilities_zero: bool,
    pub bounding_capabilities_zero: bool,
    pub no_new_privileges: bool,
    pub user_namespace: NamespaceIdentity,
    pub network_namespace: NamespaceIdentity,
    pub mount_namespace: Option<NamespaceIdentity>,
    pub hosts_snapshot_read_only: bool,
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct TaskNetnsReport {
    pub backend: &'static str,
    pub cidr: &'static str,
    pub guest_address: &'static str,
    pub host_gateway: &'static str,
    pub proxy_port: u16,
    pub policy_mode: &'static str,
    pub transparent_endpoint_count: usize,
    pub user_namespace: NamespaceIdentity,
    pub network_namespace: NamespaceIdentity,
    pub mount_namespace: Option<NamespaceIdentity>,
    pub hosts_snapshot_verified_at_start: bool,
    pub firewall_verified_at_target_start: bool,
    pub firewall_verified_at_target_end: bool,
    pub firewall_verified_at_stop: bool,
    pub ipv6_disabled_at_start: bool,
    pub ipv6_disabled_at_stop: bool,
    pub firewall_before_target: FirewallCounters,
    pub firewall_after_target: FirewallCounters,
    pub firewall_at_stop: FirewallCounters,
    pub firewall: FirewallCounters,
    pub post_target_firewall: FirewallCounters,
    pub helper_exited_before_stop: bool,
    pub helper_exit_success: bool,
    pub helper_exit_code: Option<i32>,
    pub helper_termination_signal: Option<i32>,
    pub helper_forced_kill: bool,
    pub helper_stdout_bytes: u64,
    pub helper_stdout_omitted: u64,
    pub helper_stderr_bytes: u64,
    pub helper_stderr_omitted: u64,
}

impl TaskNetnsReport {
    #[must_use]
    pub fn complete(&self) -> bool {
        self.firewall_verified_at_target_start
            && self.firewall_verified_at_target_end
            && self.firewall_verified_at_stop
            && self.ipv6_disabled_at_start
            && self.ipv6_disabled_at_stop
            && (self.policy_mode != "transparent" || self.hosts_snapshot_verified_at_start)
            && self.post_target_firewall == FirewallCounters::default()
            && !self.helper_exited_before_stop
            && !self.helper_forced_kill
            && self.helper_stdout_omitted == 0
            && self.helper_stderr_omitted == 0
            && (self.helper_exit_success
                || self.helper_termination_signal == Some(Signal::SIGTERM as i32))
    }
}

#[derive(Debug, Default)]
struct BoundedOutput {
    total: u64,
    omitted: u64,
    retained: Vec<u8>,
}

pub struct TaskNetnsHandle {
    child: Child,
    process_group: u32,
    stdout: JoinHandle<io::Result<BoundedOutput>>,
    stderr: JoinHandle<io::Result<BoundedOutput>>,
    target_pid: u32,
    proxy_port: u16,
    user_namespace: NamespaceIdentity,
    network_namespace: NamespaceIdentity,
    mount_namespace: Option<NamespaceIdentity>,
    hosts_snapshot_verified_at_start: bool,
    policy: TaskNetnsPolicy,
    firewall_before_target: Option<FirewallCounters>,
    firewall_after_target: Option<FirewallCounters>,
    tools: TaskNetnsTools,
}

impl TaskNetnsTools {
    pub fn discover() -> io::Result<Self> {
        if std::env::consts::OS != "linux" {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "task network isolation is supported only on Linux",
            ));
        }
        let identity = fs::metadata("/proc/self")?;
        let account_user_id = identity.uid();
        let primary_group_id = identity.gid();
        if account_user_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "rootless task network isolation refuses to launch a target from a root recorder",
            ));
        }
        require_nonzero_if_present(Path::new("/proc/sys/user/max_user_namespaces"))?;
        require_nonzero_if_present(Path::new("/proc/sys/kernel/unprivileged_userns_clone"))?;
        let subordinate_user_id = subordinate_id(Path::new("/etc/subuid"), account_user_id, "UID")?;
        let subordinate_group_id =
            subordinate_id(Path::new("/etc/subgid"), account_user_id, "GID")?;
        Ok(Self {
            unshare: require_tool("unshare", &["/usr/bin/unshare", "/bin/unshare"])?,
            setpriv: require_tool("setpriv", &["/usr/bin/setpriv", "/bin/setpriv"])?,
            shell: require_tool("shell", &["/bin/sh", "/usr/bin/sh"])?,
            slirp4netns: require_tool("slirp4netns", &["/usr/bin/slirp4netns"])?,
            nsenter: require_tool("nsenter", &["/usr/bin/nsenter", "/bin/nsenter"])?,
            nft: require_tool("nft", &["/usr/sbin/nft", "/sbin/nft"])?,
            sysctl: require_tool("sysctl", &["/usr/sbin/sysctl", "/sbin/sysctl"])?,
            tcpdump: crate::pcap::trusted_tcpdump_path().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no trusted fixed-path tcpdump executable was found",
                )
            })?,
            newuidmap: require_setuid_tool("newuidmap", "/usr/bin/newuidmap")?,
            newgidmap: require_setuid_tool("newgidmap", "/usr/bin/newgidmap")?,
            mount: require_tool("mount", &["/usr/bin/mount", "/bin/mount"])?,
            current_uid: account_user_id,
            current_gid: primary_group_id,
            subordinate_uid: subordinate_user_id,
            subordinate_gid: subordinate_group_id,
        })
    }

    pub fn target_command(
        &self,
        target: &[OsString],
        policy: &TaskNetnsPolicy,
    ) -> io::Result<Command> {
        if target.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "task network isolation requires a target command",
            ));
        }
        let mut command = Command::new(&self.setpriv);
        let original_path =
            std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin"));
        command
            .arg("--pdeathsig")
            .arg("SIGKILL")
            .arg(&self.unshare)
            .arg("--user")
            .arg(format!("--map-users=0:{}:1", self.subordinate_uid))
            .arg(format!("--map-users={0}:{0}:1", self.current_uid))
            .arg(format!("--map-groups=0:{}:1", self.subordinate_gid))
            .arg(format!("--map-groups={0}:{0}:1", self.current_gid))
            .arg("--keep-caps")
            .arg("--net");
        if matches!(policy, TaskNetnsPolicy::Transparent { .. }) {
            command.arg("--mount").arg("--setuid=0").arg("--setgid=0");
        }
        command.arg("--").arg(&self.shell).arg("-c");
        if let Some(hosts_path) = policy.hosts_path() {
            command
                .arg(TRANSPARENT_FIRST_STAGE_SCRIPT)
                .arg("iorec-task-netns-transparent")
                .arg(&self.setpriv)
                .arg(&self.shell)
                .arg(&self.mount)
                .arg(hosts_path)
                .arg(original_path)
                .arg(self.current_uid.to_string())
                .arg(self.current_gid.to_string())
                .args(target);
        } else {
            command
                .arg(FIRST_STAGE_SCRIPT)
                .arg("iorec-task-netns")
                .arg(&self.setpriv)
                .arg(&self.shell)
                .arg(original_path)
                .args(target);
        }
        Ok(command)
    }

    #[must_use]
    pub fn helper_paths(&self) -> Vec<&Path> {
        vec![
            &self.unshare,
            &self.setpriv,
            &self.shell,
            &self.slirp4netns,
            &self.nsenter,
            &self.nft,
            &self.sysctl,
            &self.tcpdump,
            &self.newuidmap,
            &self.newgidmap,
            &self.mount,
        ]
    }
}

impl TaskNetnsHandle {
    pub async fn start(
        tools: TaskNetnsTools,
        target_pid: u32,
        proxy_port: u16,
        policy: TaskNetnsPolicy,
    ) -> io::Result<Self> {
        if target_pid == 0 || proxy_port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "task network isolation requires a target PID and proxy port",
            ));
        }
        let user_namespace = namespace_identity(target_pid, "user")?;
        let network_namespace = namespace_identity(target_pid, "net")?;
        if user_namespace == namespace_identity(std::process::id(), "user")?
            || network_namespace == namespace_identity(std::process::id(), "net")?
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "target did not enter distinct user and network namespaces",
            ));
        }
        let mount_namespace = if let Some(hosts_path) = policy.hosts_path() {
            let mount_namespace = namespace_identity(target_pid, "mnt")?;
            if mount_namespace == namespace_identity(std::process::id(), "mnt")? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "transparent target did not enter a distinct mount namespace",
                ));
            }
            verify_hosts_snapshot(target_pid, hosts_path)?;
            Some(mount_namespace)
        } else {
            None
        };

        configure_network_sysctls(&tools, target_pid).await?;
        verify_network_sysctls(&tools, target_pid).await?;

        let mut command = Command::new(&tools.slirp4netns);
        command
            .env_clear()
            .env("LC_ALL", "C")
            .arg("--configure")
            .arg("--ready-fd=1")
            .arg(format!("--cidr={SLIRP_CIDR}"))
            .arg("--disable-dns")
            .arg("--enable-sandbox")
            .arg("--enable-seccomp")
            .arg(target_pid.to_string())
            .arg("tap0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = command.spawn()?;
        let process_group = child
            .id()
            .ok_or_else(|| io::Error::other("slirp4netns helper has no PID"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("slirp4netns stdout was not piped"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("slirp4netns stderr was not piped"))?;
        let (ready_tx, ready_rx) = oneshot::channel();
        let stdout = tokio::spawn(capture_ready_output(stdout, ready_tx));
        let stderr = tokio::spawn(capture_output(stderr));
        match tokio::time::timeout(START_TIMEOUT, ready_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                force_kill(&mut child, process_group).await;
                let _ = stdout.await;
                let _ = stderr.await;
                return Err(error);
            }
            Ok(Err(_)) => {
                force_kill(&mut child, process_group).await;
                let _ = stdout.await;
                let _ = stderr.await;
                return Err(io::Error::other(
                    "slirp4netns readiness channel closed unexpectedly",
                ));
            }
            Err(_) => {
                force_kill(&mut child, process_group).await;
                let _ = stdout.await;
                let _ = stderr.await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "slirp4netns did not configure the task network before its deadline",
                ));
            }
        }

        if let Err(error) = apply_firewall(&tools, target_pid, proxy_port, &policy).await {
            force_kill(&mut child, process_group).await;
            let _ = stdout.await;
            let _ = stderr.await;
            return Err(error);
        }
        if let Err(error) = query_firewall(&tools, target_pid, proxy_port, &policy).await {
            force_kill(&mut child, process_group).await;
            let _ = stdout.await;
            let _ = stderr.await;
            return Err(error);
        }
        if let Err(error) = verify_network_sysctls(&tools, target_pid).await {
            force_kill(&mut child, process_group).await;
            let _ = stdout.await;
            let _ = stderr.await;
            return Err(error);
        }

        Ok(Self {
            child,
            process_group,
            stdout,
            stderr,
            target_pid,
            proxy_port,
            user_namespace,
            network_namespace,
            mount_namespace,
            hosts_snapshot_verified_at_start: policy.hosts_path().is_some(),
            policy,
            firewall_before_target: None,
            firewall_after_target: None,
            tools,
        })
    }

    #[must_use]
    pub const fn user_namespace(&self) -> NamespaceIdentity {
        self.user_namespace
    }

    #[must_use]
    pub const fn network_namespace(&self) -> NamespaceIdentity {
        self.network_namespace
    }

    #[must_use]
    pub const fn mount_namespace(&self) -> Option<NamespaceIdentity> {
        self.mount_namespace
    }

    #[must_use]
    pub fn hosts_path(&self) -> Option<&Path> {
        self.policy.hosts_path()
    }

    #[must_use]
    pub const fn policy_mode(&self) -> &'static str {
        self.policy.mode()
    }

    #[must_use]
    pub const fn proxy_port(&self) -> u16 {
        self.proxy_port
    }

    pub fn ensure_running(&mut self) -> io::Result<()> {
        if self.child.try_wait()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "slirp4netns exited before the target launch barrier was released",
            ));
        }
        Ok(())
    }

    pub async fn seal_target_start(&mut self) -> io::Result<FirewallCounters> {
        if self.firewall_before_target.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "task-network target window was already started",
            ));
        }
        self.ensure_running()?;
        let counters =
            query_firewall(&self.tools, self.target_pid, self.proxy_port, &self.policy).await?;
        self.firewall_before_target = Some(counters);
        Ok(counters)
    }

    pub async fn seal_target_end(
        &mut self,
        namespace_anchor_pid: Option<u32>,
    ) -> io::Result<FirewallCounters> {
        if self.firewall_before_target.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "task-network target window was not started",
            ));
        }
        if self.firewall_after_target.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "task-network target window was already ended",
            ));
        }
        self.ensure_running()?;
        let anchor = namespace_anchor_pid
            .filter(|pid| Path::new(&format!("/proc/{pid}")).is_dir())
            .or_else(|| {
                Path::new(&format!("/proc/{}", self.target_pid))
                    .is_dir()
                    .then_some(self.target_pid)
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "task network namespace disappeared before its target window ended",
                )
            })?;
        let counters = query_firewall(&self.tools, anchor, self.proxy_port, &self.policy).await?;
        let before = self.firewall_before_target.unwrap_or_default();
        firewall_delta(counters, before)?;
        self.firewall_after_target = Some(counters);
        Ok(counters)
    }

    pub async fn stop(mut self, namespace_anchor_pid: Option<u32>) -> io::Result<TaskNetnsReport> {
        let anchor = namespace_anchor_pid
            .filter(|pid| Path::new(&format!("/proc/{pid}")).is_dir())
            .or_else(|| {
                Path::new(&format!("/proc/{}", self.target_pid))
                    .is_dir()
                    .then_some(self.target_pid)
            });
        let firewall_at_stop = if let Some(anchor) = anchor {
            query_firewall(&self.tools, anchor, self.proxy_port, &self.policy).await
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "task network namespace disappeared before final firewall verification",
            ))
        };
        let ipv6_disabled_at_stop = if let Some(anchor) = anchor {
            verify_network_sysctls(&self.tools, anchor).await.is_ok()
        } else {
            false
        };
        let helper_exited_before_stop = self.child.try_wait()?.is_some();
        let mut forced_kill = false;
        if !helper_exited_before_stop && signal_group(self.process_group, Signal::SIGTERM).is_err()
        {
            forced_kill = true;
            force_kill(&mut self.child, self.process_group).await;
        }
        let status = if let Some(status) = self.child.try_wait()? {
            status
        } else if let Ok(status) = tokio::time::timeout(STOP_TIMEOUT, self.child.wait()).await {
            status?
        } else {
            forced_kill = true;
            force_kill(&mut self.child, self.process_group).await;
            self.child.wait().await?
        };
        let mut stdout_task = self.stdout;
        let mut stderr_task = self.stderr;
        let readers = tokio::time::timeout(READER_TIMEOUT, async {
            tokio::join!(&mut stdout_task, &mut stderr_task)
        })
        .await;
        let Ok((stdout, stderr)) = readers else {
            stdout_task.abort();
            stderr_task.abort();
            let _ = tokio::join!(&mut stdout_task, &mut stderr_task);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "task-network helper output readers did not stop",
            ));
        };
        let stdout = stdout
            .map_err(|error| io::Error::other(format!("slirp stdout task panicked: {error}")))??;
        let stderr = stderr
            .map_err(|error| io::Error::other(format!("slirp stderr task panicked: {error}")))??;
        let firewall_before_target = self.firewall_before_target.unwrap_or_default();
        let firewall_after_target = self.firewall_after_target.unwrap_or_default();
        let firewall_at_stop_counters = firewall_at_stop.as_ref().copied().unwrap_or_default();
        let firewall = self
            .firewall_before_target
            .zip(self.firewall_after_target)
            .map(|(before, after)| firewall_delta(after, before))
            .transpose()?
            .unwrap_or_default();
        let post_target_firewall = self
            .firewall_after_target
            .zip(firewall_at_stop.as_ref().ok().copied())
            .map(|(after, at_stop)| firewall_delta(at_stop, after))
            .transpose()?
            .unwrap_or_default();
        Ok(TaskNetnsReport {
            backend: "rootless-user-netns-slirp4netns-nftables-v2",
            cidr: SLIRP_CIDR,
            guest_address: GUEST_ADDRESS,
            host_gateway: HOST_GATEWAY,
            proxy_port: self.proxy_port,
            policy_mode: self.policy.mode(),
            transparent_endpoint_count: self.policy.endpoints().len(),
            user_namespace: self.user_namespace,
            network_namespace: self.network_namespace,
            mount_namespace: self.mount_namespace,
            hosts_snapshot_verified_at_start: self.hosts_snapshot_verified_at_start,
            firewall_verified_at_target_start: self.firewall_before_target.is_some(),
            firewall_verified_at_target_end: self.firewall_after_target.is_some(),
            firewall_verified_at_stop: firewall_at_stop.is_ok(),
            ipv6_disabled_at_start: true,
            ipv6_disabled_at_stop,
            firewall_before_target,
            firewall_after_target,
            firewall_at_stop: firewall_at_stop_counters,
            firewall,
            post_target_firewall,
            helper_exited_before_stop,
            helper_exit_success: status.success(),
            helper_exit_code: status.code(),
            helper_termination_signal: status.signal(),
            helper_forced_kill: forced_kill,
            helper_stdout_bytes: stdout.total,
            helper_stdout_omitted: stdout.omitted,
            helper_stderr_bytes: stderr.total,
            helper_stderr_omitted: stderr.omitted,
        })
    }
}

fn firewall_delta(
    after: FirewallCounters,
    before: FirewallCounters,
) -> io::Result<FirewallCounters> {
    Ok(FirewallCounters {
        loopback_packets: after
            .loopback_packets
            .checked_sub(before.loopback_packets)
            .ok_or_else(|| counter_regressed("loopback"))?,
        proxy_packets: after
            .proxy_packets
            .checked_sub(before.proxy_packets)
            .ok_or_else(|| counter_regressed("proxy"))?,
        transparent_packets: after
            .transparent_packets
            .checked_sub(before.transparent_packets)
            .ok_or_else(|| counter_regressed("transparent redirect"))?,
        denied_packets: after
            .denied_packets
            .checked_sub(before.denied_packets)
            .ok_or_else(|| counter_regressed("deny"))?,
    })
}

fn counter_regressed(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("task-network {name} counter regressed during the target window"),
    )
}

pub fn verify_confined_target(
    target_pid: u32,
    expected_user_id: u32,
    expected_group_id: u32,
    expected_user_namespace: NamespaceIdentity,
    expected_network_namespace: NamespaceIdentity,
    expected_mount_namespace: Option<NamespaceIdentity>,
    expected_hosts_path: Option<&Path>,
) -> io::Result<TargetConfinementReport> {
    let status = read_limited(
        &Path::new("/proc")
            .join(target_pid.to_string())
            .join("status"),
        PROC_LIMIT,
    )?;
    let parsed = parse_target_status(&status)?;
    if parsed.effective_uid != expected_user_id
        || parsed.effective_gid != expected_group_id
        || !parsed.capabilities_zero
        || !parsed.bounding_capabilities_zero
        || !parsed.no_new_privileges
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target privilege drop was not complete before launch",
        ));
    }
    let user_namespace = namespace_identity(target_pid, "user")?;
    let network_namespace = namespace_identity(target_pid, "net")?;
    if user_namespace != expected_user_namespace || network_namespace != expected_network_namespace
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target namespace identity changed during its launch barrier",
        ));
    }
    let (mount_namespace, hosts_snapshot_read_only) =
        if let Some(expected) = expected_mount_namespace {
            let actual = namespace_identity(target_pid, "mnt")?;
            if actual != expected {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "target mount namespace identity changed during its launch barrier",
                ));
            }
            let hosts_path = expected_hosts_path.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "transparent target verification is missing its hosts snapshot",
                )
            })?;
            verify_hosts_snapshot(target_pid, hosts_path)?;
            (Some(actual), true)
        } else {
            if expected_hosts_path.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "hosts snapshot was provided without an expected mount namespace",
                ));
            }
            (None, false)
        };
    Ok(TargetConfinementReport {
        effective_uid: parsed.effective_uid,
        effective_gid: parsed.effective_gid,
        capabilities_zero: parsed.capabilities_zero,
        bounding_capabilities_zero: parsed.bounding_capabilities_zero,
        no_new_privileges: parsed.no_new_privileges,
        user_namespace,
        network_namespace,
        mount_namespace,
        hosts_snapshot_read_only,
    })
}

#[derive(Debug, Clone, Copy)]
struct ParsedTargetStatus {
    effective_uid: u32,
    effective_gid: u32,
    capabilities_zero: bool,
    bounding_capabilities_zero: bool,
    no_new_privileges: bool,
}

fn parse_target_status(bytes: &[u8]) -> io::Result<ParsedTargetStatus> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "target status is not UTF-8"))?;
    let effective_user_id = parse_status_id(text, "Uid:")?;
    let effective_group_id = parse_status_id(text, "Gid:")?;
    let capabilities_zero = ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
        .into_iter()
        .map(|field| parse_status_hex(text, field))
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .all(|value| value == 0);
    let bounding_capabilities_zero = parse_status_hex(text, "CapBnd:")? == 0;
    let no_new_privileges = parse_status_decimal(text, "NoNewPrivs:")? == 1;
    Ok(ParsedTargetStatus {
        effective_uid: effective_user_id,
        effective_gid: effective_group_id,
        capabilities_zero,
        bounding_capabilities_zero,
        no_new_privileges,
    })
}

fn parse_status_id(text: &str, name: &str) -> io::Result<u32> {
    let values = status_value(text, name)?
        .split_ascii_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid target identity"))?;
    if values.len() != 4 || values.iter().any(|value| *value != values[0]) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target real/effective/saved/filesystem identity differs",
        ));
    }
    Ok(values[1])
}

fn parse_status_hex(text: &str, name: &str) -> io::Result<u64> {
    u64::from_str_radix(status_value(text, name)?.trim(), 16).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "target capability status is invalid",
        )
    })
}

fn parse_status_decimal(text: &str, name: &str) -> io::Result<u64> {
    status_value(text, name)?
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "target status value is invalid"))
}

fn status_value<'a>(text: &'a str, name: &str) -> io::Result<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(name))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target status field is missing"))
}

async fn configure_network_sysctls(tools: &TaskNetnsTools, target_pid: u32) -> io::Result<()> {
    let mut command = namespace_command(tools, target_pid, tools.sysctl.as_os_str());
    command
        .arg("-q")
        .arg("-w")
        .arg("net.ipv6.conf.all.disable_ipv6=1")
        .arg("net.ipv6.conf.default.disable_ipv6=1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let status = tokio::time::timeout(COMMAND_TIMEOUT, child.wait())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "network sysctl apply timed out"))??;
    if !status.success() {
        return Err(io::Error::other(
            "task namespace rejected the fixed IPv6-disable policy",
        ));
    }
    Ok(())
}

async fn verify_network_sysctls(tools: &TaskNetnsTools, target_pid: u32) -> io::Result<()> {
    let mut command = namespace_command(tools, target_pid, tools.sysctl.as_os_str());
    command
        .arg("-n")
        .arg("net.ipv6.conf.all.disable_ipv6")
        .arg("net.ipv6.conf.default.disable_ipv6")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("sysctl output was not piped"))?;
    let reader = tokio::spawn(read_bounded(stdout));
    let status = tokio::time::timeout(COMMAND_TIMEOUT, child.wait())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "network sysctl query timed out"))??;
    let bytes = reader
        .await
        .map_err(|error| io::Error::other(format!("sysctl output task panicked: {error}")))??;
    if !status.success() || bytes != b"1\n1\n" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "task namespace IPv6-disable policy could not be verified",
        ));
    }
    Ok(())
}

async fn apply_firewall(
    tools: &TaskNetnsTools,
    target_pid: u32,
    proxy_port: u16,
    policy: &TaskNetnsPolicy,
) -> io::Result<()> {
    let script = firewall_script(proxy_port, policy);
    let mut command = namespace_command(tools, target_pid, tools.nft.as_os_str());
    command
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("nft input was not piped"))?;
    stdin.write_all(script.as_bytes()).await?;
    stdin.shutdown().await?;
    drop(stdin);
    let status = tokio::time::timeout(COMMAND_TIMEOUT, child.wait())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "nft apply timed out"))??;
    if !status.success() {
        return Err(io::Error::other(
            "nft rejected the fixed task-egress policy",
        ));
    }
    Ok(())
}

async fn query_firewall(
    tools: &TaskNetnsTools,
    target_pid: u32,
    proxy_port: u16,
    policy: &TaskNetnsPolicy,
) -> io::Result<FirewallCounters> {
    let mut command = namespace_command(tools, target_pid, tools.nft.as_os_str());
    command
        .arg("--json")
        .arg("list")
        .arg("ruleset")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("nft output was not piped"))?;
    let reader = tokio::spawn(read_bounded(stdout));
    let status = tokio::time::timeout(COMMAND_TIMEOUT, child.wait())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "nft query timed out"))??;
    let bytes = reader
        .await
        .map_err(|error| io::Error::other(format!("nft output task panicked: {error}")))??;
    if !status.success() {
        return Err(io::Error::other(
            "nft could not verify the task-egress policy",
        ));
    }
    parse_firewall_report(&bytes, proxy_port, policy)
}

fn namespace_command(tools: &TaskNetnsTools, target_pid: u32, program: &OsStr) -> Command {
    let mut command = Command::new(&tools.nsenter);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .arg("--target")
        .arg(target_pid.to_string())
        .arg("--user")
        .arg("--net")
        .arg("--preserve-credentials")
        .arg("--keep-caps")
        .arg(program);
    command
}

fn firewall_script(proxy_port: u16, policy: &TaskNetnsPolicy) -> String {
    let mut script = String::from("flush ruleset\n");
    if !policy.endpoints().is_empty() {
        script.push_str("table ip iorec_nat {\n chain output {\n  type nat hook output priority -100; policy accept;\n");
        for (index, endpoint) in policy.endpoints().iter().enumerate() {
            let _ = writeln!(
                script,
                "  ip daddr {} tcp dport {} counter dnat to {HOST_GATEWAY}:{proxy_port} comment \"iorec-transparent-{index}\"",
                endpoint.ip(),
                endpoint.port(),
            );
        }
        script.push_str(" }\n}\n");
    }
    let _ = write!(
        script,
        concat!(
            "table inet iorec {{\n",
            " chain output {{\n",
            "  type filter hook output priority filter; policy drop;\n",
            "  oifname \"lo\" counter accept comment \"iorec-loopback\"\n",
            "  ip daddr 10.0.2.2 tcp dport {proxy_port} counter accept comment \"iorec-proxy\"\n",
            "  counter drop comment \"iorec-deny\"\n",
            " }}\n",
            "}}\n",
        ),
        proxy_port = proxy_port,
    );
    script
}

fn parse_firewall_report(
    bytes: &[u8],
    proxy_port: u16,
    policy: &TaskNetnsPolicy,
) -> io::Result<FirewallCounters> {
    if bytes.len() > OUTPUT_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nft report exceeds its safety limit",
        ));
    }
    let document: Value = serde_json::from_slice(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "nft report is invalid JSON"))?;
    let entries = document
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "nft report has no entries"))?;
    let mut filter_table_count = 0_usize;
    let mut nat_table_count = 0_usize;
    let mut filter_chain_count = 0_usize;
    let mut nat_chain_count = 0_usize;
    let mut filter_rule_count = 0_usize;
    let mut loopback = None;
    let mut proxy = None;
    let mut deny = None;
    let mut transparent = vec![None; policy.endpoints().len()];
    for entry in entries {
        if let Some(table) = entry.get("table") {
            match (
                table.get("family").and_then(Value::as_str),
                table.get("name").and_then(Value::as_str),
            ) {
                (Some("inet"), Some(NFT_TABLE)) => {
                    filter_table_count = filter_table_count.saturating_add(1);
                }
                (Some("ip"), Some(NFT_NAT_TABLE)) if !transparent.is_empty() => {
                    nat_table_count = nat_table_count.saturating_add(1);
                }
                _ => return Err(unexpected_firewall_entry()),
            }
            continue;
        }
        if let Some(chain) = entry.get("chain") {
            let family = chain.get("family").and_then(Value::as_str);
            let table = chain.get("table").and_then(Value::as_str);
            let name = chain.get("name").and_then(Value::as_str);
            if family == Some("inet") && table == Some(NFT_TABLE) && name == Some(NFT_CHAIN) {
                let valid = chain.get("type").and_then(Value::as_str) == Some("filter")
                    && chain.get("hook").and_then(Value::as_str) == Some("output")
                    && chain.get("policy").and_then(Value::as_str) == Some("drop")
                    && chain.get("prio").and_then(Value::as_i64) == Some(0);
                if !valid {
                    return Err(unexpected_firewall_entry());
                }
                filter_chain_count = filter_chain_count.saturating_add(1);
            } else if family == Some("ip")
                && table == Some(NFT_NAT_TABLE)
                && name == Some(NFT_CHAIN)
                && !transparent.is_empty()
            {
                let valid = chain.get("type").and_then(Value::as_str) == Some("nat")
                    && chain.get("hook").and_then(Value::as_str) == Some("output")
                    && chain.get("policy").and_then(Value::as_str) == Some("accept")
                    && chain.get("prio").and_then(Value::as_i64) == Some(-100);
                if !valid {
                    return Err(unexpected_firewall_entry());
                }
                nat_chain_count = nat_chain_count.saturating_add(1);
            } else {
                return Err(unexpected_firewall_entry());
            }
            continue;
        }
        let Some(rule) = entry.get("rule") else {
            if entry.get("metainfo").is_some() {
                continue;
            }
            return Err(unexpected_firewall_entry());
        };
        let comment = rule.get("comment").and_then(Value::as_str).unwrap_or("");
        let expressions = rule.get("expr").and_then(Value::as_array).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "nft rule has no expressions")
        })?;
        let counter = expressions
            .iter()
            .find_map(|expression| expression.get("counter"))
            .and_then(|counter| counter.get("packets"))
            .and_then(Value::as_u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "nft rule has no counter"))?;
        let is_filter = rule.get("family").and_then(Value::as_str) == Some("inet")
            && rule.get("table").and_then(Value::as_str) == Some(NFT_TABLE)
            && rule.get("chain").and_then(Value::as_str) == Some(NFT_CHAIN);
        if is_filter {
            filter_rule_count = filter_rule_count.saturating_add(1);
        }
        match comment {
            "iorec-loopback"
                if is_filter
                    && expressions.len() == 3
                    && rule_has_verdict(expressions, "accept")
                    && rule_has_match(expressions, "meta", "oifname", &Value::from("lo")) =>
            {
                set_once(&mut loopback, counter)?;
            }
            "iorec-proxy"
                if is_filter
                    && expressions.len() == 4
                    && rule_has_verdict(expressions, "accept")
                    && rule_has_match(
                        expressions,
                        "payload",
                        "daddr",
                        &Value::from(HOST_GATEWAY),
                    )
                    && rule_has_match(
                        expressions,
                        "payload",
                        "dport",
                        &Value::from(proxy_port),
                    ) =>
            {
                set_once(&mut proxy, counter)?;
            }
            "iorec-deny"
                if is_filter && expressions.len() == 2 && rule_has_verdict(expressions, "drop") =>
            {
                set_once(&mut deny, counter)?;
            }
            _ if !is_filter => {
                let Some(index) = comment
                    .strip_prefix("iorec-transparent-")
                    .and_then(|index| index.parse::<usize>().ok())
                else {
                    return Err(unexpected_firewall_entry());
                };
                let endpoint = policy
                    .endpoints()
                    .get(index)
                    .ok_or_else(unexpected_firewall_entry)?;
                if rule.get("family").and_then(Value::as_str) != Some("ip")
                    || rule.get("table").and_then(Value::as_str) != Some(NFT_NAT_TABLE)
                    || rule.get("chain").and_then(Value::as_str) != Some(NFT_CHAIN)
                    || expressions.len() != 4
                    || !rule_has_match(
                        expressions,
                        "payload",
                        "daddr",
                        &Value::from(endpoint.ip().to_string()),
                    )
                    || !rule_has_match(
                        expressions,
                        "payload",
                        "dport",
                        &Value::from(endpoint.port()),
                    )
                    || !rule_has_dnat(expressions, proxy_port)
                {
                    return Err(unexpected_firewall_entry());
                }
                set_once(
                    transparent
                        .get_mut(index)
                        .ok_or_else(unexpected_firewall_entry)?,
                    counter,
                )?;
            }
            _ => return Err(unexpected_firewall_entry()),
        }
    }
    let expected_nat = usize::from(!transparent.is_empty());
    if filter_table_count != 1
        || filter_chain_count != 1
        || filter_rule_count != 3
        || nat_table_count != expected_nat
        || nat_chain_count != expected_nat
        || transparent.iter().any(Option::is_none)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nft task-egress chain is missing or not fail-closed",
        ));
    }
    Ok(FirewallCounters {
        loopback_packets: loopback.ok_or_else(|| missing_rule("loopback"))?,
        proxy_packets: proxy.ok_or_else(|| missing_rule("proxy"))?,
        transparent_packets: transparent
            .into_iter()
            .flatten()
            .fold(0_u64, u64::saturating_add),
        denied_packets: deny.ok_or_else(|| missing_rule("deny"))?,
    })
}

fn rule_has_dnat(expressions: &[Value], proxy_port: u16) -> bool {
    expressions.iter().any(|expression| {
        let Some(dnat) = expression.get("dnat") else {
            return false;
        };
        dnat.get("addr").and_then(Value::as_str) == Some(HOST_GATEWAY)
            && dnat.get("port").and_then(Value::as_u64) == Some(u64::from(proxy_port))
    })
}

fn unexpected_firewall_entry() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "nft task-egress policy contains an unexpected entry",
    )
}

fn rule_has_match(expressions: &[Value], kind: &str, field: &str, right: &Value) -> bool {
    expressions.iter().any(|expression| {
        let Some(matched) = expression.get("match") else {
            return false;
        };
        if matched.get("op").and_then(Value::as_str) != Some("==")
            || matched.get("right") != Some(right)
        {
            return false;
        }
        let Some(left) = matched.get("left").and_then(|left| left.get(kind)) else {
            return false;
        };
        match kind {
            "meta" => left.get("key").and_then(Value::as_str) == Some(field),
            "payload" => left.get("field").and_then(Value::as_str) == Some(field),
            _ => false,
        }
    })
}

fn rule_has_verdict(expressions: &[Value], verdict: &str) -> bool {
    expressions
        .iter()
        .any(|expression| expression.get(verdict).is_some())
}

fn set_once(slot: &mut Option<u64>, value: u64) -> io::Result<()> {
    if slot.replace(value).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nft task-egress policy contains a duplicate rule",
        ));
    }
    Ok(())
}

fn missing_rule(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("nft task-egress policy is missing its {name} rule"),
    )
}

fn namespace_identity(pid: u32, namespace: &str) -> io::Result<NamespaceIdentity> {
    let metadata = fs::metadata(
        Path::new("/proc")
            .join(pid.to_string())
            .join("ns")
            .join(namespace),
    )?;
    Ok(NamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn verify_hosts_snapshot(target_pid: u32, expected_path: &Path) -> io::Result<()> {
    let expected = fs::metadata(expected_path)?;
    if !expected.file_type().is_file() || expected.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "transparent hosts snapshot is not a private regular file",
        ));
    }
    let mounted_path = Path::new("/proc")
        .join(target_pid.to_string())
        .join("root/etc/hosts");
    let mounted_file = fs::File::open(&mounted_path)?;
    let mounted = mounted_file.metadata()?;
    if !mounted.file_type().is_file()
        || mounted.dev() != expected.dev()
        || mounted.ino() != expected.ino()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "transparent /etc/hosts is not the recorder snapshot bind mount",
        ));
    }
    let mountinfo = read_limited(
        &Path::new("/proc")
            .join(target_pid.to_string())
            .join("mountinfo"),
        PROC_LIMIT,
    )?;
    let mountinfo = std::str::from_utf8(&mountinfo)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mountinfo is not UTF-8"))?;
    let effective_mount_id = effective_mount_id(&mounted_file)?;
    verify_effective_hosts_mount(mountinfo, effective_mount_id)
}

fn verify_effective_hosts_mount(mountinfo: &str, effective_mount_id: u64) -> io::Result<()> {
    let mut matching_mounts = 0_usize;
    for line in mountinfo.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.first().and_then(|value| value.parse::<u64>().ok()) == Some(effective_mount_id)
            && fields.get(4).copied() == Some("/etc/hosts")
        {
            matching_mounts = matching_mounts.saturating_add(1);
            let options = fields.get(5).copied().unwrap_or_default();
            if !options.split(',').any(|option| option == "ro") {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "transparent /etc/hosts bind mount is writable",
                ));
            }
        }
    }
    if matching_mounts != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transparent /etc/hosts bind mount is missing or ambiguous",
        ));
    }
    Ok(())
}

fn effective_mount_id(file: &fs::File) -> io::Result<u64> {
    let fdinfo = read_limited(
        &Path::new("/proc/self/fdinfo").join(file.as_raw_fd().to_string()),
        4 * 1024,
    )?;
    let fdinfo = std::str::from_utf8(&fdinfo)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fdinfo is not UTF-8"))?;
    let mut mount_id = None;
    for line in fdinfo.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some("mnt_id:") {
            continue;
        }
        let value = fields
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "fdinfo mount ID is invalid")
            })?;
        if fields.next().is_some() || mount_id.replace(value).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fdinfo mount ID is ambiguous",
            ));
        }
    }
    mount_id
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fdinfo is missing its mount ID"))
}

fn require_tool(name: &str, candidates: &[&str]) -> io::Result<PathBuf> {
    trusted_root_executable(candidates).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no trusted fixed-path {name} executable was found"),
        )
    })
}

fn require_setuid_tool(name: &str, candidate: &str) -> io::Result<PathBuf> {
    let path = require_tool(name, &[candidate])?;
    let metadata = fs::metadata(&path)?;
    if metadata.permissions().mode() & 0o4000 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the trusted {name} helper is not set-user-ID root"),
        ));
    }
    Ok(path)
}

fn subordinate_id(path: &Path, current_uid: u32, kind: &str) -> io::Result<u32> {
    let passwd = read_trusted_root_file(Path::new("/etc/passwd"), PROC_LIMIT)?;
    let passwd = std::str::from_utf8(&passwd)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "/etc/passwd is not UTF-8"))?;
    let mut account = None;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next() else {
            continue;
        };
        let _password = fields.next();
        let Some(user_id) = fields.next() else {
            continue;
        };
        let Some(_group_id) = fields.next() else {
            continue;
        };
        if user_id.parse::<u32>().ok() == Some(current_uid)
            && !name.is_empty()
            && account.replace(name).is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the recorder UID has multiple passwd account names",
            ));
        }
    }
    let account = account.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "the recorder UID has no passwd account",
        )
    })?;
    let bytes = read_trusted_root_file(path, PROC_LIMIT)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("subordinate {kind} configuration is not UTF-8"),
        )
    })?;
    let uid_text = current_uid.to_string();
    let mut selected = None;
    for line in text.lines() {
        let mut fields = line.split(':');
        let Some(owner) = fields.next() else {
            continue;
        };
        let Some(start) = fields.next() else {
            continue;
        };
        let Some(count) = fields.next() else {
            continue;
        };
        if fields.next().is_some() || (owner != account && owner != uid_text) {
            continue;
        }
        let start = start.parse::<u32>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("subordinate {kind} start is invalid"),
            )
        })?;
        let count = count.parse::<u64>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("subordinate {kind} count is invalid"),
            )
        })?;
        if count == 0 || start == current_uid {
            continue;
        }
        selected = Some(selected.map_or(start, |existing: u32| existing.min(start)));
    }
    selected.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the recorder account has no usable subordinate {kind} mapping"),
        )
    })
}

fn read_trusted_root_file(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "rootless namespace identity configuration has unsafe ownership or permissions",
        ));
    }
    read_limited(path, maximum)
}

fn require_nonzero_if_present(path: &Path) -> io::Result<()> {
    let Ok(bytes) = read_limited(path, 64) else {
        return Ok(());
    };
    let value = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "user namespace limit is invalid",
            )
        })?;
    if value == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unprivileged user namespaces are disabled",
        ));
    }
    Ok(())
}

fn read_limited(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded control file exceeds its safety limit",
        ));
    }
    Ok(bytes)
}

async fn read_bounded(input: impl tokio::io::AsyncRead + Unpin) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input
        .take(
            u64::try_from(OUTPUT_LIMIT)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > OUTPUT_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "helper output exceeds its safety limit",
        ));
    }
    Ok(bytes)
}

async fn capture_ready_output(
    mut input: impl tokio::io::AsyncRead + Unpin,
    ready: oneshot::Sender<io::Result<()>>,
) -> io::Result<BoundedOutput> {
    let mut byte = [0_u8; 1];
    match input.read_exact(&mut byte).await {
        Ok(_) => {
            let _ = ready.send(Ok(()));
            capture_output(input).await
        }
        Err(error) => {
            let _ = ready.send(Err(io::Error::new(error.kind(), error.to_string())));
            Err(error)
        }
    }
}

async fn capture_output(mut input: impl tokio::io::AsyncRead + Unpin) -> io::Result<BoundedOutput> {
    let mut capture = BoundedOutput {
        retained: Vec::with_capacity(OUTPUT_LIMIT),
        ..BoundedOutput::default()
    };
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let length = input.read(&mut buffer).await?;
        if length == 0 {
            return Ok(capture);
        }
        capture.total = capture
            .total
            .saturating_add(u64::try_from(length).unwrap_or(u64::MAX));
        if length >= OUTPUT_LIMIT {
            capture.omitted = capture.omitted.saturating_add(
                u64::try_from(capture.retained.len().saturating_add(length - OUTPUT_LIMIT))
                    .unwrap_or(u64::MAX),
            );
            capture.retained.clear();
            capture
                .retained
                .extend_from_slice(&buffer[length - OUTPUT_LIMIT..length]);
            continue;
        }
        let overflow = capture
            .retained
            .len()
            .saturating_add(length)
            .saturating_sub(OUTPUT_LIMIT);
        if overflow > 0 {
            capture.retained.copy_within(overflow.., 0);
            capture.retained.truncate(capture.retained.len() - overflow);
            capture.omitted = capture
                .omitted
                .saturating_add(u64::try_from(overflow).unwrap_or(u64::MAX));
        }
        capture.retained.extend_from_slice(&buffer[..length]);
    }
}

fn signal_group(process_group: u32, signal: Signal) -> io::Result<()> {
    let pid = i32::try_from(process_group)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process group exceeds i32"))?;
    killpg(Pid::from_raw(pid), signal).map_err(|error| match error {
        Errno::ESRCH => io::Error::new(io::ErrorKind::NotFound, error),
        Errno::EPERM => io::Error::new(io::ErrorKind::PermissionDenied, error),
        _ => io::Error::other(error),
    })
}

async fn force_kill(child: &mut Child, process_group: u32) {
    let _ = signal_group(process_group, Signal::SIGKILL);
    let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_NFT: &str = r#"{
      "nftables": [
        {"table":{"family":"inet","name":"iorec"}},
        {"chain":{"family":"inet","table":"iorec","name":"output","type":"filter","hook":"output","prio":0,"policy":"drop"}},
        {"rule":{"family":"inet","table":"iorec","chain":"output","comment":"iorec-loopback","expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lo"}},{"counter":{"packets":4,"bytes":200}},{"accept":null}]}},
        {"rule":{"family":"inet","table":"iorec","chain":"output","comment":"iorec-proxy","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.0.2.2"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":43123}},{"counter":{"packets":9,"bytes":900}},{"accept":null}]}},
        {"rule":{"family":"inet","table":"iorec","chain":"output","comment":"iorec-deny","expr":[{"counter":{"packets":2,"bytes":120}},{"drop":null}]}}
      ]
    }"#;

    const VALID_TRANSPARENT_NFT: &str = r#"{
      "nftables": [
        {"table":{"family":"ip","name":"iorec_nat"}},
        {"chain":{"family":"ip","table":"iorec_nat","name":"output","type":"nat","hook":"output","prio":-100,"policy":"accept"}},
        {"rule":{"family":"ip","table":"iorec_nat","chain":"output","comment":"iorec-transparent-0","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"192.0.2.10"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"counter":{"packets":7,"bytes":700}},{"dnat":{"addr":"10.0.2.2","port":43123}}]}},
        {"table":{"family":"inet","name":"iorec"}},
        {"chain":{"family":"inet","table":"iorec","name":"output","type":"filter","hook":"output","prio":0,"policy":"drop"}},
        {"rule":{"family":"inet","table":"iorec","chain":"output","comment":"iorec-loopback","expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lo"}},{"counter":{"packets":4,"bytes":200}},{"accept":null}]}},
        {"rule":{"family":"inet","table":"iorec","chain":"output","comment":"iorec-proxy","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.0.2.2"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":43123}},{"counter":{"packets":9,"bytes":900}},{"accept":null}]}},
        {"rule":{"family":"inet","table":"iorec","chain":"output","comment":"iorec-deny","expr":[{"counter":{"packets":2,"bytes":120}},{"drop":null}]}}
      ]
    }"#;

    #[test]
    fn firewall_policy_is_fixed_and_numeric() {
        let script = firewall_script(43123, &TaskNetnsPolicy::ProxyOnly);
        assert!(script.contains("ip daddr 10.0.2.2 tcp dport 43123"));
        assert!(script.contains("policy drop"));
        assert!(!script.contains("accept established"));
    }

    #[test]
    fn parses_only_the_exact_fail_closed_firewall() {
        let counters =
            parse_firewall_report(VALID_NFT.as_bytes(), 43123, &TaskNetnsPolicy::ProxyOnly)
                .unwrap();
        assert_eq!(
            counters,
            FirewallCounters {
                loopback_packets: 4,
                proxy_packets: 9,
                transparent_packets: 0,
                denied_packets: 2,
            }
        );
        assert!(
            parse_firewall_report(VALID_NFT.as_bytes(), 43124, &TaskNetnsPolicy::ProxyOnly)
                .is_err()
        );
        let permissive = VALID_NFT.replace("\"policy\":\"drop\"", "\"policy\":\"accept\"");
        assert!(
            parse_firewall_report(permissive.as_bytes(), 43123, &TaskNetnsPolicy::ProxyOnly)
                .is_err()
        );
    }

    #[test]
    fn transparent_policy_requires_and_counts_exact_dnat_rules() {
        let policy = TaskNetnsPolicy::transparent(
            &["192.0.2.10:443".parse().unwrap()],
            Path::new("/tmp/iorec-test-hosts"),
        )
        .unwrap();
        let script = firewall_script(43123, &policy);
        assert!(script.contains("ip daddr 192.0.2.10 tcp dport 443"));
        assert!(script.contains("dnat to 10.0.2.2:43123"));
        assert!(script.contains("type nat hook output priority -100"));
        let counters =
            parse_firewall_report(VALID_TRANSPARENT_NFT.as_bytes(), 43123, &policy).unwrap();
        assert_eq!(counters.transparent_packets, 7);
        assert!(
            parse_firewall_report(
                VALID_TRANSPARENT_NFT
                    .replace("192.0.2.10", "192.0.2.11")
                    .as_bytes(),
                43123,
                &policy,
            )
            .is_err()
        );
        assert!(
            TaskNetnsPolicy::transparent(
                &["127.0.0.1:443".parse().unwrap()],
                Path::new("/tmp/iorec-test-hosts"),
            )
            .is_err()
        );
    }

    #[test]
    fn target_status_requires_zero_caps_and_no_new_privileges() {
        let valid = b"Uid:\t1003\t1003\t1003\t1003\nGid:\t1006\t1006\t1006\t1006\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
        let status = parse_target_status(valid).unwrap();
        assert_eq!(status.effective_uid, 1003);
        assert_eq!(status.effective_gid, 1006);
        assert!(status.capabilities_zero);
        assert!(status.bounding_capabilities_zero);
        assert!(status.no_new_privileges);

        let unsafe_status = String::from_utf8(valid.to_vec())
            .unwrap()
            .replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000002000");
        assert!(
            !parse_target_status(unsafe_status.as_bytes())
                .unwrap()
                .bounding_capabilities_zero
        );
    }

    #[test]
    fn firewall_window_delta_rejects_counter_regression() {
        let before = FirewallCounters {
            loopback_packets: 2,
            proxy_packets: 3,
            transparent_packets: 5,
            denied_packets: 1,
        };
        let after = FirewallCounters {
            loopback_packets: 5,
            proxy_packets: 12,
            transparent_packets: 13,
            denied_packets: 4,
        };
        assert_eq!(
            firewall_delta(after, before).unwrap(),
            FirewallCounters {
                loopback_packets: 3,
                proxy_packets: 9,
                transparent_packets: 8,
                denied_packets: 3,
            }
        );
        assert!(firewall_delta(before, after).is_err());
    }

    #[test]
    fn hosts_verification_uses_the_effective_stacked_mount() {
        let stacked = concat!(
            "1762 1730 259:1 /docker/hosts /etc/hosts rw,relatime - ext4 /dev/root rw\n",
            "1763 1762 0:231 /tmp/snapshot /etc/hosts ro,relatime - overlay overlay rw\n",
        );
        verify_effective_hosts_mount(stacked, 1763).unwrap();
        assert!(verify_effective_hosts_mount(stacked, 1762).is_err());
        assert!(verify_effective_hosts_mount(stacked, 9999).is_err());
    }
}
