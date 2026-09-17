use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

use serde::Serialize;

const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
const MAX_PROC_CGROUP_BYTES: u64 = 1024 * 1024;
const MAX_CGROUP_PROCS_BYTES: u64 = 4 * 1024 * 1024;
const MAX_REMAINING_PID_SAMPLE: usize = 1_024;

/// A uniquely-created cgroup-v2 task boundary. The target shell is placed in
/// this cgroup while stopped, before its real executable is allowed to run;
/// descendants then inherit the same boundary.
#[derive(Debug)]
pub struct TaskCgroup {
    path: PathBuf,
    removed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskCgroupReport {
    pub path: PathBuf,
    pub removed: bool,
    pub remaining_processes: u64,
    pub remaining_pids: Vec<u32>,
    pub pid_sample_truncated: bool,
}

impl TaskCgroup {
    pub fn create_current(run_id: &str) -> io::Result<Self> {
        let mount = Path::new(CGROUP_MOUNT).canonicalize()?;
        if !mount.join("cgroup.controllers").is_file() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the unified cgroup-v2 hierarchy is unavailable",
            ));
        }
        let membership = read_limited(Path::new("/proc/self/cgroup"), MAX_PROC_CGROUP_BYTES)?;
        let relative = unified_membership_path(&membership)?;
        let parent = mount.join(relative).canonicalize()?;
        if !parent.starts_with(&mount) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the current cgroup resolves outside the cgroup-v2 mount",
            ));
        }
        Self::create_in(&parent, run_id)
    }

    fn create_in(parent: &Path, run_id: &str) -> io::Result<Self> {
        validate_run_id(run_id)?;
        let name = format!("iorec-{run_id}");
        let path = parent.join(name);
        fs::create_dir(&path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "create delegated task cgroup under {}: {error}",
                    parent.display()
                ),
            )
        })?;
        Ok(Self {
            path,
            removed: false,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn assign(&self, pid: u32) -> io::Result<()> {
        if pid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot assign PID zero to a task cgroup",
            ));
        }
        // cgroupfs does not permit users to replace its virtual control files
        // with symlinks. O_NOFOLLOW is rejected by some kernels for these
        // virtual files, so the exact newly-created child path is opened
        // through the standard CLOEXEC file API.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(self.path.join("cgroup.procs"))?;
        // cgroup.procs treats every write as one complete command. Formatting
        // a line may issue a second newline-only write, which the kernel
        // rejects after already moving the process.
        file.write_all(pid.to_string().as_bytes())?;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<TaskCgroupReport> {
        let bytes = read_limited(&self.path.join("cgroup.procs"), MAX_CGROUP_PROCS_BYTES)?;
        let mut remaining_processes = 0_u64;
        let mut remaining_pids = Vec::new();
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let text = std::str::from_utf8(line).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "cgroup.procs is not UTF-8")
            })?;
            let pid = text.parse::<u32>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cgroup.procs contains an invalid PID",
                )
            })?;
            remaining_processes = remaining_processes.saturating_add(1);
            if remaining_pids.len() < MAX_REMAINING_PID_SAMPLE {
                remaining_pids.push(pid);
            }
        }
        remaining_pids.sort_unstable();
        let removed = if remaining_processes == 0 {
            remove_empty_cgroup(&self.path)?;
            self.removed = true;
            true
        } else {
            false
        };
        Ok(TaskCgroupReport {
            path: self.path.clone(),
            removed,
            remaining_processes,
            pid_sample_truncated: remaining_processes
                > u64::try_from(remaining_pids.len()).unwrap_or(u64::MAX),
            remaining_pids,
        })
    }
}

fn remove_empty_cgroup(path: &Path) -> io::Result<()> {
    // cgroupfs control files are virtual and do not make rmdir report a
    // non-empty directory. Unit-test fixtures use an ordinary file instead.
    #[cfg(test)]
    fs::remove_file(path.join("cgroup.procs"))?;
    fs::remove_dir(path)
}

impl Drop for TaskCgroup {
    fn drop(&mut self) {
        if !self.removed {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn read_limited(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cgroup control file exceeds its safety limit",
        ));
    }
    Ok(bytes)
}

fn unified_membership_path(bytes: &[u8]) -> io::Result<PathBuf> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "/proc/self/cgroup is not UTF-8")
    })?;
    let mut found = None;
    for line in text.lines() {
        let Some(path) = line.strip_prefix("0::") else {
            continue;
        };
        if found.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "multiple unified cgroup memberships were reported",
            ));
        }
        let path = Path::new(path);
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the unified cgroup membership path is invalid",
            ));
        }
        found = Some(path.strip_prefix("/").unwrap_or(path).to_path_buf());
    }
    found.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "the process has no unified cgroup-v2 membership",
        )
    })
}

fn validate_run_id(run_id: &str) -> io::Result<()> {
    if run_id.is_empty()
        || run_id.len() > 249
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run ID is invalid for a cgroup name",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_a_single_safe_unified_membership() {
        assert_eq!(
            unified_membership_path(b"0::/user.slice/session.scope\n").unwrap(),
            PathBuf::from("user.slice/session.scope")
        );
        assert!(unified_membership_path(b"2:cpu:/legacy\n").is_err());
        assert!(unified_membership_path(b"0::/first\n0::/second\n").is_err());
        assert!(unified_membership_path(b"0::/../escape\n").is_err());
    }

    #[test]
    fn creates_assigns_and_removes_only_its_exact_child() {
        let temporary = tempfile::tempdir().unwrap();
        let task = TaskCgroup::create_in(temporary.path(), "run-test").unwrap();
        let path = task.path().to_path_buf();
        fs::write(path.join("cgroup.procs"), b"").unwrap();
        task.assign(42).unwrap();
        assert_eq!(fs::read_to_string(path.join("cgroup.procs")).unwrap(), "42");
        fs::write(path.join("cgroup.procs"), b"").unwrap();
        let report = task.finish().unwrap();
        assert!(report.removed);
        assert!(!path.exists());
        assert!(temporary.path().exists());
    }

    #[test]
    fn refuses_to_remove_a_cgroup_with_live_members() {
        let temporary = tempfile::tempdir().unwrap();
        let task = TaskCgroup::create_in(temporary.path(), "run-live").unwrap();
        let path = task.path().to_path_buf();
        fs::write(path.join("cgroup.procs"), b"71\n70\n").unwrap();
        let report = task.finish().unwrap();
        assert!(!report.removed);
        assert_eq!(report.remaining_processes, 2);
        assert_eq!(report.remaining_pids, [70, 71]);
        assert!(path.exists());
    }
}
