use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use nix::fcntl::OFlag;
use sha2::{Digest, Sha256};
use tracing::warn;
use url::Url;

use crate::{
    input::validate_json_complexity, manifest::CommandMetadata, secure_fs::read_regular_limited,
};

const ENVIRONMENT_ALLOWLIST: &[&str] = &[
    "LANG",
    "LC_ALL",
    "SHELL",
    "TERM",
    "COLORTERM",
    "OPENAI_BASE_URL",
    "ANTHROPIC_BASE_URL",
    "GOOGLE_GEMINI_BASE_URL",
];
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PACKAGE_METADATA_BYTES: usize = 1024 * 1024;
const MAX_VENV_LIB_ENTRIES: usize = 32;
const MAX_SITE_PACKAGES_ENTRIES: usize = 10_000;

pub async fn discover_command(argv: &[OsString], cwd: &Path) -> io::Result<CommandMetadata> {
    let executable = argv
        .first()
        .and_then(|command| resolve_executable(command, cwd));
    let fingerprint = match executable.clone() {
        Some(path) => match tokio::task::spawn_blocking({
            let path = path.clone();
            move || fingerprint_executable(&path)
        })
        .await
        .map_err(|error| io::Error::other(format!("hash task panicked: {error}")))?
        {
            Ok(fingerprint) => Some(fingerprint),
            Err(error) => {
                warn!(
                    path = %path.display(),
                    error_kind = ?error.kind(),
                    "target executable fingerprint is unavailable"
                );
                None
            }
        },
        None => None,
    };
    let (agent, runtime) = executable.as_deref().map_or((None, None), |path| {
        detect_agent_and_runtime(path, argv.first().map(OsString::as_os_str))
    });
    let agent_version = executable
        .as_deref()
        .and_then(|path| detect_agent_version(path, agent.as_deref()));
    Ok(CommandMetadata {
        argv: sanitize_argv(argv),
        cwd: cwd.to_path_buf(),
        executable,
        executable_sha256: fingerprint
            .as_ref()
            .map(|fingerprint| fingerprint.sha256.clone()),
        agent,
        // Never invoke the target a second time for discovery. Only anchored
        // install paths and matching local package metadata are accepted.
        agent_version,
        runtime,
        executable_tls_surfaces: fingerprint
            .map(|fingerprint| fingerprint.tls_surfaces)
            .unwrap_or_default(),
        environment: environment_snapshot(),
    })
}

fn detect_agent_version(path: &Path, agent: Option<&str>) -> Option<String> {
    let agent = agent?;
    let components: Vec<&OsStr> = path
        .components()
        .map(std::path::Component::as_os_str)
        .collect();
    for (index, pair) in components.windows(2).enumerate() {
        let Some(anchor) = pair[0].to_str() else {
            continue;
        };
        let owner = index
            .checked_sub(1)
            .and_then(|owner| components.get(owner))
            .and_then(|owner| owner.to_str())
            .unwrap_or_default();
        let anchored = match agent {
            "codex" => anchor == "releases" && matches!(owner, "standalone" | "codex"),
            "claude-code" => anchor == "versions" && owner.contains("claude"),
            _ => false,
        };
        if anchored && let Some(version) = pair[1].to_str().and_then(normalize_version) {
            return Some(version);
        }
    }
    package_json_version(path, agent).or_else(|| python_distribution_version(path, agent))
}

fn package_json_version(path: &Path, agent: &str) -> Option<String> {
    let accepted_names: &[&str] = match agent {
        "codex" => &["@openai/codex"],
        "claude-code" => &["@anthropic-ai/claude-code"],
        "gemini-cli" => &["@google/gemini-cli"],
        _ => return None,
    };
    for ancestor in path.parent()?.ancestors().take(8) {
        let Ok(bytes) =
            read_regular_limited(&ancestor.join("package.json"), MAX_PACKAGE_METADATA_BYTES)
        else {
            continue;
        };
        if validate_json_complexity(&bytes).is_err() {
            return None;
        }
        let Ok(package) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let Some(name) = package.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !accepted_names.contains(&name) {
            continue;
        }
        return package
            .get("version")
            .and_then(serde_json::Value::as_str)
            .and_then(normalize_version);
    }
    None
}

fn python_distribution_version(path: &Path, agent: &str) -> Option<String> {
    if agent != "hermes" || path.parent()?.file_name()? != "bin" {
        return None;
    }
    let venv = path.parent()?.parent()?;
    read_regular_limited(&venv.join("pyvenv.cfg"), 64 * 1024).ok()?;
    let lib = venv.join("lib");
    if !is_real_directory(&lib) {
        return None;
    }
    let mut versions = BTreeSet::new();
    for (lib_index, python) in fs::read_dir(lib).ok()?.enumerate() {
        if lib_index >= MAX_VENV_LIB_ENTRIES {
            return None;
        }
        let python = python.ok()?;
        let name = python.file_name();
        if !name.to_string_lossy().starts_with("python") || !python.file_type().ok()?.is_dir() {
            continue;
        }
        let site_packages = python.path().join("site-packages");
        if !is_real_directory(&site_packages) {
            continue;
        }
        for (package_index, distribution) in fs::read_dir(site_packages).ok()?.enumerate() {
            if package_index >= MAX_SITE_PACKAGES_ENTRIES {
                return None;
            }
            let distribution = distribution.ok()?;
            let name = distribution.file_name();
            let name = name.to_str()?;
            if !name.starts_with("hermes_agent-")
                || !name.ends_with(".dist-info")
                || !distribution.file_type().ok()?.is_dir()
            {
                continue;
            }
            let metadata = read_regular_limited(
                &distribution.path().join("METADATA"),
                MAX_PACKAGE_METADATA_BYTES,
            )
            .ok()?;
            let metadata = std::str::from_utf8(&metadata).ok()?;
            if metadata_header(metadata, "Name") != Some("hermes-agent") {
                continue;
            }
            if let Some(version) = metadata_header(metadata, "Version").and_then(normalize_version)
            {
                versions.insert(version);
            }
        }
    }
    (versions.len() == 1)
        .then(|| versions.into_iter().next())
        .flatten()
}

fn is_real_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink())
}

fn metadata_header<'a>(metadata: &'a str, name: &str) -> Option<&'a str> {
    metadata
        .lines()
        .take_while(|line| !line.is_empty())
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn normalize_version(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 64 {
        return None;
    }
    let core_end = value
        .bytes()
        .position(|byte| !byte.is_ascii_digit() && byte != b'.')
        .unwrap_or(value.len());
    let core = &value[..core_end];
    if core.split('.').count() != 3
        || core
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    let suffix = &value[core_end..];
    let recognized_target = ["-x86_64", "-aarch64", "-arm64"]
        .iter()
        .any(|target| suffix.starts_with(target))
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'));
    if suffix.is_empty() || recognized_target {
        Some(core.to_owned())
    } else if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        Some(value.to_owned())
    } else {
        None
    }
}

fn sanitize_argv(argv: &[OsString]) -> Vec<String> {
    const SECRET_FLAGS: &[&str] = &[
        "--api-key",
        "--api_key",
        "--token",
        "--password",
        "--authorization",
        "--cookie",
        "--client-secret",
    ];
    let mut redact_next = false;
    argv.iter()
        .enumerate()
        .map(|(index, value)| {
            let text = value.to_string_lossy();
            let lowercase = text.to_ascii_lowercase();
            if index == 0 {
                return text.into_owned();
            }
            if redact_next {
                redact_next = false;
                return "[REDACTED_SENSITIVE_ARG]".to_owned();
            }
            if SECRET_FLAGS.contains(&lowercase.as_str()) {
                redact_next = true;
                return text.into_owned();
            }
            let contains_secret_shape = [
                "authorization",
                "api_key",
                "api-key",
                "access_token",
                "refresh_token",
                "password",
                "client_secret",
                "client-secret",
                "cookie",
                "bearer ",
            ]
            .iter()
            .any(|marker| lowercase.contains(marker));
            if contains_secret_shape || lowercase.starts_with("sk-") {
                "[REDACTED_SENSITIVE_ARG]".to_owned()
            } else if text.starts_with('-') {
                if let Some((flag, _value)) = text.split_once('=') {
                    format!("{flag}=[REDACTED_ARG]")
                } else {
                    text.into_owned()
                }
            } else {
                // Prompts, shell snippets and filenames are commonly supplied as
                // positional arguments. Keep command shape, never their content,
                // in the plaintext manifest.
                "[REDACTED_ARG]".to_owned()
            }
        })
        .collect()
}

fn resolve_executable(command: &OsStr, cwd: &Path) -> Option<PathBuf> {
    let candidate = Path::new(command);
    if candidate.components().count() > 1 || candidate.is_absolute() {
        let absolute = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            cwd.join(candidate)
        };
        return canonical_regular_file(&absolute);
    }
    env::split_paths(&env::var_os("PATH")?)
        .map(|directory| directory.join(candidate))
        .find_map(|path| canonical_regular_file(&path))
}

fn canonical_regular_file(path: &Path) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    fs::symlink_metadata(&canonical)
        .ok()?
        .file_type()
        .is_file()
        .then_some(canonical)
}

#[derive(Debug)]
struct ExecutableFingerprint {
    sha256: String,
    tls_surfaces: Vec<String>,
}

fn fingerprint_executable(path: &Path) -> io::Result<ExecutableFingerprint> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)?;
    let before = input.metadata()?;
    if !before.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target executable is not a regular file",
        ));
    }
    if before.len() > MAX_EXECUTABLE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target executable exceeds the fingerprint size limit",
        ));
    }
    let mut digest = Sha256::new();
    let mut tls_scanner = TlsMarkerScanner::default();
    let mut buffer = vec![0_u8; 128 * 1024].into_boxed_slice();
    let mut total = 0_u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        digest.update(&buffer[..read]);
        tls_scanner.update(&buffer[..read]);
    }
    let after = input.metadata()?;
    if total != before.len() || file_identity(&before) != file_identity(&after) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target executable changed during fingerprinting",
        ));
    }
    Ok(ExecutableFingerprint {
        sha256: format!("sha256:{}", hex::encode(digest.finalize())),
        tls_surfaces: tls_scanner.finish(),
    })
}

fn file_identity(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[derive(Default)]
struct TlsMarkerScanner {
    tail: Vec<u8>,
    found: BTreeSet<TlsMarker>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TlsMarker {
    BoringSsl,
    Rustls,
    OpenSsl,
    OpenSslDependency,
    GnuTlsDependency,
    NssDependency,
    GoBuildInfo,
    GoCryptoTls,
}

impl TlsMarkerScanner {
    const TAIL_BYTES: usize = 64;

    fn update(&mut self, bytes: &[u8]) {
        let mut scan = Vec::with_capacity(self.tail.len().saturating_add(bytes.len()));
        scan.extend_from_slice(&self.tail);
        scan.extend_from_slice(bytes);
        scan.make_ascii_lowercase();
        find_tls_markers(&scan, &mut self.found);
        let keep = scan.len().min(Self::TAIL_BYTES);
        self.tail = scan[scan.len() - keep..].to_vec();
    }

    fn finish(self) -> Vec<String> {
        let mut surfaces = Vec::new();
        if self.found.contains(&TlsMarker::BoringSsl) {
            surfaces.push("boringssl-binary-marker".to_owned());
        }
        if self.found.contains(&TlsMarker::Rustls) {
            surfaces.push("rustls-binary-marker".to_owned());
        }
        if self.found.contains(&TlsMarker::GoBuildInfo)
            && self.found.contains(&TlsMarker::GoCryptoTls)
        {
            surfaces.push("go-crypto-tls-binary-marker".to_owned());
        }
        if self.found.contains(&TlsMarker::OpenSsl) {
            surfaces.push("openssl-binary-marker".to_owned());
        }
        if self.found.contains(&TlsMarker::OpenSslDependency) {
            surfaces.push("openssl-dynamic-dependency".to_owned());
        }
        if self.found.contains(&TlsMarker::GnuTlsDependency) {
            surfaces.push("gnutls-dynamic-dependency".to_owned());
        }
        if self.found.contains(&TlsMarker::NssDependency) {
            surfaces.push("nss-dynamic-dependency".to_owned());
        }
        surfaces
    }
}

fn find_tls_markers(bytes: &[u8], found: &mut BTreeSet<TlsMarker>) {
    for (index, first) in bytes.iter().copied().enumerate() {
        let remaining = &bytes[index..];
        match first {
            b'b' if remaining.starts_with(b"boringssl") => {
                found.insert(TlsMarker::BoringSsl);
            }
            b'r' if remaining.starts_with(b"rustls") => {
                found.insert(TlsMarker::Rustls);
            }
            b'o' if remaining.starts_with(b"openssl 1.")
                || remaining.starts_with(b"openssl 3.") =>
            {
                found.insert(TlsMarker::OpenSsl);
            }
            b'l' if remaining.starts_with(b"libssl.so")
                || remaining.starts_with(b"libcrypto.so") =>
            {
                found.insert(TlsMarker::OpenSslDependency);
            }
            b'l' if remaining.starts_with(b"libgnutls.so") => {
                found.insert(TlsMarker::GnuTlsDependency);
            }
            b'l' if remaining.starts_with(b"libnss3.so") => {
                found.insert(TlsMarker::NssDependency);
            }
            0xff if remaining.starts_with(b"\xff go buildinf:") => {
                found.insert(TlsMarker::GoBuildInfo);
            }
            b'c' if remaining.starts_with(b"crypto/tls") => {
                found.insert(TlsMarker::GoCryptoTls);
            }
            _ => {}
        }
    }
}

fn detect_agent_and_runtime(
    path: &Path,
    invoked_as: Option<&OsStr>,
) -> (Option<String>, Option<String>) {
    let resolved_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let invoked_name = invoked_as
        .map(Path::new)
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let matches_name =
        |needle: &str| resolved_name.contains(needle) || invoked_name.contains(needle);
    let agent = if matches_name("hermes") {
        Some("hermes".to_owned())
    } else if resolved_name == "codex"
        || resolved_name.starts_with("codex-")
        || invoked_name == "codex"
        || invoked_name.starts_with("codex-")
    {
        Some("codex".to_owned())
    } else if matches_name("claude") {
        Some("claude-code".to_owned())
    } else if matches_name("gemini") {
        Some("gemini-cli".to_owned())
    } else {
        None
    };

    let mut prefix = vec![0_u8; 64 * 1024].into_boxed_slice();
    let read = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)
        .and_then(|mut file| {
            if !file.metadata()?.file_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "target executable is not a regular file",
                ));
            }
            file.read(&mut prefix)
        })
        .unwrap_or(0);
    let bytes = &prefix[..read];
    let runtime = if matches!(resolved_name.as_str(), "node" | "nodejs")
        || matches!(invoked_name.as_str(), "node" | "nodejs")
    {
        Some("node".to_owned())
    } else if resolved_name == "bun" || invoked_name == "bun" {
        Some("bun".to_owned())
    } else if resolved_name.starts_with("python") || invoked_name.starts_with("python") {
        Some("python".to_owned())
    } else if bytes.starts_with(b"#!") {
        let shebang = bytes
            .split(|byte| *byte == b'\n')
            .next()
            .and_then(|line| std::str::from_utf8(line).ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if shebang.contains("python") {
            Some("python".to_owned())
        } else if shebang.contains("node") {
            Some("node".to_owned())
        } else if shebang.contains("bun") {
            Some("bun".to_owned())
        } else {
            Some(format!("script:{shebang}"))
        }
    } else if bytes.starts_with(b"\x7fELF") {
        if bytes
            .windows(b"\xff Go buildinf:".len())
            .any(|window| window == b"\xff Go buildinf:")
        {
            Some("go-native".to_owned())
        } else if bytes.windows(4).any(|window| window == b"rust") {
            Some("rust-or-native".to_owned())
        } else {
            Some("native-elf".to_owned())
        }
    } else {
        Some("unknown".to_owned())
    };
    (agent, runtime)
}

fn environment_snapshot() -> BTreeMap<String, String> {
    ENVIRONMENT_ALLOWLIST
        .iter()
        .filter_map(|key| {
            let value = env::var(key).ok()?;
            let sanitized = if key.ends_with("BASE_URL") {
                sanitize_url(&value)
            } else {
                value.chars().take(4096).collect()
            };
            Some(((*key).to_owned(), sanitized))
        })
        .collect()
}

fn sanitize_url(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return "[INVALID_URL]".to_owned();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use nix::{sys::stat::Mode, unistd::mkfifo};

    use super::*;

    #[test]
    fn url_credentials_and_query_are_removed() {
        let safe = sanitize_url("https://user:secret@example.test/v1?api_key=secret#fragment");
        assert_eq!(safe, "https://example.test/v1");
    }

    #[test]
    fn resolves_known_path_command() {
        assert_eq!(
            resolve_executable(OsStr::new("/bin/sh"), Path::new("/tmp")),
            Some(PathBuf::from("/usr/bin/dash"))
        );
    }

    #[test]
    fn executable_fingerprinting_rejects_special_and_oversized_files() {
        let temporary = tempfile::tempdir().unwrap();
        let fifo = temporary.path().join("target-fifo");
        mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        assert_eq!(resolve_executable(fifo.as_os_str(), temporary.path()), None);
        assert_eq!(
            fingerprint_executable(&fifo).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        let oversized = temporary.path().join("oversized");
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&oversized)
            .unwrap();
        file.set_len(MAX_EXECUTABLE_BYTES + 1).unwrap();
        assert_eq!(
            fingerprint_executable(&oversized).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn command_metadata_redacts_credential_shaped_arguments() {
        let sanitized = sanitize_argv(&[
            OsString::from("agent"),
            OsString::from("--api-key"),
            OsString::from("sk-secret"),
            OsString::from("authorization=Bearer hidden"),
            OsString::from("safe"),
            OsString::from("--model=gpt-test"),
        ]);
        assert_eq!(sanitized[0], "agent");
        assert_eq!(sanitized[1], "--api-key");
        assert_eq!(sanitized[2], "[REDACTED_SENSITIVE_ARG]");
        assert_eq!(sanitized[3], "[REDACTED_SENSITIVE_ARG]");
        assert_eq!(sanitized[4], "[REDACTED_ARG]");
        assert_eq!(sanitized[5], "--model=[REDACTED_ARG]");
    }

    #[test]
    fn invocation_name_detects_versioned_native_installations() {
        let path = Path::new("/opt/claude/versions/2.1.272");
        let (agent, runtime) = detect_agent_and_runtime(path, Some(OsStr::new("claude")));
        assert_eq!(agent.as_deref(), Some("claude-code"));
        assert_eq!(runtime.as_deref(), Some("unknown"));
        assert_eq!(
            detect_agent_version(path, agent.as_deref()).as_deref(),
            Some("2.1.272")
        );
        assert_eq!(
            detect_agent_version(
                Path::new(
                    "/home/test/.codex/packages/standalone/releases/0.154.0-x86_64-unknown-linux-musl/bin/codex"
                ),
                Some("codex")
            )
            .as_deref(),
            Some("0.154.0")
        );
        assert_eq!(
            detect_agent_version(Path::new("/tmp/versions/9.9.9/codex"), Some("codex")),
            None
        );
    }

    #[test]
    fn package_versions_require_a_matching_official_package_name() {
        let temporary = tempfile::tempdir().unwrap();
        let package = temporary.path().join("node_modules/@google/gemini-cli");
        let executable = package.join("dist/index.js");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(
            package.join("package.json"),
            br#"{"name":"not-the-gemini-package","version":"7.8.9"}"#,
        )
        .unwrap();
        assert_eq!(detect_agent_version(&executable, Some("gemini-cli")), None);

        fs::write(
            package.join("package.json"),
            br#"{"name":"@google/gemini-cli","version":"7.8.9-beta.1"}"#,
        )
        .unwrap();
        assert_eq!(
            detect_agent_version(&executable, Some("gemini-cli")).as_deref(),
            Some("7.8.9-beta.1")
        );
        assert_eq!(normalize_version("7.8"), None);
        assert_eq!(normalize_version("7.8.9/../../secret"), None);
    }

    #[test]
    fn hermes_version_requires_unambiguous_venv_distribution_metadata() {
        let temporary = tempfile::tempdir().unwrap();
        let venv = temporary.path().join("venv");
        let executable = venv.join("bin/hermes");
        let distribution = venv
            .join("lib/python3.13/site-packages")
            .join("hermes_agent-0.19.0.dist-info");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::create_dir_all(&distribution).unwrap();
        fs::write(venv.join("pyvenv.cfg"), b"home = /usr/bin\n").unwrap();
        fs::write(
            distribution.join("METADATA"),
            b"Metadata-Version: 2.4\nName: hermes-agent\nVersion: 0.19.0\n\nbody\n",
        )
        .unwrap();
        assert_eq!(
            detect_agent_version(&executable, Some("hermes")).as_deref(),
            Some("0.19.0")
        );

        let ambiguous = venv
            .join("lib/python3.13/site-packages")
            .join("hermes_agent-0.20.0.dist-info");
        fs::create_dir(&ambiguous).unwrap();
        fs::write(
            ambiguous.join("METADATA"),
            b"Name: hermes-agent\nVersion: 0.20.0\n\n",
        )
        .unwrap();
        assert_eq!(detect_agent_version(&executable, Some("hermes")), None);
    }

    #[test]
    fn distinguishes_node_and_bun_shebangs_for_tls_planning() {
        let temporary = tempfile::tempdir().unwrap();
        let node = temporary.path().join("node-agent");
        let bun = temporary.path().join("bun-agent");
        std::fs::write(&node, b"#!/usr/bin/env node\n").unwrap();
        std::fs::write(&bun, b"#!/usr/bin/env bun\n").unwrap();
        assert_eq!(
            detect_agent_and_runtime(&node, None).1.as_deref(),
            Some("node")
        );
        assert_eq!(
            detect_agent_and_runtime(&bun, None).1.as_deref(),
            Some("bun")
        );
    }

    #[test]
    fn tls_binary_markers_are_streamed_across_read_boundaries() {
        let mut scanner = TlsMarkerScanner::default();
        scanner.update(b"ELF-prefix-bori");
        scanner.update(b"ngssl-and-rustls-and-\xff Go buil");
        scanner.update(b"dinf:-crypto/");
        scanner.update(b"tls-and-libssl.so.3");
        assert_eq!(
            scanner.finish(),
            vec![
                "boringssl-binary-marker",
                "rustls-binary-marker",
                "go-crypto-tls-binary-marker",
                "openssl-dynamic-dependency",
            ]
        );
    }

    #[tokio::test]
    async fn discovery_never_executes_the_target_for_version_metadata() {
        let temporary = tempfile::tempdir().unwrap();
        let executable = temporary.path().join("codex");
        let marker = temporary.path().join("executed");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\nprintf executed > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();

        let metadata = discover_command(&[executable.into_os_string()], temporary.path())
            .await
            .unwrap();
        assert_eq!(metadata.agent.as_deref(), Some("codex"));
        assert!(metadata.agent_version.is_none());
        assert!(!marker.exists());
    }
}
