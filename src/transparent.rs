use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{self, Write as _},
    net::{IpAddr, SocketAddr},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::{
    ServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use url::Url;
use zeroize::Zeroizing;

pub const HOSTS_FILE_NAME: &str = ".transparent-hosts";
pub const CA_FILE_NAME: &str = ".transparent-ca.pem";
const MAX_TRANSPARENT_ENDPOINTS: usize = 64;
const CERTIFICATE_LIFETIME_DAYS: i64 = 7;

pub struct TransparentArtifacts {
    hosts_path: PathBuf,
    ca_path: Option<PathBuf>,
    server_config: Option<Arc<ServerConfig>>,
    upstream_host: String,
    upstream_port: u16,
    endpoints: Vec<SocketAddr>,
    ca_sha256: Option<String>,
    cleaned: bool,
}

impl TransparentArtifacts {
    pub fn prepare(
        run_dir: &Path,
        run_id: &str,
        upstream: &Url,
        endpoints: &[SocketAddr],
        endpoints_truncated: bool,
    ) -> Result<Self> {
        anyhow::ensure!(
            !endpoints_truncated,
            "transparent interception refuses a truncated upstream address snapshot"
        );
        anyhow::ensure!(
            matches!(upstream.scheme(), "http" | "https"),
            "transparent interception requires an HTTP(S) upstream"
        );
        let upstream_host = upstream
            .host_str()
            .context("transparent upstream URL has no host")?
            .to_owned();
        let upstream_port = upstream
            .port_or_known_default()
            .context("transparent upstream URL has no port")?;
        let mut exact = BTreeSet::new();
        for endpoint in endpoints {
            anyhow::ensure!(
                endpoint.port() == upstream_port,
                "transparent upstream snapshot contains an unexpected port"
            );
            let IpAddr::V4(address) = endpoint.ip() else {
                continue;
            };
            anyhow::ensure!(
                !address.is_unspecified()
                    && !address.is_loopback()
                    && !address.is_multicast()
                    && !address.is_broadcast(),
                "transparent upstream snapshot contains an unusable IPv4 address; loopback, unspecified, multicast, and broadcast endpoints are unsupported"
            );
            exact.insert(SocketAddr::new(IpAddr::V4(address), endpoint.port()));
        }
        anyhow::ensure!(
            !exact.is_empty(),
            "transparent interception requires at least one resolved IPv4 upstream endpoint"
        );
        anyhow::ensure!(
            exact.len() <= MAX_TRANSPARENT_ENDPOINTS,
            "transparent interception upstream snapshot exceeds its endpoint limit"
        );
        let endpoints = exact.into_iter().collect::<Vec<_>>();
        let hosts_path = run_dir.join(HOSTS_FILE_NAME);
        let hosts = hosts_snapshot(&upstream_host, &endpoints);
        write_new_private_file(&hosts_path, hosts.as_bytes())
            .context("write transparent /etc/hosts snapshot")?;

        let mut artifacts = Self {
            hosts_path,
            ca_path: None,
            server_config: None,
            upstream_host,
            upstream_port,
            endpoints,
            ca_sha256: None,
            cleaned: false,
        };
        if upstream.scheme() == "https" {
            let identity = generate_identity(run_id, &artifacts.upstream_host)
                .context("generate per-run transparent TLS identity")?;
            let ca_path = run_dir.join(CA_FILE_NAME);
            if let Err(error) = write_new_private_file(&ca_path, identity.ca_pem.as_bytes()) {
                let _ = artifacts.remove_files();
                return Err(error).context("write transparent public CA certificate");
            }
            artifacts.ca_path = Some(ca_path);
            artifacts.server_config = Some(identity.server_config);
            artifacts.ca_sha256 = Some(identity.ca_sha256);
        }
        Ok(artifacts)
    }

    #[must_use]
    pub fn hosts_path(&self) -> &Path {
        &self.hosts_path
    }

    #[must_use]
    pub fn ca_path(&self) -> Option<&Path> {
        self.ca_path.as_deref()
    }

    #[must_use]
    pub fn server_config(&self) -> Option<Arc<ServerConfig>> {
        self.server_config.clone()
    }

    #[must_use]
    pub fn upstream_host(&self) -> &str {
        &self.upstream_host
    }

    #[must_use]
    pub const fn upstream_port(&self) -> u16 {
        self.upstream_port
    }

    #[must_use]
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.endpoints
    }

    #[must_use]
    pub fn ca_sha256(&self) -> Option<&str> {
        self.ca_sha256.as_deref()
    }

    pub fn cleanup(mut self) -> io::Result<()> {
        let result = self.remove_files();
        self.cleaned = result.is_ok();
        result
    }

    fn remove_files(&mut self) -> io::Result<()> {
        let mut first_error = None;
        for path in self.ca_path.iter().chain(std::iter::once(&self.hosts_path)) {
            if let Err(error) = fs::remove_file(path)
                && error.kind() != io::ErrorKind::NotFound
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

impl Drop for TransparentArtifacts {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.remove_files();
        }
    }
}

struct GeneratedIdentity {
    ca_pem: String,
    ca_sha256: String,
    server_config: Arc<ServerConfig>,
}

fn generate_identity(run_id: &str, upstream_host: &str) -> Result<GeneratedIdentity> {
    let now = OffsetDateTime::now_utc();
    let not_before = now - Duration::minutes(5);
    let not_after = now + Duration::days(CERTIFICATE_LIFETIME_DAYS);

    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let mut ca_name = DistinguishedName::new();
    ca_name.push(DnType::CommonName, format!("iorec ephemeral CA {run_id}"));
    ca_params.distinguished_name = ca_name;
    let ca_key = Zeroizing::new(KeyPair::generate()?);
    let ca = ca_params.self_signed(&*ca_key)?;
    let issuer = Issuer::from_params(&ca_params, &*ca_key);

    let mut leaf_params = CertificateParams::new(vec![upstream_host.to_owned()])?;
    leaf_params.not_before = not_before;
    leaf_params.not_after = not_after;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let mut leaf_name = DistinguishedName::new();
    leaf_name.push(DnType::CommonName, upstream_host);
    leaf_params.distinguished_name = leaf_name;
    let leaf_key = Zeroizing::new(KeyPair::generate()?);
    let leaf = leaf_params.signed_by(&*leaf_key, &issuer)?;

    // The AWS-LC rustls provider wraps this DER value in `Zeroizing` while it is
    // parsed. The generation-time KeyPair copies above are independently
    // zeroized on every return path.
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone(), ca.der().clone()], private_key)?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let ca_sha256 = hex::encode(Sha256::digest(ca.der().as_ref()));
    Ok(GeneratedIdentity {
        ca_pem: ca.pem(),
        ca_sha256,
        server_config: Arc::new(server_config),
    })
}

fn hosts_snapshot(upstream_host: &str, endpoints: &[SocketAddr]) -> String {
    let mut output = String::from("127.0.0.1 localhost\n::1 localhost\n");
    for endpoint in endpoints {
        if let IpAddr::V4(address) = endpoint.ip() {
            let _ = writeln!(output, "{address} {upstream_host}");
        }
    }
    output
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepares_bounded_ephemeral_https_material_and_cleans_it() {
        let directory = tempfile::tempdir().unwrap();
        let upstream = Url::parse("https://api.example.test/v1").unwrap();
        let endpoints = [
            "192.0.2.20:443".parse().unwrap(),
            "192.0.2.10:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ];
        let artifacts = TransparentArtifacts::prepare(
            directory.path(),
            "run-test",
            &upstream,
            &endpoints,
            false,
        )
        .unwrap();
        assert_eq!(artifacts.upstream_host(), "api.example.test");
        assert_eq!(artifacts.endpoints().len(), 2);
        assert!(artifacts.server_config().is_some());
        assert_eq!(artifacts.ca_sha256().unwrap().len(), 64);
        let hosts = fs::read_to_string(artifacts.hosts_path()).unwrap();
        assert!(hosts.contains("192.0.2.10 api.example.test"));
        assert!(hosts.contains("192.0.2.20 api.example.test"));
        let ca_path = artifacts.ca_path().unwrap().to_owned();
        let ca = fs::read_to_string(&ca_path).unwrap();
        assert!(ca.contains("BEGIN CERTIFICATE"));
        assert!(!ca.contains("PRIVATE KEY"));
        assert_eq!(
            fs::metadata(&ca_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let hosts_path = artifacts.hosts_path().to_owned();
        artifacts.cleanup().unwrap();
        assert!(!hosts_path.exists());
        assert!(!ca_path.exists());
    }

    #[test]
    fn refuses_incomplete_or_unusable_address_snapshots() {
        let directory = tempfile::tempdir().unwrap();
        let upstream = Url::parse("http://api.example.test:8080").unwrap();
        assert!(
            TransparentArtifacts::prepare(
                directory.path(),
                "run-test",
                &upstream,
                &["192.0.2.10:8080".parse().unwrap()],
                true,
            )
            .is_err()
        );
        assert!(
            TransparentArtifacts::prepare(
                directory.path(),
                "run-test",
                &upstream,
                &["[2001:db8::1]:8080".parse().unwrap()],
                false,
            )
            .is_err()
        );
        assert!(
            TransparentArtifacts::prepare(
                directory.path(),
                "run-test",
                &upstream,
                &["127.0.0.1:8080".parse().unwrap()],
                false,
            )
            .is_err()
        );
        assert!(!directory.path().join(HOSTS_FILE_NAME).exists());
    }

    #[test]
    fn non_loopback_ipv4_literal_hosts_snapshot_is_supported() {
        let directory = tempfile::tempdir().unwrap();
        let upstream = Url::parse("http://192.0.2.11:8080").unwrap();
        let artifacts = TransparentArtifacts::prepare(
            directory.path(),
            "run-test",
            &upstream,
            &["192.0.2.11:8080".parse().unwrap()],
            false,
        )
        .unwrap();
        assert!(
            fs::read_to_string(artifacts.hosts_path())
                .unwrap()
                .contains("192.0.2.11 192.0.2.11")
        );
    }
}
