use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use tokio::process::Command;

const PYTHON_SITECUSTOMIZE: &str = include_str!("../assets/python/sitecustomize.py");
const PYTHON_INJECTION_DIRECTORY: &str = "runtime-python";
const NODE_PRELOAD: &str = include_str!("../assets/node/preload.cjs");
const NODE_LOADER: &str = include_str!("../assets/node/loader.mjs");
const NODE_INJECTION_DIRECTORY: &str = "runtime-node";

#[derive(Debug, Clone)]
pub struct PythonInjection {
    path: PathBuf,
    sha256: String,
}

impl PythonInjection {
    pub fn prepare(run_dir: &Path, command: &[OsString]) -> io::Result<Self> {
        Self::validate_command(command)?;
        let path = run_dir.join(PYTHON_INJECTION_DIRECTORY);
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let module = path.join("sitecustomize.py");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&module)?;
        file.write_all(PYTHON_SITECUSTOMIZE.as_bytes())?;
        file.sync_all()?;
        File::open(&path)?.sync_all()?;
        let sha256 = hex::encode(Sha256::digest(PYTHON_SITECUSTOMIZE.as_bytes()));
        Ok(Self { path, sha256 })
    }

    pub fn apply(&self, command: &mut Command) -> io::Result<()> {
        let mut paths = vec![self.path.clone()];
        if let Some(existing) = std::env::var_os("PYTHONPATH") {
            paths.extend(std::env::split_paths(&existing));
        }
        let joined = std::env::join_paths(paths).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("existing PYTHONPATH cannot be safely extended: {error}"),
            )
        })?;
        command
            .env("PYTHONPATH", joined)
            .env("IOREC_PYTHON_INJECTION", "1");
        Ok(())
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn validate_command(command: &[OsString]) -> io::Result<()> {
        validate_python_command(command)
    }
}

#[derive(Debug, Clone)]
pub struct NodeInjection {
    module: PathBuf,
    sha256: String,
}

impl NodeInjection {
    pub fn prepare(run_dir: &Path) -> io::Result<Self> {
        let path = run_dir.join(NODE_INJECTION_DIRECTORY);
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let module = path.join("preload.cjs");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&module)?;
        file.write_all(NODE_PRELOAD.as_bytes())?;
        file.sync_all()?;
        let loader = path.join("loader.mjs");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&loader)?;
        file.write_all(NODE_LOADER.as_bytes())?;
        file.sync_all()?;
        File::open(&path)?.sync_all()?;
        let mut digest = Sha256::new();
        digest.update(NODE_PRELOAD.as_bytes());
        digest.update([0]);
        digest.update(NODE_LOADER.as_bytes());
        let sha256 = hex::encode(digest.finalize());
        Ok(Self { module, sha256 })
    }

    pub fn apply(&self, command: &mut Command) {
        command.env("IOREC_NODE_INJECTION", "1");
    }

    pub fn node_option(&self) -> io::Result<String> {
        let path = self.module.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Node preload path is not valid UTF-8",
            )
        })?;
        let escaped = path.replace('\\', "\\\\").replace('"', "\\\"");
        Ok(format!("--require=\"{escaped}\""))
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

fn validate_python_command(command: &[OsString]) -> io::Result<()> {
    if command.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Python injection requires a target command",
        ));
    }
    for argument in command.iter().skip(1) {
        let argument = argument.as_os_str();
        if matches!(argument.to_str(), Some("-S" | "-I" | "-E"))
            || compact_python_flag_disables_site(argument)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Python -S, -I, and -E modes bypass the requested runtime injection",
            ));
        }
        if argument == OsStr::new("-c") || argument == OsStr::new("-m") {
            break;
        }
        if !argument.to_string_lossy().starts_with('-') {
            break;
        }
    }
    Ok(())
}

fn compact_python_flag_disables_site(argument: &OsStr) -> bool {
    argument.to_str().is_some_and(|argument| {
        argument.starts_with('-')
            && !argument.starts_with("--")
            && argument[1..]
                .bytes()
                .any(|flag| matches!(flag, b'S' | b'I' | b'E'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepares_private_deterministic_python_bootstrap() {
        let temporary = tempfile::tempdir().unwrap();
        let injection = PythonInjection::prepare(
            temporary.path(),
            &[OsString::from("python3"), OsString::from("agent.py")],
        )
        .unwrap();
        let module = injection.path.join("sitecustomize.py");
        let metadata = fs::metadata(&module).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(module).unwrap(), PYTHON_SITECUSTOMIZE);
        assert_eq!(injection.sha256().len(), 64);
        assert!(PythonInjection::prepare(temporary.path(), &[OsString::from("python3")]).is_err());
    }

    #[test]
    fn rejects_interpreter_modes_that_disable_sitecustomize() {
        for flag in ["-S", "-I", "-E", "-IE"] {
            assert!(
                validate_python_command(&[OsString::from("python3"), OsString::from(flag)])
                    .is_err()
            );
        }
        assert!(
            validate_python_command(&[
                OsString::from("python3"),
                OsString::from("-c"),
                OsString::from("print('-S is data')"),
            ])
            .is_ok()
        );
    }

    #[test]
    fn prepares_private_deterministic_node_preload() {
        let temporary = tempfile::tempdir().unwrap();
        let injection = NodeInjection::prepare(temporary.path()).unwrap();
        let metadata = fs::metadata(&injection.module).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(injection.module.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(fs::read_to_string(&injection.module).unwrap(), NODE_PRELOAD);
        assert_eq!(
            fs::read_to_string(injection.module.parent().unwrap().join("loader.mjs")).unwrap(),
            NODE_LOADER
        );
        assert_eq!(
            fs::metadata(injection.module.parent().unwrap().join("loader.mjs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(injection.sha256().len(), 64);
        assert!(injection.node_option().unwrap().starts_with("--require=\""));
        assert!(NodeInjection::prepare(temporary.path()).is_err());
    }
}
