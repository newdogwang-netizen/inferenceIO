use std::path::Path;

use serde::Serialize;

use crate::{
    crypto::EncryptionKey,
    inspect::inspect_run_with_key,
    manifest::{self, write_atomic_authenticated},
};

#[derive(Debug, Clone, Serialize)]
pub struct MigrationReport {
    pub run_id: String,
    pub changed: bool,
    pub manifest_authenticated: Option<bool>,
    pub event_schema: u32,
    pub manifest_schema: u32,
}

pub fn migrate_run(run_dir: &Path, key: Option<&EncryptionKey>) -> anyhow::Result<MigrationReport> {
    let manifest_path = run_dir.join("manifest.json");
    let manifest = manifest::read(&manifest_path)?;
    let authentication = manifest.verify_authentication(key)?;
    if authentication != Some(false) {
        return Ok(MigrationReport {
            run_id: manifest.run_id,
            changed: false,
            manifest_authenticated: authentication,
            event_schema: crate::SCHEMA_VERSION,
            manifest_schema: manifest.schema_version,
        });
    }

    anyhow::ensure!(
        manifest.status != "running",
        "refusing to migrate a run that is still being recorded"
    );
    let inspection = inspect_run_with_key(run_dir, true, key)?;
    anyhow::ensure!(
        inspection.log.discarded_tail_bytes == 0,
        "run has an incomplete event tail; recover it before migration"
    );
    anyhow::ensure!(
        inspection.missing_blobs.is_empty() && inspection.corrupt_blobs.is_empty(),
        "run must pass blob integrity checks before migration"
    );
    write_atomic_authenticated(&manifest_path, &manifest, key)?;
    let migrated = manifest::read(&manifest_path)?;
    anyhow::ensure!(
        migrated.verify_authentication(key)? == Some(true),
        "post-migration manifest authentication failed"
    );
    Ok(MigrationReport {
        run_id: migrated.run_id,
        changed: true,
        manifest_authenticated: Some(true),
        event_schema: crate::SCHEMA_VERSION,
        manifest_schema: migrated.schema_version,
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use crate::{
        manifest::{CommandMetadata, EncryptionMetadata, Manifest, write_atomic},
        policy::CapturePolicy,
        storage::RunStore,
    };

    use super::*;

    #[tokio::test]
    async fn authenticates_a_legacy_manifest_without_rewriting_raw_evidence() {
        let temporary = tempfile::tempdir().unwrap();
        let key = EncryptionKey::new([73; 32]);
        let policy = CapturePolicy::default();
        let mut manifest = Manifest::new(
            "legacy-run".to_owned(),
            CommandMetadata {
                argv: vec!["agent".to_owned()],
                cwd: PathBuf::from("/tmp"),
                executable: None,
                executable_sha256: None,
                agent: None,
                agent_version: None,
                runtime: None,
                executable_tls_surfaces: Vec::new(),
                environment: BTreeMap::new(),
            },
            policy.clone(),
        );
        manifest.status = "finished".to_owned();
        manifest.finished_at = Some(chrono::Utc::now());
        manifest.storage.encryption = Some(EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".to_owned(),
            key_id: key.key_id().to_owned(),
            key_derivation: None,
            blob_key_management: Some(crate::blob_keys::BLOB_KEY_MANAGEMENT_V1.to_owned()),
            scope: vec!["events".to_owned(), "blobs".to_owned()],
        });
        write_atomic(&temporary.path().join("manifest.json"), &manifest).unwrap();
        let (store, _) = RunStore::create_with_encryption(
            temporary.path(),
            "legacy-run",
            policy,
            Some(key.clone()),
        )
        .unwrap();
        store
            .append(store.event("test", "legacy_evidence"))
            .await
            .unwrap();
        store.shutdown().await.unwrap();
        let events_before = std::fs::read(temporary.path().join("events.jsonl")).unwrap();

        let report = migrate_run(temporary.path(), Some(&key)).unwrap();
        assert!(report.changed);
        assert_eq!(report.manifest_authenticated, Some(true));
        assert_eq!(
            std::fs::read(temporary.path().join("events.jsonl")).unwrap(),
            events_before
        );
        assert!(!migrate_run(temporary.path(), Some(&key)).unwrap().changed);
    }
}
