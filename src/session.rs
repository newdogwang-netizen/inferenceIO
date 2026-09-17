use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    input::validate_json_complexity,
    metadata,
    model::{EventIds, TerminalState},
    policy::BodyCaptureMode,
    secure_fs::{open_regular_read, read_regular_limited},
    storage::RunStore,
};

const MAX_FILES: usize = 10_000;
const MAX_SCAN_ENTRIES: usize = 100_000;
const MAX_DEPTH: usize = 8;
const MAX_SESSION_DELTA: u64 = 64 * 1024 * 1024;
const MAX_SESSION_IMPORT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SESSION_RECORDS: u64 = 100_000;
const MAX_TOOL_CALLS_PER_RECORD: usize = 1_024;
const MAX_METADATA_LINE: u64 = 1024 * 1024;
const SESSION_TAIL_WINDOW: u64 = 64 * 1024;
const MAX_GEMINI_PROJECT_REGISTRY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionFormat {
    Codex,
    Claude,
    Gemini,
}

impl SessionFormat {
    const fn name(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Gemini => "gemini",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FileStamp {
    device: u64,
    inode: u64,
    length: u64,
    stable_offset: u64,
}

impl FileStamp {
    fn read(path: &Path) -> io::Result<Self> {
        let mut file = open_regular_read(path)?;
        let metadata = file.metadata()?;
        let length = metadata.len();
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length,
            stable_offset: last_complete_record_offset(&mut file, length)?,
        })
    }
}

/// Snapshot of agent-owned session files taken immediately before launch.
/// Only bytes appended or files created by the target run are imported.
pub struct SessionReader {
    format: SessionFormat,
    cwd: PathBuf,
    roots: Vec<PathBuf>,
    baseline: BTreeMap<PathBuf, FileStamp>,
    gemini_home: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportReport {
    pub files_changed: u64,
    pub records: u64,
    pub malformed_records: u64,
    pub incomplete_tails: u64,
    pub truncated_files: u64,
    pub bytes_read: u64,
    pub omitted_records: u64,
    pub limit_reached: bool,
}

impl SessionReader {
    pub fn snapshot(adapter: &str, cwd: &Path) -> io::Result<Option<Self>> {
        Self::snapshot_with_environment(adapter, cwd, &BTreeMap::new())
    }

    pub fn snapshot_with_environment(
        adapter: &str,
        cwd: &Path,
        environment: &BTreeMap<OsString, OsString>,
    ) -> io::Result<Option<Self>> {
        let configured = |name: &str| {
            environment
                .get(OsStr::new(name))
                .cloned()
                .or_else(|| std::env::var_os(name))
        };
        let Some(home) = configured("HOME").map(PathBuf::from) else {
            return Ok(None);
        };
        let (format, roots, gemini_home) = match adapter {
            "codex" => {
                let root = configured("CODEX_HOME")
                    .map_or_else(|| home.join(".codex"), PathBuf::from)
                    .join("sessions");
                (SessionFormat::Codex, vec![root], None)
            }
            "claude" => (
                SessionFormat::Claude,
                vec![claude_session_root(
                    &home,
                    cwd,
                    configured("CLAUDE_CONFIG_DIR").as_deref(),
                )],
                None,
            ),
            "gemini" => {
                let base = configured("GEMINI_CLI_HOME").map_or_else(|| home, PathBuf::from);
                (
                    SessionFormat::Gemini,
                    gemini_session_roots(&base, cwd)?,
                    Some(base),
                )
            }
            _ => return Ok(None),
        };
        Self::snapshot_roots(format, cwd, roots).map(|mut reader| {
            reader.gemini_home = gemini_home;
            Some(reader)
        })
    }

    fn snapshot_roots(format: SessionFormat, cwd: &Path, roots: Vec<PathBuf>) -> io::Result<Self> {
        let mut baseline = BTreeMap::new();
        for root in &roots {
            for path in candidate_files(root)? {
                baseline.insert(path.clone(), FileStamp::read(&path)?);
            }
        }
        Ok(Self {
            format,
            cwd: cwd.to_path_buf(),
            roots,
            baseline,
            gemini_home: None,
        })
    }

    pub async fn import(self, store: &RunStore) -> io::Result<ImportReport> {
        let mut report = ImportReport::default();
        let mut roots = self.roots.clone();
        if let Some(home) = &self.gemini_home {
            roots.extend(gemini_session_roots(home, &self.cwd)?);
            roots.sort();
            roots.dedup();
        }
        'roots: for root in &roots {
            for path in candidate_files(root)? {
                if report.bytes_read >= MAX_SESSION_IMPORT_BYTES
                    || report.records >= MAX_SESSION_RECORDS
                {
                    report.limit_reached = true;
                    break 'roots;
                }
                let stamp = FileStamp::read(&path)?;
                if self.baseline.get(&path).is_some_and(|before| {
                    before.device == stamp.device
                        && before.inode == stamp.inode
                        && before.length == stamp.length
                }) {
                    continue;
                }
                let offset = if path.extension().is_some_and(|value| value == "json") {
                    // Legacy Gemini sessions are whole-file snapshots and may
                    // be rewritten in place, so deltas are not valid JSON.
                    0
                } else {
                    self.baseline.get(&path).map_or(0, |before| {
                        if before.device == stamp.device
                            && before.inode == stamp.inode
                            && stamp.length >= before.length
                        {
                            before.stable_offset
                        } else {
                            0
                        }
                    })
                };
                if stamp.length == offset {
                    continue;
                }
                if self
                    .import_file(store, &path, offset, stamp, &mut report)
                    .await?
                {
                    report.files_changed = report.files_changed.saturating_add(1);
                }
            }
        }
        Ok(report)
    }

    async fn import_file(
        &self,
        store: &RunStore,
        path: &Path,
        offset: u64,
        stamp: FileStamp,
        report: &mut ImportReport,
    ) -> io::Result<bool> {
        let available = stamp.length.saturating_sub(offset);
        let remaining_import_bytes = MAX_SESSION_IMPORT_BYTES.saturating_sub(report.bytes_read);
        let read_limit = available.min(MAX_SESSION_DELTA).min(remaining_import_bytes);
        let mut file = open_regular_read(path)?;
        let metadata = file.metadata()?;
        if metadata.dev() != stamp.device
            || metadata.ino() != stamp.inode
            || metadata.len() < stamp.length
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session file changed identity or shrank while being imported",
            ));
        }
        let codex_metadata = if self.format == SessionFormat::Codex {
            codex_session_metadata_from_file(&file)?
        } else {
            None
        };
        if self.format == SessionFormat::Codex
            && codex_metadata.as_ref().map(|item| &item.cwd) != Some(&self.cwd)
        {
            return Ok(false);
        }
        file.seek(SeekFrom::Start(offset))?;
        let capacity = usize::try_from(read_limit).unwrap_or(usize::MAX);
        let mut bytes = Vec::with_capacity(capacity);
        file.take(read_limit).read_to_end(&mut bytes)?;
        report.bytes_read = report
            .bytes_read
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));

        if available > read_limit {
            report.truncated_files = report.truncated_files.saturating_add(1);
            report.limit_reached = true;
            let mut event = store.event("session", "session_file_truncated");
            event.terminal_state = Some(TerminalState::Incomplete);
            event.confidence = Some(1.0);
            event.evidence = vec![format!("{}_session_file", self.format.name())];
            event.normalized = Some(json!({
                "file": safe_file_name(path),
                "available_bytes": available,
                "captured_bytes": read_limit,
            }));
            store.append(event).await.map_err(io::Error::other)?;
        }

        let complete_length = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |position| position + 1);
        let mut state = SessionState::default();
        if let Some(metadata) = codex_metadata {
            state.session_id = metadata.session_id;
        }
        if self.format == SessionFormat::Gemini {
            state.parent = gemini_parent_session(path);
        }
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let remaining_records = MAX_SESSION_RECORDS.saturating_sub(report.records);
            if let Some(value) = parse_json_value(&bytes) {
                let (persisted, omitted) = self
                    .persist_parsed_value(store, path, value, &mut state, remaining_records)
                    .await?;
                report.records = report.records.saturating_add(persisted);
                report.omitted_records = report.omitted_records.saturating_add(omitted);
                report.limit_reached |= omitted > 0;
            } else {
                persist_unparsed(store, self.format, path, &bytes).await?;
                report.malformed_records = report.malformed_records.saturating_add(1);
            }
            return Ok(true);
        }
        for line in bytes[..complete_length].split(|byte| *byte == b'\n') {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let remaining_records = MAX_SESSION_RECORDS.saturating_sub(report.records);
            if remaining_records == 0 {
                report.limit_reached = true;
                break;
            }
            if let Some(value) = parse_json_value(line) {
                let (persisted, omitted) = self
                    .persist_parsed_value(store, path, value, &mut state, remaining_records)
                    .await?;
                report.records = report.records.saturating_add(persisted);
                report.omitted_records = report.omitted_records.saturating_add(omitted);
                report.limit_reached |= omitted > 0;
            } else {
                persist_unparsed(store, self.format, path, line).await?;
                report.malformed_records = report.malformed_records.saturating_add(1);
            }
        }
        if complete_length != bytes.len() {
            report.incomplete_tails = report.incomplete_tails.saturating_add(1);
            let tail = &bytes[complete_length..];
            let mut event = store.event("session", "session_tail_incomplete");
            event.terminal_state = Some(TerminalState::Incomplete);
            event.confidence = Some(1.0);
            event.evidence = vec![format!("{}_session_file", self.format.name())];
            event.normalized = Some(json!({
                "file": safe_file_name(path),
                "bytes": tail.len(),
                "sha256": hex::encode(Sha256::digest(tail)),
            }));
            store.append(event).await.map_err(io::Error::other)?;
        }
        Ok(true)
    }

    async fn persist_parsed_value(
        &self,
        store: &RunStore,
        path: &Path,
        value: Value,
        state: &mut SessionState,
        remaining_records: u64,
    ) -> io::Result<(u64, u64)> {
        if remaining_records == 0 {
            return Ok((0, 1));
        }
        if self.format != SessionFormat::Gemini {
            self.persist_record(store, path, value, state).await?;
            return Ok((1, 0));
        }

        let messages = value
            .get("messages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if messages.is_empty() {
            self.persist_record(store, path, value, state).await?;
            return Ok((1, 0));
        }

        let mut metadata = value;
        if let Some(object) = metadata.as_object_mut() {
            object.remove("messages");
        }
        self.persist_record(store, path, metadata, state).await?;
        let message_count = u64::try_from(messages.len()).unwrap_or(u64::MAX);
        let messages_to_persist = usize::try_from(remaining_records.saturating_sub(1))
            .unwrap_or(usize::MAX)
            .min(messages.len());
        for message in messages.into_iter().take(messages_to_persist) {
            self.persist_record(store, path, message, state).await?;
        }
        let persisted =
            1_u64.saturating_add(u64::try_from(messages_to_persist).unwrap_or(u64::MAX));
        Ok((
            persisted,
            1_u64
                .saturating_add(message_count)
                .saturating_sub(persisted),
        ))
    }

    async fn persist_record(
        &self,
        store: &RunStore,
        path: &Path,
        value: Value,
        state: &mut SessionState,
    ) -> io::Result<()> {
        let record_type = record_type(self.format, &value).to_owned();
        update_state(self.format, &value, &record_type, state);
        let ids = extract_ids(self.format, &value, &record_type, state);
        ids.validate().map_err(io::Error::other)?;
        let (sanitized, redaction) = store.policy().sanitize_json_owned(value);
        if !redaction.omitted.is_empty() {
            store.note_capture_drop();
        }
        let raw = if store.policy().body_mode == BodyCaptureMode::Full {
            let bytes = serde_json::to_vec(&sanitized).map_err(io::Error::other)?;
            Some(
                store
                    .store_blob(&bytes, Some("application/json"))
                    .await
                    .map_err(io::Error::other)?,
            )
        } else {
            None
        };
        let mut event = store.event(
            "session",
            format!("session_{}", safe_event_label(&record_type)),
        );
        event.ids = ids;
        event.raw = raw;
        event.redaction = redaction;
        event.normalized = Some(record_summary(path, &record_type, &sanitized));
        event.confidence = Some(if event.ids.session_id.is_some() {
            1.0
        } else {
            0.6
        });
        event.evidence = vec![
            format!("{}_session_file", self.format.name()),
            "credential_redacted_record".to_owned(),
        ];
        if let Some(timestamp) = source_timestamp(&sanitized) {
            event.observed_at = timestamp;
        }
        store.append(event).await.map_err(io::Error::other)?;
        if self.format == SessionFormat::Gemini && record_type == "gemini" {
            persist_gemini_tool_calls(store, &sanitized, state).await?;
        }
        Ok(())
    }
}

fn claude_session_root(home: &Path, cwd: &Path, config_dir: Option<&OsStr>) -> PathBuf {
    config_dir
        .map_or_else(|| home.join(".claude"), PathBuf::from)
        .join("projects")
        .join(claude_project_key(cwd))
}

#[derive(Default)]
struct SessionState {
    session_id: Option<String>,
    turn_id: Option<String>,
    parent: Option<String>,
}

struct CodexMetadata {
    cwd: PathBuf,
    session_id: Option<String>,
}

fn codex_session_metadata_from_file(file: &File) -> io::Result<Option<CodexMetadata>> {
    let mut line = Vec::new();
    BufReader::new(file.try_clone()?)
        .take(MAX_METADATA_LINE)
        .read_until(b'\n', &mut line)?;
    let Some(value) = parse_json_value(&line) else {
        return Ok(None);
    };
    if value.get("type").and_then(Value::as_str) != Some("session_meta") {
        return Ok(None);
    }
    let Some(cwd) = value.pointer("/payload/cwd").and_then(Value::as_str) else {
        return Ok(None);
    };
    let session_id = string_at(&value, &["/payload/id", "/payload/session_id"]);
    Ok(Some(CodexMetadata {
        cwd: PathBuf::from(cwd),
        session_id,
    }))
}

fn parse_json_value(bytes: &[u8]) -> Option<Value> {
    validate_json_complexity(bytes).ok()?;
    serde_json::from_slice(bytes).ok()
}

fn update_state(format: SessionFormat, value: &Value, record_type: &str, state: &mut SessionState) {
    match format {
        SessionFormat::Codex => {
            let session_pointers = if record_type == "session_meta" {
                &["/payload/id", "/payload/session_id"][..]
            } else {
                &["/payload/session_id"][..]
            };
            if let Some(session_id) = string_at(value, session_pointers) {
                state.session_id = Some(session_id);
            }
            if let Some(turn_id) = string_at(value, &["/payload/turn_id"]) {
                state.turn_id = Some(turn_id);
            }
        }
        SessionFormat::Claude => {
            state.session_id = string_at(value, &["/sessionId", "/session_id"])
                .or_else(|| state.session_id.take());
            if record_type == "user"
                && !value
                    .get("isSidechain")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            {
                state.turn_id = string_at(value, &["/promptId", "/uuid"]);
            }
        }
        SessionFormat::Gemini => {
            state.session_id = string_at(value, &["/sessionId", "/$set/sessionId"])
                .or_else(|| state.session_id.take());
            if record_type == "user" {
                state.turn_id = string_at(value, &["/id"]);
            }
        }
    }
}

fn extract_ids(
    format: SessionFormat,
    value: &Value,
    record_type: &str,
    state: &SessionState,
) -> EventIds {
    let mut ids = EventIds {
        session_id: state.session_id.clone(),
        turn_id: state.turn_id.clone(),
        ..EventIds::default()
    };
    match format {
        SessionFormat::Codex => {
            ids.inference_id = string_at(
                value,
                &[
                    "/payload/response_id",
                    "/payload/request_id",
                    "/payload/call_id",
                ],
            );
            if record_type == "assistant" && ids.inference_id.is_none() {
                ids.inference_id = string_at(value, &["/payload/id"]);
            }
        }
        SessionFormat::Claude => {
            ids.parent_id = string_at(value, &["/parentUuid", "/parent_uuid", "/parentToolUseID"]);
            if record_type == "assistant" {
                ids.inference_id = string_at(value, &["/requestId", "/message/id", "/uuid"]);
            }
        }
        SessionFormat::Gemini => {
            ids.parent_id.clone_from(&state.parent);
            if record_type == "gemini" {
                ids.inference_id = string_at(value, &["/id"]);
            }
        }
    }
    ids
}

fn record_type(format: SessionFormat, value: &Value) -> &str {
    if format == SessionFormat::Codex
        && value.get("type").and_then(Value::as_str) == Some("response_item")
        && value.pointer("/payload/type").and_then(Value::as_str) == Some("message")
        && let Some(role @ ("assistant" | "developer" | "system" | "user")) =
            value.pointer("/payload/role").and_then(Value::as_str)
    {
        return role;
    }
    if format == SessionFormat::Gemini {
        if value.get("$rewindTo").is_some() {
            return "rewind";
        }
        if value.get("$set").is_some() {
            return "metadata_update";
        }
        if value.get("sessionId").is_some() && value.get("projectHash").is_some() {
            return "metadata";
        }
    }
    value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
}

async fn persist_gemini_tool_calls(
    store: &RunStore,
    value: &Value,
    state: &SessionState,
) -> io::Result<()> {
    let Some(tool_calls) = value.get("toolCalls").and_then(Value::as_array) else {
        return Ok(());
    };
    let inference_id = string_at(value, &["/id"]);
    for tool in tool_calls.iter().take(MAX_TOOL_CALLS_PER_RECORD) {
        let mut event = store.event("session", "session_tool_call");
        event.ids = EventIds {
            session_id: state.session_id.clone(),
            turn_id: state.turn_id.clone(),
            inference_id: inference_id.clone(),
            parent_id: inference_id.clone(),
            ..EventIds::default()
        };
        event.normalized = Some(json!({
            "tool_call_id": metadata::value_string(tool.get("id")),
            "name": metadata::value_string(tool.get("name")),
            "status": metadata::value_string(tool.get("status")),
            "agent_id": metadata::value_string(tool.get("agentId")),
        }));
        event.confidence = Some(1.0);
        event.evidence = vec!["gemini_session_file".to_owned()];
        if let Some(timestamp) = source_timestamp(tool) {
            event.observed_at = timestamp;
        }
        store.append(event).await.map_err(io::Error::other)?;
    }
    let omitted = tool_calls.len().saturating_sub(MAX_TOOL_CALLS_PER_RECORD);
    if omitted > 0 {
        store.note_capture_drops(u64::try_from(omitted).unwrap_or(u64::MAX));
    }
    Ok(())
}

fn record_summary(path: &Path, record_type: &str, value: &Value) -> Value {
    json!({
        "file": safe_file_name(path),
        "record_type": metadata::bounded_string(record_type),
        "payload_type": metadata::value_string(value.pointer("/payload/type")),
        "role": metadata::value_string(
            value.pointer("/payload/role").or_else(|| value.pointer("/message/role"))
        ),
        "model": metadata::value_string(
            value.get("model").or_else(|| value.pointer("/message/model"))
        ),
        "ordinal": value.get("ordinal").and_then(Value::as_u64),
    })
}

async fn persist_unparsed(
    store: &RunStore,
    format: SessionFormat,
    path: &Path,
    line: &[u8],
) -> io::Result<()> {
    let mut event = store.event("session", "session_record_unparsed");
    event.terminal_state = Some(TerminalState::Incomplete);
    event.confidence = Some(1.0);
    event.evidence = vec![format!("{}_session_file", format.name())];
    event.normalized = Some(json!({
        "file": safe_file_name(path),
        "bytes": line.len(),
        "sha256": hex::encode(Sha256::digest(line)),
    }));
    store.append(event).await.map_err(io::Error::other)?;
    Ok(())
}

fn source_timestamp(value: &Value) -> Option<DateTime<Utc>> {
    let text = value
        .get("timestamp")
        .or_else(|| value.pointer("/payload/timestamp"))
        .and_then(Value::as_str)?;
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn string_at(value: &Value, pointers: &[&str]) -> Option<String> {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer).and_then(Value::as_str))
        .filter(|value| !value.is_empty())
        .map(metadata::bounded_string)
}

fn candidate_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut output = Vec::new();
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut scanned_entries = 0_usize;
    while let Some((directory, depth)) = pending.pop() {
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session scan root and descendants must be real directories, not symlinks",
            ));
        }
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            scanned_entries = scanned_entries.saturating_add(1);
            if scanned_entries > MAX_SCAN_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session directory scan exceeded its entry safety limit",
                ));
            }
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() && depth < MAX_DEPTH {
                pending.push((entry.path(), depth + 1));
            } else if file_type.is_file()
                && entry.path().extension().is_some_and(|value| {
                    value.eq_ignore_ascii_case("jsonl") || value.eq_ignore_ascii_case("json")
                })
            {
                output.push(entry.path());
                if output.len() > MAX_FILES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "session file scan exceeded safety limit",
                    ));
                }
            }
        }
    }
    output.sort();
    Ok(output)
}

fn last_complete_record_offset(file: &mut File, length: u64) -> io::Result<u64> {
    if length == 0 {
        return Ok(0);
    }
    file.seek(SeekFrom::Start(length - 1))?;
    let mut last = [0_u8; 1];
    file.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(length);
    }

    let start = length.saturating_sub(SESSION_TAIL_WINDOW);
    file.seek(SeekFrom::Start(start))?;
    let mut tail = Vec::new();
    file.take(length - start).read_to_end(&mut tail)?;
    Ok(tail
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(start, |position| {
            start.saturating_add(u64::try_from(position + 1).unwrap_or(u64::MAX))
        }))
}

fn claude_project_key(cwd: &Path) -> String {
    cwd.to_string_lossy()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn gemini_project_hash(cwd: &Path) -> String {
    hex::encode(Sha256::digest(cwd.to_string_lossy().as_bytes()))
}

fn gemini_session_roots(home: &Path, cwd: &Path) -> io::Result<Vec<PathBuf>> {
    let temporary = home.join(".gemini/tmp");
    let mut identifiers = vec![gemini_project_hash(cwd)];
    if let Some(identifier) = gemini_project_identifier(home, cwd)? {
        identifiers.push(identifier);
    }
    identifiers.sort();
    identifiers.dedup();
    Ok(identifiers
        .into_iter()
        .map(|identifier| temporary.join(identifier).join("chats"))
        .collect())
}

fn gemini_project_identifier(home: &Path, cwd: &Path) -> io::Result<Option<String>> {
    let registry_path = home.join(".gemini/projects.json");
    let bytes = match read_regular_limited(&registry_path, MAX_GEMINI_PROJECT_REGISTRY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    validate_json_complexity(&bytes)?;
    let registry: Value = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Gemini project registry: {error}"),
        )
    })?;
    let Some(identifier) = registry
        .get("projects")
        .and_then(Value::as_object)
        .and_then(|projects| projects.get(cwd.to_string_lossy().as_ref()))
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    let mut components = Path::new(identifier).components();
    let valid_component = matches!(components.next(), Some(Component::Normal(component)) if component == OsStr::new(identifier));
    if identifier.is_empty()
        || identifier.len() > 255
        || !valid_component
        || components.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Gemini project registry contains an unsafe project identifier",
        ));
    }
    Ok(Some(identifier.to_owned()))
}

fn gemini_parent_session(path: &Path) -> Option<String> {
    let parent = path.parent()?.file_name()?.to_str()?;
    (parent != "chats").then(|| metadata::bounded_string(parent))
}

fn safe_event_label(value: &str) -> String {
    value
        .chars()
        .take(64)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn safe_file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || "unknown".to_owned(),
        |name| metadata::bounded_string(&name.to_string_lossy()),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, symlink},
    };

    use crate::{policy::CapturePolicy, storage::for_each_event};

    use super::*;

    #[test]
    fn claude_session_root_honors_explicit_config_directory() {
        let home = Path::new("/home/tester");
        let cwd = Path::new("/work/project");
        assert_eq!(
            claude_session_root(home, cwd, None),
            Path::new("/home/tester/.claude/projects/-work-project")
        );
        assert_eq!(
            claude_session_root(home, cwd, Some(OsStr::new("/private/claude"))),
            Path::new("/private/claude/projects/-work-project")
        );
    }

    fn append(path: &Path, text: &str) {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn session_scan_rejects_symlink_roots_and_allows_missing_roots() {
        let temporary = tempfile::tempdir().unwrap();
        let sessions = temporary.path().join("sessions");
        fs::create_dir(&sessions).unwrap();
        append(&sessions.join("session.jsonl"), "{}\n");
        let linked = temporary.path().join("linked-sessions");
        symlink(&sessions, &linked).unwrap();

        let error = candidate_files(&linked).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            candidate_files(&temporary.path().join("not-created"))
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn gemini_snapshot_follows_overlay_home_and_current_project_registry() {
        let temporary = tempfile::tempdir().unwrap();
        let home = temporary.path().join("overlay-home");
        fs::create_dir_all(home.join(".gemini")).unwrap();
        let cwd = temporary.path().join("project");
        fs::create_dir(&cwd).unwrap();
        let environment = BTreeMap::from([(
            OsString::from("GEMINI_CLI_HOME"),
            home.as_os_str().to_owned(),
        )]);
        let reader = SessionReader::snapshot_with_environment("gemini", &cwd, &environment)
            .unwrap()
            .unwrap();

        append(
            &home.join(".gemini/projects.json"),
            &json!({"projects": {cwd.to_string_lossy().as_ref(): "project-short-id"}}).to_string(),
        );
        let chats = home.join(".gemini/tmp/project-short-id/chats");
        fs::create_dir_all(&chats).unwrap();
        append(
            &chats.join("session.jsonl"),
            concat!(
                "{\"sessionId\":\"session-current\",\"projectHash\":\"hash\",\"startTime\":\"2026-01-01T00:00:00Z\"}\n",
                "{\"id\":\"turn-current\",\"timestamp\":\"2026-01-01T00:00:01Z\",\"type\":\"user\",\"content\":\"prompt\"}\n"
            ),
        );

        let run = temporary.path().join("run");
        let (store, _) = RunStore::create(&run, "run", CapturePolicy::default()).unwrap();
        let report = reader.import(&store).await.unwrap();
        store.shutdown().await.unwrap();
        assert_eq!(report.files_changed, 1);
        assert_eq!(report.records, 2);
    }

    #[test]
    fn gemini_project_registry_rejects_escaping_identifiers() {
        let temporary = tempfile::tempdir().unwrap();
        let config = temporary.path().join(".gemini");
        fs::create_dir(&config).unwrap();
        let cwd = Path::new("/work/project");
        append(
            &config.join("projects.json"),
            &json!({"projects": {"/work/project": "../outside"}}).to_string(),
        );
        assert_eq!(
            gemini_project_identifier(temporary.path(), cwd)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn codex_imports_only_appended_matching_records_and_redacts() {
        let temporary = tempfile::tempdir().unwrap();
        let sessions = temporary.path().join("sessions");
        fs::create_dir(&sessions).unwrap();
        let target = sessions.join("target.jsonl");
        append(
            &target,
            &format!(
                "{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"session-1\",\"cwd\":{}}}}}\n",
                serde_json::to_string(temporary.path().to_str().unwrap()).unwrap()
            ),
        );
        let reader = SessionReader::snapshot_roots(
            SessionFormat::Codex,
            temporary.path(),
            vec![sessions.clone()],
        )
        .unwrap();
        append(
            &target,
            "{\"type\":\"turn_context\",\"payload\":{\"turn_id\":\"turn-1\",\"authorization\":\"do-not-store\"}}\n",
        );
        let unrelated = sessions.join("unrelated.jsonl");
        append(
            &unrelated,
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"wrong\",\"cwd\":\"/elsewhere\"}}\n{\"type\":\"event_msg\",\"payload\":{}}\n",
        );

        let run = temporary.path().join("run");
        let (store, _) = RunStore::create(&run, "run", CapturePolicy::default()).unwrap();
        let report = reader.import(&store).await.unwrap();
        store.shutdown().await.unwrap();
        assert_eq!(report.files_changed, 1);
        assert_eq!(report.records, 1);
        let text = fs::read_to_string(run.join("events.jsonl")).unwrap();
        assert!(!text.contains("do-not-store"));
        assert!(!text.contains("wrong"));
        let mut events = Vec::new();
        for_each_event(&run.join("events.jsonl"), |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
        assert_eq!(events[0].ids.session_id.as_deref(), Some("session-1"));
        assert_eq!(events[0].ids.turn_id.as_deref(), Some("turn-1"));
    }

    #[tokio::test]
    async fn codex_current_messages_keep_the_session_and_identify_assistant_completion() {
        let temporary = tempfile::tempdir().unwrap();
        let sessions = temporary.path().join("sessions");
        fs::create_dir(&sessions).unwrap();
        let reader = SessionReader::snapshot_roots(
            SessionFormat::Codex,
            temporary.path(),
            vec![sessions.clone()],
        )
        .unwrap();
        let target = sessions.join("rollout.jsonl");
        append(
            &target,
            &format!(
                concat!(
                    "{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"session-current\",\"cwd\":{}}}}}\n",
                    "{{\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"turn-current\"}}}}\n",
                    "{{\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"developer\",\"id\":\"developer-message\"}}}}\n",
                    "{{\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"id\":\"assistant-message\"}}}}\n"
                ),
                serde_json::to_string(temporary.path().to_str().unwrap()).unwrap()
            ),
        );

        let run = temporary.path().join("run");
        let (store, _) = RunStore::create(&run, "run", CapturePolicy::default()).unwrap();
        let report = reader.import(&store).await.unwrap();
        store.shutdown().await.unwrap();
        assert_eq!(report.records, 4);

        let mut events = Vec::new();
        for_each_event(&run.join("events.jsonl"), |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
        assert!(events.iter().all(|event| {
            event.ids.session_id.as_deref() == Some("session-current")
                && event.ids.turn_id.as_deref() == Some("turn-current")
                || event.event == "session_session_meta"
        }));
        let assistant = events
            .iter()
            .find(|event| event.event == "session_assistant")
            .unwrap();
        assert_eq!(assistant.ids.session_id.as_deref(), Some("session-current"));
        assert_eq!(assistant.ids.turn_id.as_deref(), Some("turn-current"));
        assert_eq!(
            assistant.ids.inference_id.as_deref(),
            Some("assistant-message")
        );
    }

    #[tokio::test]
    async fn claude_preserves_turn_and_parent_relationships() {
        let temporary = tempfile::tempdir().unwrap();
        let sessions = temporary.path().join("sessions");
        fs::create_dir(&sessions).unwrap();
        let reader = SessionReader::snapshot_roots(
            SessionFormat::Claude,
            temporary.path(),
            vec![sessions.clone()],
        )
        .unwrap();
        let target = sessions.join("session.jsonl");
        append(
            &target,
            "{\"type\":\"user\",\"sessionId\":\"session-c\",\"uuid\":\"turn-c\",\"message\":{\"role\":\"user\"}}\n{\"type\":\"assistant\",\"sessionId\":\"session-c\",\"uuid\":\"answer-c\",\"parentUuid\":\"turn-c\",\"message\":{\"id\":\"inference-c\",\"role\":\"assistant\"}}\n",
        );

        let run = temporary.path().join("run");
        let (store, _) = RunStore::create(&run, "run", CapturePolicy::default()).unwrap();
        let report = reader.import(&store).await.unwrap();
        store.shutdown().await.unwrap();
        assert_eq!(report.records, 2);
        let mut events = Vec::new();
        for_each_event(&run.join("events.jsonl"), |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
        assert_eq!(events[1].ids.turn_id.as_deref(), Some("turn-c"));
        assert_eq!(events[1].ids.parent_id.as_deref(), Some("turn-c"));
        assert_eq!(events[1].ids.inference_id.as_deref(), Some("inference-c"));
    }

    #[tokio::test]
    async fn snapshot_replays_a_line_that_was_incomplete_at_launch() {
        let temporary = tempfile::tempdir().unwrap();
        let sessions = temporary.path().join("sessions");
        fs::create_dir(&sessions).unwrap();
        let target = sessions.join("session.jsonl");
        append(
            &target,
            "{\"type\":\"user\",\"sessionId\":\"session-c\",\"uuid\":",
        );
        let reader =
            SessionReader::snapshot_roots(SessionFormat::Claude, temporary.path(), vec![sessions])
                .unwrap();
        append(&target, "\"turn-c\"}\n");

        let run = temporary.path().join("run");
        let (store, _) = RunStore::create(&run, "run", CapturePolicy::default()).unwrap();
        let report = reader.import(&store).await.unwrap();
        store.shutdown().await.unwrap();
        assert_eq!(report.records, 1);
        assert_eq!(report.malformed_records, 0);
    }

    #[tokio::test]
    async fn gemini_jsonl_preserves_session_turn_inference_and_tool_topology() {
        let temporary = tempfile::tempdir().unwrap();
        let chats = temporary.path().join("chats");
        fs::create_dir(&chats).unwrap();
        let reader = SessionReader::snapshot_roots(
            SessionFormat::Gemini,
            temporary.path(),
            vec![chats.clone()],
        )
        .unwrap();
        let target = chats.join("session-test.jsonl");
        append(
            &target,
            concat!(
                "{\"sessionId\":\"session-g\",\"projectHash\":\"hash\",\"startTime\":\"2026-01-01T00:00:00Z\"}\n",
                "{\"id\":\"turn-g\",\"timestamp\":\"2026-01-01T00:00:01Z\",\"type\":\"user\",\"content\":\"prompt\"}\n",
                "{\"id\":\"inference-g\",\"timestamp\":\"2026-01-01T00:00:02Z\",\"type\":\"gemini\",\"model\":\"gemini-test\",\"content\":\"answer\",\"toolCalls\":[{\"id\":\"tool-g\",\"name\":\"read_file\",\"status\":\"success\",\"timestamp\":\"2026-01-01T00:00:03Z\"}]}\n"
            ),
        );

        let run = temporary.path().join("run");
        let (store, _) = RunStore::create(&run, "run", CapturePolicy::default()).unwrap();
        let report = reader.import(&store).await.unwrap();
        store.shutdown().await.unwrap();
        assert_eq!(report.records, 3);
        let mut events = Vec::new();
        for_each_event(&run.join("events.jsonl"), |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[1].ids.session_id.as_deref(), Some("session-g"));
        assert_eq!(events[1].ids.turn_id.as_deref(), Some("turn-g"));
        assert_eq!(events[2].ids.inference_id.as_deref(), Some("inference-g"));
        assert_eq!(events[3].event, "session_tool_call");
        assert_eq!(events[3].ids.parent_id.as_deref(), Some("inference-g"));
    }

    #[tokio::test]
    async fn gemini_legacy_json_expands_embedded_messages() {
        let temporary = tempfile::tempdir().unwrap();
        let chats = temporary.path().join("chats");
        fs::create_dir(&chats).unwrap();
        let reader = SessionReader::snapshot_roots(
            SessionFormat::Gemini,
            temporary.path(),
            vec![chats.clone()],
        )
        .unwrap();
        append(
            &chats.join("session-legacy.json"),
            "{\"sessionId\":\"legacy-g\",\"projectHash\":\"hash\",\"startTime\":\"2026-01-01T00:00:00Z\",\"lastUpdated\":\"2026-01-01T00:00:01Z\",\"messages\":[{\"id\":\"turn-legacy\",\"type\":\"user\",\"timestamp\":\"2026-01-01T00:00:01Z\",\"content\":\"prompt\"}]}",
        );

        let run = temporary.path().join("run");
        let (store, _) = RunStore::create(&run, "run", CapturePolicy::default()).unwrap();
        let report = reader.import(&store).await.unwrap();
        store.shutdown().await.unwrap();
        assert_eq!(report.records, 2);
        assert_eq!(report.malformed_records, 0);
    }
}
