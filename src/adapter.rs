use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::{RECORDER_VERSION, input::validate_json_complexity, secure_fs::read_regular_limited};

const MAX_ADAPTER_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_ADAPTER_OVERLAY_ENTRIES: usize = 10_000;
const MAX_ADAPTER_OVERLAY_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ADAPTER_OVERLAY_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AdapterSelection {
    Auto,
    None,
    Generic,
    Codex,
    Claude,
    Hermes,
    Gemini,
}

#[derive(Debug)]
pub struct AdapterPlan {
    pub name: String,
    pub environment: BTreeMap<OsString, OsString>,
    pub known_gaps: Vec<String>,
    _temporary: Option<TempDir>,
}

impl AdapterPlan {
    pub fn apply_environment(&self, command: &mut tokio::process::Command) {
        command.envs(self.environment.iter());
    }
}

pub fn prepare(
    selected: AdapterSelection,
    detected_agent: Option<&str>,
    command: &mut Vec<OsString>,
    proxy_url: Option<&str>,
) -> Result<AdapterPlan> {
    let resolved = match selected {
        AdapterSelection::Auto => match detected_agent {
            Some("codex") => AdapterSelection::Codex,
            Some("claude-code") => AdapterSelection::Claude,
            Some("hermes") => AdapterSelection::Hermes,
            Some("gemini-cli") => AdapterSelection::Gemini,
            _ => AdapterSelection::Generic,
        },
        explicit => explicit,
    };
    match resolved {
        AdapterSelection::Codex => prepare_codex(command, proxy_url),
        AdapterSelection::Claude => prepare_claude(command),
        AdapterSelection::Hermes => prepare_hermes(command, proxy_url),
        AdapterSelection::Gemini => prepare_gemini(proxy_url),
        AdapterSelection::Auto => anyhow::bail!("internal adapter resolution failure"),
        AdapterSelection::None | AdapterSelection::Generic => Ok(AdapterPlan {
            name: if resolved == AdapterSelection::None {
                "none"
            } else {
                "generic"
            }
            .to_owned(),
            environment: BTreeMap::new(),
            known_gaps: vec!["no agent-native lifecycle/model hook configured".to_owned()],
            _temporary: None,
        }),
    }
}

fn prepare_codex(command: &mut Vec<OsString>, proxy_url: Option<&str>) -> Result<AdapterPlan> {
    validate_codex_command(command)?;
    let mut gaps =
        vec!["Codex rustls traffic has no independent transport verification".to_owned()];
    if let Some(proxy_url) = proxy_url {
        let base_url = format!("{}/v1", proxy_url.trim_end_matches('/'));
        let mut overrides = vec![
            "model_provider=\"iorec\"".to_owned(),
            "model_providers.iorec.name=\"IORec Flight Recorder\"".to_owned(),
            format!("model_providers.iorec.base_url={}", json!(base_url)),
            "model_providers.iorec.wire_api=\"responses\"".to_owned(),
            "model_providers.iorec.supports_websockets=false".to_owned(),
        ];
        if std::env::var_os("OPENAI_API_KEY").is_some() {
            overrides.push("model_providers.iorec.env_key=\"OPENAI_API_KEY\"".to_owned());
        } else {
            overrides.push("model_providers.iorec.requires_openai_auth=true".to_owned());
        }
        insert_codex_config_options(
            command,
            overrides
                .into_iter()
                .flat_map(|value| [OsString::from("-c"), OsString::from(value)]),
        );
    } else {
        gaps.push("Codex provider was not redirected because --upstream is absent".to_owned());
    }
    Ok(AdapterPlan {
        name: "codex".to_owned(),
        environment: BTreeMap::new(),
        known_gaps: gaps,
        _temporary: None,
    })
}

fn prepare_claude(command: &mut Vec<OsString>) -> Result<AdapterPlan> {
    reject_flags(command, &["--bare", "--safe-mode", "--settings"], "Claude")?;
    let temporary = secure_tempdir("iorec-claude-")?;
    let executable = std::env::current_exe().context("resolve iorec executable for Claude hook")?;
    let hook_command = format!(
        "{} hook --source claude --event auto",
        shell_quote(executable.as_os_str())
    );
    let events = [
        "SessionStart",
        "SessionEnd",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "PermissionRequest",
        "PermissionDenied",
        "SubagentStart",
        "SubagentStop",
        "PreCompact",
        "PostCompact",
        "Stop",
        "StopFailure",
    ];
    let hooks: serde_json::Map<String, Value> = events
        .into_iter()
        .map(|event| {
            (
                event.to_owned(),
                json!([{"hooks": [{
                    "type": "command",
                    "command": hook_command,
                    "timeout": 10,
                    "statusMessage": "Recording agent lifecycle"
                }]}]),
            )
        })
        .collect();
    let settings = temporary.path().join("settings.json");
    write_private_json(&settings, &json!({"hooks": hooks}))?;
    insert_global_options(
        command,
        [
            OsString::from("--settings"),
            settings.as_os_str().to_owned(),
        ],
    );
    Ok(AdapterPlan {
        name: "claude".to_owned(),
        environment: BTreeMap::new(),
        known_gaps: vec![
            "Claude lifecycle hooks do not expose a native model hook".to_owned(),
            "OAuth, Bedrock, and Vertex endpoint compatibility is not independently verified"
                .to_owned(),
        ],
        _temporary: Some(temporary),
    })
}

fn prepare_gemini(proxy_url: Option<&str>) -> Result<AdapterPlan> {
    let source_home = std::env::var_os("GEMINI_CLI_HOME")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .context("cannot locate Gemini CLI home")?;
    prepare_gemini_from(
        &source_home,
        proxy_url,
        std::env::var_os("GEMINI_API_KEY").is_some(),
    )
}

fn prepare_gemini_from(
    source_home: &Path,
    proxy_url: Option<&str>,
    has_gemini_api_key: bool,
) -> Result<AdapterPlan> {
    let temporary = secure_tempdir("iorec-gemini-")?;
    let overlay_home = temporary.path().join("home");
    let overlay_config = overlay_home.join(".gemini");
    fs::create_dir(&overlay_home)?;
    fs::set_permissions(&overlay_home, fs::Permissions::from_mode(0o700))?;
    clone_gemini_config(&source_home.join(".gemini"), &overlay_config)?;

    let executable = std::env::current_exe().context("resolve iorec executable for Gemini hook")?;
    let hook_command = format!(
        "{} hook --source gemini --event auto",
        shell_quote(executable.as_os_str())
    );
    let events = [
        "SessionStart",
        "SessionEnd",
        "BeforeAgent",
        "AfterAgent",
        "BeforeModel",
        "AfterModel",
        "BeforeToolSelection",
        "BeforeTool",
        "AfterTool",
        "PreCompress",
        "Notification",
    ];
    let settings_path = overlay_config.join("settings.json");
    let mut settings = existing_json_file(&source_home.join(".gemini/settings.json"))?;
    let root = settings
        .as_object_mut()
        .context("existing Gemini user settings must be a JSON object")?;
    let configured_hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .context("existing Gemini hooks setting must be an object")?;
    for event in events {
        let event_hooks = configured_hooks
            .entry(event)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .with_context(|| format!("existing Gemini {event} hooks setting must be an array"))?;
        event_hooks.push(json!({
            "matcher": "*",
            "sequential": true,
            "hooks": [{
                "type": "command",
                "name": format!("iorec-{event}"),
                "command": hook_command,
                "timeout": 10000,
                "description": "Record agent inference lifecycle"
            }]
        }));
    }
    if proxy_url.is_some() && has_gemini_api_key {
        set_default_gemini_api_key_auth(root)?;
    }
    write_private_json(&settings_path, &settings)?;
    let mut environment = BTreeMap::new();
    environment.insert(
        OsString::from("GEMINI_CLI_HOME"),
        overlay_home.as_os_str().to_owned(),
    );
    Ok(AdapterPlan {
        name: "gemini".to_owned(),
        environment,
        known_gaps: vec!["Gemini stable model hooks may omit non-text multimodal parts".to_owned()],
        _temporary: Some(temporary),
    })
}

fn set_default_gemini_api_key_auth(root: &mut serde_json::Map<String, Value>) -> Result<()> {
    let security = root
        .entry("security")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .context("existing Gemini security setting must be an object")?;
    let auth = security
        .entry("auth")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .context("existing Gemini security.auth setting must be an object")?;
    auth.entry("selectedType")
        .or_insert_with(|| Value::String("gemini-api-key".to_owned()));
    Ok(())
}

fn prepare_hermes(command: &[OsString], proxy_url: Option<&str>) -> Result<AdapterPlan> {
    reject_flags(command, &["--safe-mode", "--ignore-user-config"], "Hermes")?;
    if proxy_url.is_some() {
        reject_flags(command, &["--provider"], "Hermes recorder routing")?;
    }
    let source_home = std::env::var_os("HERMES_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".hermes")))
        .context("cannot locate HERMES_HOME")?;
    let temporary = secure_tempdir("iorec-hermes-")?;
    let overlay = temporary.path().join("home");
    fs::create_dir(&overlay)?;
    fs::set_permissions(&overlay, fs::Permissions::from_mode(0o700))?;
    overlay_directory(&source_home, &overlay, &["config.yaml", "plugins"])?;
    overlay_plugins(&source_home.join("plugins"), &overlay.join("plugins"))?;
    write_hermes_plugin(&overlay.join("plugins/iorec"))?;
    write_hermes_config(
        &source_home.join("config.yaml"),
        &overlay.join("config.yaml"),
        proxy_url,
    )?;

    let mut environment = BTreeMap::new();
    environment.insert(
        OsString::from("HERMES_HOME"),
        overlay.as_os_str().to_owned(),
    );
    let mut gaps = vec![
        "Hermes observer hooks expose final responses but not individual stream chunks".to_owned(),
        "Hermes fallback provider identities collapse onto the configured single-upstream proxy"
            .to_owned(),
    ];
    if proxy_url.is_none() {
        gaps.push(
            "Hermes model endpoint was not redirected because --upstream is absent".to_owned(),
        );
    }
    Ok(AdapterPlan {
        name: "hermes".to_owned(),
        environment,
        known_gaps: gaps,
        _temporary: Some(temporary),
    })
}

fn insert_global_options(command: &mut Vec<OsString>, options: impl IntoIterator<Item = OsString>) {
    let options: Vec<OsString> = options.into_iter().collect();
    command.splice(1..1, options);
}

fn insert_codex_config_options(
    command: &mut Vec<OsString>,
    options: impl IntoIterator<Item = OsString>,
) {
    let options: Vec<OsString> = options.into_iter().collect();
    let insertion = codex_config_scope_index(command);
    command.splice(insertion..insertion, options);
}

fn codex_config_scope_index(command: &[OsString]) -> usize {
    let mut index = 1_usize;
    while index < command.len() {
        let argument = command[index].to_string_lossy();
        if matches!(argument.as_ref(), "exec" | "e" | "review") {
            // Codex 0.154 keeps top-level and non-interactive subcommand
            // config overrides in separate clap scopes. Put recorder-owned
            // provider keys in the same scope as user `exec`/`review` config
            // so an unrelated subcommand `-c` cannot replace the routing.
            return index + 1;
        }
        if argument == "--" {
            break;
        }
        if codex_global_option_takes_value(&argument) {
            index = index.saturating_add(2);
        } else {
            index += 1;
        }
    }
    1
}

fn codex_global_option_takes_value(argument: &str) -> bool {
    matches!(
        argument,
        "-c" | "--config"
            | "--enable"
            | "--disable"
            | "--remote"
            | "--remote-auth-token-env"
            | "-i"
            | "--image"
            | "-m"
            | "--model"
            | "--local-provider"
            | "-p"
            | "--profile"
            | "-s"
            | "--sandbox"
            | "-C"
            | "--cd"
            | "--add-dir"
            | "-a"
            | "--ask-for-approval"
    )
}

fn validate_codex_command(command: &[OsString]) -> Result<()> {
    reject_flags(
        command,
        &["--oss", "--local-provider", "--remote"],
        "Codex recorder routing",
    )?;
    let mut arguments = command.iter().skip(1);
    while let Some(argument) = arguments.next() {
        let text = argument.to_string_lossy();
        let config = if text == "-c" || text == "--config" {
            arguments.next().map(|value| value.to_string_lossy())
        } else if let Some(value) = text.strip_prefix("--config=") {
            Some(std::borrow::Cow::Borrowed(value))
        } else if text.starts_with("-c") && text.len() > 2 {
            Some(std::borrow::Cow::Borrowed(&text[2..]))
        } else {
            None
        };
        if let Some(config) = config {
            let key = config
                .split_once('=')
                .map_or(config.as_ref(), |(key, _)| key)
                .trim();
            anyhow::ensure!(
                key != "model_provider" && !key.starts_with("model_providers"),
                "Codex argument overrides recorder-controlled provider configuration: {key}"
            );
        }
    }
    Ok(())
}

fn reject_flags(command: &[OsString], forbidden: &[&str], context: &str) -> Result<()> {
    for argument in command.iter().skip(1) {
        let argument = argument.to_string_lossy();
        if let Some(flag) = forbidden.iter().find(|flag| {
            argument.as_ref() == **flag
                || argument
                    .strip_prefix(**flag)
                    .is_some_and(|suffix| suffix.starts_with('='))
        }) {
            anyhow::bail!("{context} cannot guarantee capture when {flag} is supplied");
        }
    }
    Ok(())
}

fn secure_tempdir(prefix: &str) -> io::Result<TempDir> {
    let directory = tempfile::Builder::new().prefix(prefix).tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

fn write_private_json(path: &Path, value: &Value) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn existing_json_file(path: &Path) -> Result<Value> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(json!({}));
        }
        Err(error) => return Err(error).context("inspect existing JSON settings"),
    };
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "existing JSON settings path is not a regular file: {}",
        path.display()
    );
    let bytes = read_regular_limited(path, MAX_ADAPTER_CONFIG_BYTES)
        .context("read existing JSON settings as a regular non-symlink file")?;
    let uncommented = strip_json_comments(&bytes).context("parse comments in JSON settings")?;
    validate_json_complexity(&uncommented)
        .context("existing JSON settings exceed safety limits")?;
    serde_json::from_slice(&uncommented).context("parse existing JSON settings")
}

fn strip_json_comments(input: &[u8]) -> Result<Vec<u8>> {
    #[derive(Clone, Copy)]
    enum State {
        Normal,
        String,
        Escape,
        LineComment,
        BlockComment,
        BlockCommentStar,
    }

    let mut output = input.to_vec();
    let mut state = State::Normal;
    let mut index = 0_usize;
    while index < input.len() {
        let byte = input[index];
        state = match state {
            State::Normal if byte == b'"' => State::String,
            State::Normal if byte == b'/' && input.get(index + 1) == Some(&b'/') => {
                output[index] = b' ';
                output[index + 1] = b' ';
                index += 1;
                State::LineComment
            }
            State::Normal if byte == b'/' && input.get(index + 1) == Some(&b'*') => {
                output[index] = b' ';
                output[index + 1] = b' ';
                index += 1;
                State::BlockComment
            }
            State::Normal => State::Normal,
            State::String if byte == b'\\' => State::Escape,
            State::String if byte == b'"' => State::Normal,
            State::String | State::Escape => State::String,
            State::LineComment if matches!(byte, b'\n' | b'\r') => State::Normal,
            State::LineComment => {
                output[index] = b' ';
                State::LineComment
            }
            State::BlockComment if byte == b'*' => {
                output[index] = b' ';
                State::BlockCommentStar
            }
            State::BlockComment => {
                if !matches!(byte, b'\n' | b'\r') {
                    output[index] = b' ';
                }
                State::BlockComment
            }
            State::BlockCommentStar if byte == b'/' => {
                output[index] = b' ';
                State::Normal
            }
            State::BlockCommentStar if byte == b'*' => {
                output[index] = b' ';
                State::BlockCommentStar
            }
            State::BlockCommentStar => {
                if !matches!(byte, b'\n' | b'\r') {
                    output[index] = b' ';
                }
                State::BlockComment
            }
        };
        index += 1;
    }
    anyhow::ensure!(
        !matches!(state, State::BlockComment | State::BlockCommentStar),
        "unterminated block comment"
    );
    Ok(output)
}

fn clone_gemini_config(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir(target)?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o700))?;
    if !source.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(source)?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "Gemini config root is not a regular directory: {}",
        source.display()
    );
    let mut entries = 0_usize;
    let mut bytes = 0_usize;
    clone_gemini_directory(source, target, true, &mut entries, &mut bytes)
}

fn clone_gemini_directory(
    source: &Path,
    target: &Path,
    root: bool,
    entries: &mut usize,
    bytes: &mut usize,
) -> Result<()> {
    let mut children = fs::read_dir(source)?.collect::<io::Result<Vec<_>>>()?;
    children.sort_by_key(fs::DirEntry::file_name);
    for child in children {
        check_overlay_entry_limit(entries)?;
        let name = child.file_name();
        if root && gemini_overlay_excluded(&name) {
            continue;
        }
        let source_path = child.path();
        let target_path = target.join(&name);
        let file_type = child.file_type()?;
        if file_type.is_dir() {
            fs::create_dir(&target_path)?;
            fs::set_permissions(&target_path, fs::Permissions::from_mode(0o700))?;
            clone_gemini_directory(&source_path, &target_path, false, entries, bytes)?;
        } else if file_type.is_file() {
            let content = read_regular_limited(&source_path, MAX_ADAPTER_OVERLAY_FILE_BYTES)
                .with_context(|| format!("copy Gemini config file {}", source_path.display()))?;
            *bytes = bytes
                .checked_add(content.len())
                .context("Gemini config size overflow")?;
            anyhow::ensure!(
                *bytes <= MAX_ADAPTER_OVERLAY_BYTES,
                "Gemini config overlay exceeds the {MAX_ADAPTER_OVERLAY_BYTES}-byte safety limit"
            );
            write_private(target_path, &content)?;
        } else {
            anyhow::bail!(
                "Gemini config contains a symlink or special file that cannot be isolated safely: {}",
                source_path.display()
            );
        }
    }
    Ok(())
}

fn gemini_overlay_excluded(name: &OsStr) -> bool {
    matches!(
        name.to_str(),
        Some("settings.json" | "tmp" | "history" | "bin" | "cli-browser-profile")
    ) || name.to_str().is_some_and(|value| {
        value.starts_with("projects.json.")
            && Path::new(value)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("tmp"))
    })
}

fn shell_quote(value: &OsStr) -> String {
    let text = value.to_string_lossy();
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn overlay_directory(source: &Path, target: &Path, excluded: &[&str]) -> io::Result<()> {
    if !source.is_dir() {
        return Ok(());
    }
    let mut entries = 0_usize;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        check_overlay_entry_limit(&mut entries)?;
        if excluded
            .iter()
            .any(|name| entry.file_name() == OsStr::new(name))
        {
            continue;
        }
        symlink(entry.path(), target.join(entry.file_name()))?;
    }
    Ok(())
}

fn overlay_plugins(source: &Path, target: &Path) -> io::Result<()> {
    fs::create_dir(target)?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o700))?;
    if source.is_dir() {
        let mut entries = 0_usize;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            check_overlay_entry_limit(&mut entries)?;
            if entry.file_name() != OsStr::new("iorec") {
                symlink(entry.path(), target.join(entry.file_name()))?;
            }
        }
    }
    Ok(())
}

fn check_overlay_entry_limit(entries: &mut usize) -> io::Result<()> {
    *entries = entries.saturating_add(1);
    if *entries > MAX_ADAPTER_OVERLAY_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("adapter overlay exceeds the {MAX_ADAPTER_OVERLAY_ENTRIES}-entry safety limit"),
        ));
    }
    Ok(())
}

fn write_hermes_config(source: &Path, target: &Path, proxy_url: Option<&str>) -> Result<()> {
    let mut config: serde_yaml_ng::Value = match fs::symlink_metadata(source) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let bytes = read_regular_limited(source, MAX_ADAPTER_CONFIG_BYTES)
                .context("read Hermes config as a regular non-symlink file")?;
            serde_yaml_ng::from_slice(&bytes).context("parse Hermes config")?
        }
        Ok(_) => anyhow::bail!("Hermes config exists but is not a regular file"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::default())
        }
        Err(error) => return Err(error).context("inspect Hermes config"),
    };
    let root = config
        .as_mapping_mut()
        .context("Hermes config root must be a mapping")?;
    let plugins = root
        .entry(serde_yaml_ng::Value::String("plugins".to_owned()))
        .or_insert_with(|| serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::default()))
        .as_mapping_mut()
        .context("Hermes plugins config must be a mapping")?;
    let enabled = plugins
        .entry(serde_yaml_ng::Value::String("enabled".to_owned()))
        .or_insert_with(|| serde_yaml_ng::Value::Sequence(Vec::new()))
        .as_sequence_mut()
        .context("Hermes plugins.enabled must be a sequence")?;
    let iorec = serde_yaml_ng::Value::String("iorec".to_owned());
    if !enabled.contains(&iorec) {
        enabled.push(iorec);
    }
    if let Some(proxy_url) = proxy_url {
        let endpoint = format!("{}/v1", proxy_url.trim_end_matches('/'));
        let model_key = serde_yaml_ng::Value::String("model".to_owned());
        {
            let model = root
                .entry(model_key)
                .or_insert_with(|| serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::default()))
                .as_mapping_mut()
                .context("Hermes model config must be a mapping")?;
            model.insert(
                serde_yaml_ng::Value::String("base_url".to_owned()),
                serde_yaml_ng::Value::String(endpoint.clone()),
            );
            rewrite_hermes_fallbacks(
                model.get_mut(serde_yaml_ng::Value::String(
                    "fallback_providers".to_owned(),
                )),
                &endpoint,
            );
        }
        rewrite_hermes_fallbacks(
            root.get_mut(serde_yaml_ng::Value::String(
                "fallback_providers".to_owned(),
            )),
            &endpoint,
        );
    }
    let bytes = serde_yaml_ng::to_string(&config)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(target)?;
    output.write_all(bytes.as_bytes())?;
    output.sync_all()?;
    Ok(())
}

fn rewrite_hermes_fallbacks(value: Option<&mut serde_yaml_ng::Value>, endpoint: &str) {
    let Some(fallbacks) = value.and_then(serde_yaml_ng::Value::as_sequence_mut) else {
        return;
    };
    for fallback in fallbacks {
        if let Some(mapping) = fallback.as_mapping_mut() {
            mapping.insert(
                serde_yaml_ng::Value::String("base_url".to_owned()),
                serde_yaml_ng::Value::String(endpoint.to_owned()),
            );
        }
    }
}

fn write_hermes_plugin(path: &Path) -> io::Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let manifest = format!(
        "name: iorec\nversion: \"{RECORDER_VERSION}\"\ndescription: Read-only Agent Inference Flight Recorder observer\nhooks:\n  - pre_api_request\n  - post_api_request\n  - api_request_error\n  - pre_llm_call\n  - post_llm_call\n  - pre_tool_call\n  - post_tool_call\n  - on_session_start\n  - on_session_end\n  - on_session_finalize\n  - on_session_reset\n  - subagent_start\n  - subagent_stop\n"
    );
    write_private(path.join("plugin.yaml"), manifest.as_bytes())?;
    write_private(path.join("__init__.py"), HERMES_PLUGIN.as_bytes())?;
    Ok(())
}

fn write_private(path: PathBuf, bytes: &[u8]) -> io::Result<()> {
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    output.write_all(bytes)?;
    output.sync_all()
}

const HERMES_PLUGIN: &str = r#"import json
import math
import os
import socket

_HOOKS = (
    "pre_api_request", "post_api_request", "api_request_error",
    "pre_llm_call", "post_llm_call", "pre_tool_call", "post_tool_call",
    "on_session_start", "on_session_end", "on_session_finalize",
    "on_session_reset", "subagent_start", "subagent_stop",
)

_MAX_DEPTH = 24
_MAX_NODES = 10000
_MAX_ITEMS = 1024
_MAX_STRING = 4096
_MAX_SUBMISSION_BYTES = 16 * 1024 * 1024

def _safe(value, depth=0, budget=None):
    if budget is None:
        budget = [_MAX_NODES]
    if budget[0] <= 0:
        return {"truncated": True, "reason": "max_nodes"}
    budget[0] -= 1
    if depth > _MAX_DEPTH:
        return {"truncated": True, "reason": "max_depth"}
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else {"type": "float", "value": repr(value)}
    if isinstance(value, str):
        if len(value) <= _MAX_STRING:
            return value
        return {
            "type": "str",
            "prefix": value[:_MAX_STRING],
            "length": len(value),
            "truncated": True,
        }
    if isinstance(value, dict):
        output = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _MAX_ITEMS:
                output["[TRUNCATED]"] = {"reason": "max_items"}
                break
            output[str(key)[:_MAX_STRING]] = _safe(item, depth + 1, budget)
        return output
    if isinstance(value, (list, tuple)):
        output = [_safe(item, depth + 1, budget) for item in value[:_MAX_ITEMS]]
        if len(value) > _MAX_ITEMS:
            output.append({"truncated": True, "reason": "max_items"})
        return output
    try:
        rendered = repr(value)[:_MAX_STRING]
    except Exception:
        rendered = "[UNAVAILABLE]"
    return {"type": type(value).__name__[:128], "repr": rendered}

def _send(name, payload):
    socket_path = os.environ.get("IOREC_COLLECTOR_SOCKET")
    token = os.environ.get("IOREC_COLLECTOR_TOKEN")
    if not socket_path or not token:
        return
    try:
        submission = {
            "token": token,
            "source": "hermes",
            "event": name,
            "payload": _safe(payload),
            "evidence": ["hermes.observer.v1"],
        }
        data = json.dumps(
            submission, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if len(data) > _MAX_SUBMISSION_BYTES:
            submission["payload"] = {
                "truncated": True,
                "reason": "max_submission_bytes",
                "encoded_bytes": len(data),
            }
            data = json.dumps(
                submission, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10.0)
            client.connect(socket_path)
            client.sendall(data)
            client.shutdown(socket.SHUT_WR)
            response = client.recv(65536)
        if not json.loads(response).get("accepted"):
            raise RuntimeError("iorec collector rejected observer event")
    except Exception:
        # Hermes observer hooks are fail-open by contract. Transport capture
        # and the coverage manifest remain the independent loss detectors.
        return

def register(ctx):
    for hook_name in _HOOKS:
        def callback(_hook_name=hook_name, **kwargs):
            _send(_hook_name, kwargs)
        ctx.register_hook(hook_name, callback)
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_adapter_uses_ephemeral_responses_provider() {
        let mut command = vec![OsString::from("codex"), OsString::from("exec")];
        let plan = prepare(
            AdapterSelection::Codex,
            Some("codex"),
            &mut command,
            Some("http://127.0.0.1:1234"),
        )
        .unwrap();
        let rendered: Vec<String> = command
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(plan.name, "codex");
        assert!(
            rendered
                .iter()
                .any(|value| value == "model_provider=\"iorec\"")
        );
        assert!(
            rendered
                .iter()
                .any(|value| value.contains("http://127.0.0.1:1234/v1"))
        );
        assert_eq!(rendered.first().map(String::as_str), Some("codex"));
        assert_eq!(rendered.get(1).map(String::as_str), Some("exec"));
        assert_eq!(rendered.get(2).map(String::as_str), Some("-c"));
    }

    #[test]
    fn codex_provider_stays_in_exec_scope_with_user_config() {
        let mut command = vec![
            OsString::from("codex"),
            OsString::from("-m"),
            OsString::from("test-model"),
            OsString::from("exec"),
            OsString::from("-c"),
            OsString::from("analytics.enabled=false"),
            OsString::from("prompt"),
        ];
        prepare(
            AdapterSelection::Codex,
            Some("codex"),
            &mut command,
            Some("http://127.0.0.1:1234"),
        )
        .unwrap();
        let exec_index = command
            .iter()
            .position(|value| value == OsStr::new("exec"))
            .unwrap();
        let provider_index = command
            .iter()
            .position(|value| value == OsStr::new("model_provider=\"iorec\""))
            .unwrap();
        let user_config_index = command
            .iter()
            .position(|value| value == OsStr::new("analytics.enabled=false"))
            .unwrap();
        assert!(exec_index < provider_index);
        assert!(provider_index < user_config_index);
    }

    #[test]
    fn claude_settings_cover_lifecycle_events_without_touching_user_config() {
        let mut command = vec![OsString::from("claude"), OsString::from("-p")];
        let plan = prepare(
            AdapterSelection::Claude,
            Some("claude-code"),
            &mut command,
            None,
        )
        .unwrap();
        let settings_index = command
            .iter()
            .position(|value| value == OsStr::new("--settings"))
            .unwrap();
        let settings = fs::read_to_string(&command[settings_index + 1]).unwrap();
        assert!(settings.contains("SessionStart"));
        assert!(settings.contains("SubagentStart"));
        assert!(settings.contains("PreCompact"));
        drop(plan);
    }

    #[test]
    fn gemini_uses_isolated_user_overlay_and_preserves_existing_hooks() {
        let source = tempfile::tempdir().unwrap();
        let source_config = source.path().join(".gemini");
        fs::create_dir(&source_config).unwrap();
        let original = br#"{
            // Gemini accepts JSON comments in user settings.
            "general": {"enableAutoUpdate": false},
            "hooks": {
                "BeforeModel": [{
                    "matcher": "*",
                    "hooks": [{"type": "command", "name": "existing", "command": "true"}]
                }]
            }
        }
"#;
        write_private(source_config.join("settings.json"), original).unwrap();
        write_private(source_config.join("projects.json"), b"{\"source\":true}\n").unwrap();
        fs::create_dir(source_config.join("tmp")).unwrap();
        write_private(source_config.join("tmp/session.json"), b"{}\n").unwrap();

        let plan = prepare_gemini_from(source.path(), Some("http://127.0.0.1:1234"), true).unwrap();
        assert!(
            !plan
                .environment
                .contains_key(OsStr::new("GEMINI_CLI_SYSTEM_SETTINGS_PATH"))
        );
        let overlay_home =
            PathBuf::from(plan.environment.get(OsStr::new("GEMINI_CLI_HOME")).unwrap());
        let overlay_config = overlay_home.join(".gemini");
        let settings: Value =
            serde_json::from_slice(&fs::read(overlay_config.join("settings.json")).unwrap())
                .unwrap();
        assert_eq!(settings["general"]["enableAutoUpdate"], false);
        assert_eq!(
            settings["hooks"]["BeforeModel"].as_array().unwrap().len(),
            2
        );
        assert_eq!(
            settings["security"]["auth"]["selectedType"],
            "gemini-api-key"
        );
        assert!(
            settings["hooks"]["AfterModel"][0]["hooks"][0]["command"]
                .as_str()
                .unwrap()
                .contains("hook --source gemini --event auto")
        );
        assert!(!overlay_config.join("tmp").exists());
        assert!(!overlay_config.join("projects.json").is_symlink());
        fs::write(
            overlay_config.join("projects.json"),
            b"{\"overlay\":true}\n",
        )
        .unwrap();
        assert_eq!(
            fs::read(source_config.join("projects.json")).unwrap(),
            b"{\"source\":true}\n"
        );
        assert_eq!(
            fs::read(source_config.join("settings.json")).unwrap(),
            original
        );
    }

    #[test]
    fn gemini_preserves_an_explicit_auth_method() {
        let source = tempfile::tempdir().unwrap();
        let source_config = source.path().join(".gemini");
        fs::create_dir(&source_config).unwrap();
        write_private(
            source_config.join("settings.json"),
            br#"{"security":{"auth":{"selectedType":"oauth-personal"}}}"#,
        )
        .unwrap();
        let plan = prepare_gemini_from(source.path(), Some("http://127.0.0.1:1234"), true).unwrap();
        let overlay_home =
            PathBuf::from(plan.environment.get(OsStr::new("GEMINI_CLI_HOME")).unwrap());
        let settings: Value =
            serde_json::from_slice(&fs::read(overlay_home.join(".gemini/settings.json")).unwrap())
                .unwrap();
        assert_eq!(
            settings["security"]["auth"]["selectedType"],
            "oauth-personal"
        );
    }

    #[test]
    fn gemini_overlay_rejects_symlinks_in_user_config() {
        let source = tempfile::tempdir().unwrap();
        let source_config = source.path().join(".gemini");
        fs::create_dir(&source_config).unwrap();
        symlink("/tmp", source_config.join("extensions")).unwrap();
        assert!(prepare_gemini_from(source.path(), None, false).is_err());
    }

    #[test]
    fn json_comment_stripping_ignores_comment_markers_inside_strings() {
        let stripped = strip_json_comments(
            br#"{"url":"https://example.test/a/*b*/",/* block */"enabled":true}// tail"#,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&stripped).unwrap();
        assert_eq!(value["url"], "https://example.test/a/*b*/");
        assert_eq!(value["enabled"], true);
        assert!(strip_json_comments(b"{/* unterminated").is_err());
    }

    #[test]
    fn codex_rejects_provider_overrides_that_could_bypass_capture() {
        let mut command = vec![
            OsString::from("codex"),
            OsString::from("--config"),
            OsString::from("model_provider=other"),
            OsString::from("exec"),
        ];
        assert!(
            prepare(
                AdapterSelection::Codex,
                Some("codex"),
                &mut command,
                Some("http://127.0.0.1:1234"),
            )
            .is_err()
        );
    }

    #[test]
    fn agent_flags_that_disable_hooks_or_overlay_are_rejected() {
        let mut claude = vec![OsString::from("claude"), OsString::from("--bare")];
        assert!(prepare(AdapterSelection::Claude, None, &mut claude, None).is_err());

        let mut claude_safe = vec![OsString::from("claude"), OsString::from("--safe-mode")];
        assert!(prepare(AdapterSelection::Claude, None, &mut claude_safe, None).is_err());

        let mut hermes = vec![OsString::from("hermes"), OsString::from("--safe-mode")];
        assert!(prepare(AdapterSelection::Hermes, None, &mut hermes, None).is_err());
    }

    #[test]
    fn hermes_observer_is_fail_open_and_bounds_payload_conversion() {
        let try_offset = HERMES_PLUGIN.find("    try:\n        submission").unwrap();
        let safe_offset = HERMES_PLUGIN.find("\"payload\": _safe(payload)").unwrap();
        assert!(try_offset < safe_offset);
        assert!(HERMES_PLUGIN.contains("_MAX_NODES = 10000"));
        assert!(HERMES_PLUGIN.contains("_MAX_ITEMS = 1024"));
        assert!(HERMES_PLUGIN.contains("allow_nan=False"));
    }

    #[test]
    fn adapter_overlay_entry_limit_fails_closed() {
        let mut entries = MAX_ADAPTER_OVERLAY_ENTRIES;
        let error = check_overlay_entry_limit(&mut entries).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(entries, MAX_ADAPTER_OVERLAY_ENTRIES + 1);
    }
}
