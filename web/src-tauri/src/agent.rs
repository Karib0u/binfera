//! Runs the analyst's own agent inside the app.
//!
//! Each chat turn starts an agent process and attaches Binfera's MCP server (`binfera mcp`, the
//! bundled sidecar) for that run. The process's events are translated into [`AgentEvent`],
//! and a conversation continues by resuming the session id the agent reports.
//!
//! The prompt goes in on stdin: Claude's `--allowedTools` and `--mcp-config` are variadic and
//! would swallow a positional prompt, and stdin has no length or quoting limits.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use tauri::ipc::Channel;
use tauri::State;

mod vibe;

/// Longest tool output kept for display; the agent itself always sees all of it.
const OUTPUT_CHARS: usize = 4000;
/// stderr kept for the error message.
const STDERR_LINES: usize = 30;

#[derive(Default)]
struct Inner {
    /// Process id of each live run (also its process group on Unix).
    running: Mutex<HashMap<u64, u32>>,
    /// Runs the panel cancelled, so a cancel that races ahead of the spawn still takes effect.
    cancelled: Mutex<HashSet<u64>>,
}

#[derive(Clone, Default)]
pub struct Agents(Arc<Inner>);

impl Agents {
    /// Stops every live run; called when the app exits.
    pub fn shutdown(&self) {
        let pids: Vec<u32> = self.0.running.lock().unwrap().values().copied().collect();
        for pid in pids {
            crate::engine::kill_tree(pid);
        }
    }
}

/// What the panel shows, whichever agent produced it.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum AgentEvent {
    /// The id to resume this conversation with.
    Session {
        id: String,
    },
    /// A piece of the agent's answer.
    Text {
        text: String,
    },
    /// A tool call; the same `id` is sent again when it finishes, with `status` and `output`.
    Tool {
        id: String,
        name: String,
        input: Value,
        /// `running`, `done` or `error`.
        status: String,
        output: Option<String>,
    },
    /// What the turn cost, sent just before `Done`.
    Usage {
        input: u64,
        output: u64,
        cost: Option<f64>,
    },
    /// The turn is over.
    Done,
    Error {
        message: String,
    },
}

#[derive(Serialize)]
pub struct AgentInfo {
    id: &'static str,
    name: &'static str,
    /// Where the CLI was found; `None` when it is not installed.
    path: Option<String>,
    version: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRequest {
    id: u64,
    /// The desktop provider id.
    provider: String,
    prompt: String,
    /// The session id of an earlier turn, to continue that conversation.
    session: Option<String>,
    /// A model name for the agent's `--model`; the agent's own default when absent.
    model: Option<String>,
    /// How hard the model reasons; the agent's own default when absent.
    effort: Option<String>,
}

/// What the panel may pick besides the agent's defaults.
#[derive(Debug, Default, PartialEq)]
struct Choice<'a> {
    model: Option<&'a str>,
    effort: Option<&'a str>,
}

/// The panel's model and effort, checked: they end up on a command line and in a config value, so
/// only plain model names (letters, digits and `. _ - : / [ ]`) and a lowercase effort word pass. The
/// levels themselves come from each model's own list, which changes with the models.
fn choice<'a>(model: Option<&'a str>, effort: Option<&'a str>) -> Result<Choice<'a>, String> {
    let model = model.map(str::trim).filter(|m| !m.is_empty());
    if let Some(m) = model {
        let plain = m.len() <= 80
            && !m.starts_with('-')
            && m.chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-_:/[]".contains(c));
        if !plain {
            return Err(format!("not a model name: {m}"));
        }
    }
    let effort = effort.map(str::trim).filter(|e| !e.is_empty());
    if let Some(e) = effort {
        if e.len() > 16 || !e.chars().all(|c| c.is_ascii_lowercase()) {
            return Err(format!("unknown reasoning effort: {e}"));
        }
    }
    Ok(Choice { model, effort })
}

// ----- finding the CLI -----------------------------------------------------------------------

/// A desktop app starts with a minimal PATH, so the usual install locations are searched as well.
fn search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    // Where uv installs tools such as the Vibe CLI when its default (~/.local/bin) is moved.
    for var in ["UV_TOOL_BIN_DIR", "XDG_BIN_HOME"] {
        if let Some(dir) = std::env::var_os(var).filter(|d| !d.is_empty()) {
            dirs.push(PathBuf::from(dir));
        }
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let home = PathBuf::from(home);
        for rel in [
            ".local/bin",
            ".claude/local",
            ".npm-global/bin",
            ".bun/bin",
            ".volta/bin",
            ".cargo/bin",
            "AppData/Roaming/npm",
        ] {
            dirs.push(home.join(rel));
        }
        // nvm keeps one bin directory per Node version.
        if let Ok(versions) = std::fs::read_dir(home.join(".nvm/versions/node")) {
            for v in versions.flatten() {
                dirs.push(v.path().join("bin"));
            }
        }
    }
    for fixed in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        dirs.push(PathBuf::from(fixed));
    }
    dirs
}

fn find(name: &str) -> Option<PathBuf> {
    let names: Vec<String> = if cfg!(windows) {
        vec![format!("{name}.exe"), format!("{name}.cmd")]
    } else {
        vec![name.to_string()]
    };
    search_dirs()
        .into_iter()
        .flat_map(|d| names.iter().map(move |n| d.join(n)))
        .find(|p| p.is_file())
}

/// The PATH a spawned agent runs with: Codex's launcher is a Node script and needs `node` found.
fn child_path() -> std::ffi::OsString {
    std::env::join_paths(search_dirs()).unwrap_or_default()
}

fn version_of(program: &PathBuf) -> Option<String> {
    let out = Command::new(program)
        .arg("--version")
        .env("PATH", child_path())
        .stdin(Stdio::null())
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
}

#[tauri::command]
pub async fn agent_detect() -> Vec<AgentInfo> {
    tauri::async_runtime::spawn_blocking(|| {
        [("claude", "Claude Code"), ("codex", "Codex")]
            .into_iter()
            .chain([("vibe", "Mistral Vibe")])
            .map(|(id, name)| {
                let path = find_provider(id);
                AgentInfo {
                    id,
                    name,
                    version: path.as_ref().and_then(|path| {
                        if id == "vibe" {
                            vibe::version(path.clone())
                        } else {
                            version_of(path)
                        }
                    }),
                    path: path.map(|p| p.to_string_lossy().into_owned()),
                }
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

fn find_provider(provider: &str) -> Option<PathBuf> {
    if provider == "vibe" {
        vibe::find_server()
    } else {
        find(provider)
    }
}

// ----- the models an agent offers ------------------------------------------------------------

/// One model the agent lists for itself, as the panel's picker shows it.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelInfo {
    /// What `--model` takes.
    id: String,
    name: String,
    description: String,
    /// The reasoning levels this model supports, lowest first; empty when it has none to choose.
    efforts: Vec<String>,
    default_effort: Option<String>,
    /// The agent's own default model.
    is_default: bool,
}

/// The answer to Claude Code's `initialize` control request.
fn parse_claude_models(response: &Value) -> Vec<ModelInfo> {
    let models = response["response"]["response"]["models"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    // The "default" row names the model the user's settings resolve to.
    let resolved = models
        .iter()
        .find(|m| m["value"] == "default")
        .and_then(|m| m["resolvedModel"].as_str());
    let mut default_marked = false;
    models
        .iter()
        // "default" stands for whatever the user's settings say; the panel's own Default row does that.
        .filter(|m| m["value"] != "default")
        .filter_map(|m| {
            Some(ModelInfo {
                id: m["value"].as_str()?.into(),
                name: m["displayName"].as_str().or(m["value"].as_str())?.into(),
                description: m["description"].as_str().unwrap_or_default().into(),
                efforts: m["supportedEffortLevels"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.as_str().map(String::from))
                    .collect(),
                default_effort: None,
                is_default: {
                    let is = !default_marked
                        && resolved.is_some()
                        && (m["resolvedModel"].as_str() == resolved
                            || m["value"].as_str() == resolved);
                    default_marked |= is;
                    is
                },
            })
        })
        .collect()
}

/// What the agent uses when the panel leaves a choice blank, from the agent's own configuration.
#[derive(Debug, Default, PartialEq)]
struct Configured {
    model: Option<String>,
    effort: Option<String>,
}

fn config_dir(var: &str, default: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|home| PathBuf::from(home).join(default))
        })
}

/// Claude Code's effort: `CLAUDE_CODE_EFFORT_LEVEL`, else `effortLevel` in its user settings.
fn claude_configured(env: Option<String>, settings: Option<&str>) -> Configured {
    let effort = env.filter(|e| !e.trim().is_empty()).or_else(|| {
        let settings: Value = serde_json::from_str(settings?).ok()?;
        settings["effortLevel"].as_str().map(String::from)
    });
    Configured {
        model: None,
        effort: effort.map(|e| e.trim().to_lowercase()),
    }
}

/// Codex's `model` and `model_reasoning_effort` from its config.toml.
fn codex_configured(config: Option<&str>) -> Configured {
    let Some(table) = config.and_then(|c| c.parse::<toml::Table>().ok()) else {
        return Configured::default();
    };
    // The selected profile's values replace the top-level ones.
    let profile = table
        .get("profile")
        .and_then(|p| p.as_str())
        .and_then(|name| table.get("profiles")?.get(name));
    let get = |key: &str| {
        profile
            .and_then(|p| p.get(key))
            .or_else(|| table.get(key))
            .and_then(|v| v.as_str())
            .map(String::from)
    };
    Configured {
        model: get("model"),
        effort: get("model_reasoning_effort"),
    }
}

/// Marks the model and reasoning level the agent falls back to, so the panel can name them.
fn apply_configured(models: &mut [ModelInfo], configured: &Configured) {
    if let Some(model) = &configured.model {
        if models.iter().any(|m| &m.id == model) {
            for m in models.iter_mut() {
                m.is_default = &m.id == model;
            }
        }
    }
    if let Some(effort) = &configured.effort {
        for m in models.iter_mut() {
            if m.efforts.is_empty() || m.efforts.contains(effort) {
                m.default_effort = Some(effort.clone());
            }
        }
    }
}

/// The answer to Codex app-server's `model/list`.
fn parse_codex_models(response: &Value) -> Vec<ModelInfo> {
    response["result"]["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["hidden"] != true)
        .filter_map(|m| {
            Some(ModelInfo {
                id: m["id"].as_str()?.into(),
                name: m["displayName"].as_str().or(m["id"].as_str())?.into(),
                description: m["description"].as_str().unwrap_or_default().into(),
                efforts: m["supportedReasoningEfforts"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e["reasoningEffort"].as_str().map(String::from))
                    .collect(),
                default_effort: m["defaultReasoningEffort"].as_str().map(String::from),
                is_default: m["isDefault"].as_bool().unwrap_or(false),
            })
        })
        .collect()
}

/// How long a model list may take: the agents start their own services first.
const LIST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Starts the agent's protocol mode, sends it `requests` and returns the first reply for which
/// `wanted` gives something within `timeout`, then stops the process. It asks for a list or a
/// version, so no model runs.
fn ask_agent<T: Send + 'static>(
    program: PathBuf,
    args: &[&str],
    requests: Vec<String>,
    timeout: std::time::Duration,
    wanted: fn(&Value) -> Option<T>,
) -> Result<T, String> {
    let mut command = agent_command(&program, &work_dir()?);
    command.args(args).stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", program.display()))?;
    let pid = child.id();
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if let Some(found) = wanted(&v) {
                    let _ = tx.send(found);
                    return;
                }
            }
        }
    });
    for request in requests {
        let _ = writeln!(stdin, "{request}");
    }
    let found = rx.recv_timeout(timeout);
    crate::engine::kill_tree(pid);
    let _ = child.wait();
    found.map_err(|_| format!("{} did not list its models", program.display()))
}

fn claude_models(program: PathBuf) -> Result<Vec<ModelInfo>, String> {
    let settings = config_dir("CLAUDE_CONFIG_DIR", ".claude")
        .and_then(|dir| std::fs::read_to_string(dir.join("settings.json")).ok());
    let configured = claude_configured(
        std::env::var("CLAUDE_CODE_EFFORT_LEVEL").ok(),
        settings.as_deref(),
    );
    let mut models = ask_agent(
        program,
        &[
            "-p",
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--verbose",
            "--strict-mcp-config",
            "--tools",
            "",
            "--no-session-persistence",
        ],
        vec![json!({"type": "control_request", "request_id": "models", "request": {"subtype": "initialize"}}).to_string()],
        LIST_TIMEOUT,
        |v| {
            (v["type"] == "control_response" && v["response"]["request_id"] == "models")
                .then(|| parse_claude_models(v))
        },
    )?;
    apply_configured(&mut models, &configured);
    Ok(models)
}

fn codex_models(program: PathBuf) -> Result<Vec<ModelInfo>, String> {
    let config = config_dir("CODEX_HOME", ".codex")
        .and_then(|dir| std::fs::read_to_string(dir.join("config.toml")).ok());
    let mut models = ask_agent(
        program,
        &["app-server"],
        vec![
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "binfera", "version": "1"}}}).to_string(),
            json!({"jsonrpc": "2.0", "method": "initialized"}).to_string(),
            json!({"jsonrpc": "2.0", "id": 2, "method": "model/list", "params": {}}).to_string(),
        ],
        LIST_TIMEOUT,
        |v| (v["id"] == 2).then(|| parse_codex_models(v)),
    )?;
    apply_configured(&mut models, &codex_configured(config.as_deref()));
    Ok(models)
}

/// The models the agent says it can run, with the reasoning levels each one supports.
#[tauri::command]
pub async fn agent_models(provider: String) -> Result<Vec<ModelInfo>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let list = match provider.as_str() {
            "claude" => claude_models,
            "codex" => codex_models,
            "vibe" => vibe::models,
            other => return Err(format!("unknown agent: {other}")),
        };
        let program =
            find_provider(&provider).ok_or_else(|| format!("{provider} is not installed"))?;
        list(program)
    })
    .await
    .map_err(|e| e.to_string())?
}

// ----- building the command ------------------------------------------------------------------

/// The same server as `binfera mcp`, spelled for each CLI.
fn claude_args(engine: &str, session: Option<&str>, pick: &Choice) -> Vec<String> {
    let mcp = json!({ "mcpServers": { "binfera": { "command": engine, "args": ["mcp"] } } });
    let mut args: Vec<String> = [
        "-p",
        "--output-format",
        "stream-json",
        "--verbose",
        // Only Binfera's server, not whatever the user has configured elsewhere.
        "--strict-mcp-config",
        "--mcp-config",
    ]
    .map(String::from)
    .to_vec();
    args.push(mcp.to_string());
    // No built-in tools (no shell, no file access): the agent works through Binfera only.
    args.extend(["--tools".into(), String::new()]);
    args.extend(["--allowedTools".into(), "mcp__binfera__*".into()]);
    if let Some(id) = session {
        args.extend(["--resume".into(), id.into()]);
    }
    if let Some(model) = pick.model {
        args.extend(["--model".into(), model.into()]);
    }
    if let Some(effort) = pick.effort {
        args.extend(["--effort".into(), effort.into()]);
    }
    args
}

fn codex_args(engine: &str, session: Option<&str>, pick: &Choice) -> Vec<String> {
    let toml = |s: &str| serde_json::to_string(s).unwrap_or_default();
    let mut args: Vec<String> = vec!["exec".into()];
    if let Some(id) = session {
        args.extend(["resume".into(), id.into()]);
    }
    args.extend(["--json".into(), "--skip-git-repo-check".into()]);
    if let Some(model) = pick.model {
        args.extend(["-m".into(), model.into()]);
    }
    if let Some(effort) = pick.effort {
        args.extend([
            "-c".into(),
            format!("model_reasoning_effort={}", toml(effort)),
        ]);
    }
    for setting in [
        format!("mcp_servers.binfera.command={}", toml(engine)),
        "mcp_servers.binfera.args=[\"mcp\"]".to_string(),
        // `codex exec` cannot ask, and without this every MCP call fails on "approval required".
        "mcp_servers.binfera.default_tools_approval_mode=\"approve\"".to_string(),
        // Whatever the model runs on its own can read, never write.
        "sandbox_mode=\"read-only\"".to_string(),
    ] {
        args.extend(["-c".into(), setting]);
    }
    args
}

// ----- translating the event streams ---------------------------------------------------------

fn clip(mut s: String) -> String {
    if let Some((i, _)) = s.char_indices().nth(OUTPUT_CHARS) {
        s.truncate(i);
        s.push('…');
    }
    s
}

/// A tool result's text: a string, or a list of content blocks.
fn content_text(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn tool(id: &str, name: &str, input: Value, status: &str, output: Option<String>) -> AgentEvent {
    AgentEvent::Tool {
        id: id.into(),
        name: name.into(),
        input,
        status: status.into(),
        output: output.map(clip),
    }
}

/// One line of `claude -p --output-format stream-json`.
fn parse_claude(line: &str) -> Vec<AgentEvent> {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return vec![];
    };
    let mut out = vec![];
    match v["type"].as_str() {
        Some("system") if v["subtype"] == "init" => {
            if let Some(id) = v["session_id"].as_str() {
                out.push(AgentEvent::Session { id: id.into() });
            }
        }
        Some("assistant") => {
            for block in v["message"]["content"].as_array().into_iter().flatten() {
                match block["type"].as_str() {
                    Some("text") => {
                        if let Some(t) = block["text"].as_str().filter(|t| !t.trim().is_empty()) {
                            out.push(AgentEvent::Text { text: t.into() });
                        }
                    }
                    Some("tool_use") => out.push(tool(
                        block["id"].as_str().unwrap_or_default(),
                        block["name"]
                            .as_str()
                            .unwrap_or_default()
                            .trim_start_matches("mcp__binfera__"),
                        block["input"].clone(),
                        "running",
                        None,
                    )),
                    _ => {}
                }
            }
        }
        Some("user") => {
            for block in v["message"]["content"].as_array().into_iter().flatten() {
                if block["type"] == "tool_result" {
                    let failed = block["is_error"].as_bool().unwrap_or(false);
                    // The name and input are already on the panel's row for this id.
                    out.push(tool(
                        block["tool_use_id"].as_str().unwrap_or_default(),
                        "",
                        Value::Null,
                        if failed { "error" } else { "done" },
                        Some(content_text(&block["content"])),
                    ));
                }
            }
        }
        Some("result") => {
            if v["is_error"].as_bool().unwrap_or(false) {
                let message = v["result"].as_str().unwrap_or("the agent failed");
                out.push(AgentEvent::Error {
                    message: message.into(),
                });
            } else {
                let u = &v["usage"];
                let n = |k: &str| u[k].as_u64().unwrap_or(0);
                out.push(AgentEvent::Usage {
                    input: n("input_tokens")
                        + n("cache_creation_input_tokens")
                        + n("cache_read_input_tokens"),
                    output: n("output_tokens"),
                    cost: v["total_cost_usd"].as_f64(),
                });
                out.push(AgentEvent::Done);
            }
        }
        _ => {}
    }
    out
}

/// One line of `codex exec --json`.
fn parse_codex(line: &str) -> Vec<AgentEvent> {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return vec![];
    };
    let item = &v["item"];
    let id = item["id"].as_str().unwrap_or_default();
    match (v["type"].as_str(), item["type"].as_str()) {
        (Some("thread.started"), _) => v["thread_id"]
            .as_str()
            .map(|id| vec![AgentEvent::Session { id: id.into() }])
            .unwrap_or_default(),
        (Some("item.completed"), Some("agent_message")) => item["text"]
            .as_str()
            .filter(|t| !t.trim().is_empty())
            .map(|t| vec![AgentEvent::Text { text: t.into() }])
            .unwrap_or_default(),
        (Some("item.started"), Some("mcp_tool_call")) => vec![tool(
            id,
            item["tool"].as_str().unwrap_or_default(),
            item["arguments"].clone(),
            "running",
            None,
        )],
        (Some("item.completed"), Some("mcp_tool_call")) => {
            let failed = item["status"] == "failed" || !item["error"].is_null();
            let text = if failed {
                item["error"]["message"]
                    .as_str()
                    .unwrap_or("the tool call failed")
                    .to_string()
            } else {
                content_text(&item["result"]["content"])
            };
            vec![tool(
                id,
                item["tool"].as_str().unwrap_or_default(),
                item["arguments"].clone(),
                if failed { "error" } else { "done" },
                Some(text),
            )]
        }
        // The shell is sandboxed read-only, but the analyst should see that the agent used it.
        (Some("item.started"), Some("command_execution")) => {
            vec![tool(
                id,
                "shell",
                json!({ "command": item["command"] }),
                "running",
                None,
            )]
        }
        (Some("item.completed"), Some("command_execution")) => {
            let failed = item["exit_code"].as_i64().is_some_and(|c| c != 0);
            vec![tool(
                id,
                "shell",
                json!({ "command": item["command"] }),
                if failed { "error" } else { "done" },
                item["aggregated_output"].as_str().map(String::from),
            )]
        }
        (Some("turn.completed"), _) => vec![
            AgentEvent::Usage {
                input: v["usage"]["input_tokens"].as_u64().unwrap_or(0),
                output: v["usage"]["output_tokens"].as_u64().unwrap_or(0),
                cost: None,
            },
            AgentEvent::Done,
        ],
        (Some("turn.failed"), _) => vec![AgentEvent::Error {
            message: v["error"]["message"]
                .as_str()
                .unwrap_or("the agent failed")
                .into(),
        }],
        _ => vec![],
    }
}

// ----- running a turn ------------------------------------------------------------------------

fn work_dir() -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join("binfera-agent");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    Ok(dir)
}

fn agent_command(program: &std::path::Path, cwd: &std::path::Path) -> Command {
    let mut command = Command::new(program);
    command
        .current_dir(cwd)
        .env("PATH", child_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut command, 0x0800_0000);
    command
}

/// Starts one turn and returns at once; the run's events arrive on `on_event` and end with
/// `Done` or `Error`.
#[tauri::command]
pub fn agent_run(
    state: State<'_, Agents>,
    request: AgentRequest,
    on_event: Channel<AgentEvent>,
) -> Result<(), String> {
    let parse: Option<fn(&str) -> Vec<AgentEvent>> = match request.provider.as_str() {
        "claude" => Some(parse_claude),
        "codex" => Some(parse_codex),
        "vibe" => None,
        other => return Err(format!("unknown agent: {other}")),
    };
    let provider = request.provider.as_str();
    let program = find_provider(provider).ok_or_else(|| format!("{provider} is not installed"))?;
    let engine = crate::engine::sidecar()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "binfera".into());
    let session = request.session.as_deref();
    let pick = choice(request.model.as_deref(), request.effort.as_deref())?;
    let cwd = work_dir()?;
    let mut command = agent_command(&program, &cwd);
    match provider {
        "claude" => {
            command.args(claude_args(&engine, session, &pick));
        }
        "vibe" => {
            vibe::configure(&mut command);
        }
        _ => {
            command.args(codex_args(&engine, session, &pick));
        }
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", program.display()))?;

    let inner = state.0.clone();
    let id = request.id;
    let pid = child.id();
    inner.running.lock().unwrap().insert(id, pid);
    if inner.cancelled.lock().unwrap().contains(&id) {
        crate::engine::kill_tree(pid);
    }

    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut stderr = child.stderr.take().ok_or("no stderr")?;
    std::thread::spawn(move || {
        let stderr_thread = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            let lines: Vec<&str> = text.lines().collect();
            lines[lines.len().saturating_sub(STDERR_LINES)..].join("\n")
        });

        let mut emit = |event| {
            if on_event.send(event).is_err() {
                // The panel is gone: nothing is listening, so stop the agent.
                crate::engine::kill_tree(pid);
            }
        };
        let mut ended = false;
        if let Some(parse) = parse {
            // Feed the prompt from its own thread so a full pipe can never block the reader below.
            let feeder = std::thread::spawn(move || {
                let _ = stdin.write_all(request.prompt.as_bytes());
            });
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                for event in parse(&line) {
                    ended |= matches!(event, AgentEvent::Done | AgentEvent::Error { .. });
                    emit(event);
                }
            }
            let _ = feeder.join();
        } else {
            // Requests are written from their own thread so a long prompt never blocks the reading.
            let (input, lines) = std::sync::mpsc::channel::<String>();
            let writer = std::thread::spawn(move || {
                for line in lines {
                    if writeln!(stdin, "{line}")
                        .and_then(|_| stdin.flush())
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let result = vibe::run(input, stdout, &cwd, &engine, &request, &mut emit);
            // The app server and the Binfera server it started stay up until told otherwise; the
            // turn is settled here, so end them rather than wait on how they shut down.
            crate::engine::kill_tree(pid);
            let _ = writer.join();
            let cancelled = inner.cancelled.lock().unwrap().contains(&id);
            match result {
                Ok(()) => emit(AgentEvent::Done),
                Err(_) if cancelled => emit(AgentEvent::Done),
                Err(message) => emit(AgentEvent::Error { message }),
            }
            ended = true;
        }
        let status = child.wait();
        let stderr_text = stderr_thread.join().unwrap_or_default();
        let cancelled = inner.cancelled.lock().unwrap().remove(&id);
        inner.running.lock().unwrap().remove(&id);

        if !ended {
            let failed = status.as_ref().map(|s| !s.success()).unwrap_or(true);
            let event = if cancelled || !failed {
                AgentEvent::Done
            } else {
                let tail = stderr_text.trim();
                AgentEvent::Error {
                    message: if tail.is_empty() {
                        "the agent stopped without answering".into()
                    } else {
                        tail.into()
                    },
                }
            };
            let _ = on_event.send(event);
        }
    });
    Ok(())
}

#[tauri::command]
pub fn agent_cancel(state: State<'_, Agents>, id: u64) {
    state.0.cancelled.lock().unwrap().insert(id);
    if let Some(pid) = state.0.running.lock().unwrap().get(&id).copied() {
        crate::engine::kill_tree(pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_session_text_tools_and_result() {
        assert_eq!(
            parse_claude(r#"{"type":"system","subtype":"init","session_id":"s1","tools":[]}"#),
            vec![AgentEvent::Session { id: "s1".into() }]
        );
        let call = r#"{"type":"assistant","message":{"content":[{"type":"thinking","thinking":""},{"type":"text","text":"Opening."},{"type":"tool_use","id":"t1","name":"mcp__binfera__open_binary","input":{"path":"/bin/ls"}}]}}"#;
        assert_eq!(
            parse_claude(call),
            vec![
                AgentEvent::Text {
                    text: "Opening.".into()
                },
                tool(
                    "t1",
                    "open_binary",
                    json!({"path":"/bin/ls"}),
                    "running",
                    None
                ),
            ]
        );
        let result = r#"{"type":"user","message":{"content":[{"tool_use_id":"t1","type":"tool_result","content":"{\"ok\":true}"}]}}"#;
        assert_eq!(
            parse_claude(result),
            vec![tool(
                "t1",
                "",
                Value::Null,
                "done",
                Some("{\"ok\":true}".into())
            )]
        );
        let failed = r#"{"type":"user","message":{"content":[{"tool_use_id":"t2","type":"tool_result","is_error":true,"content":[{"type":"text","text":"bad id"}]}]}}"#;
        assert_eq!(
            parse_claude(failed),
            vec![tool("t2", "", Value::Null, "error", Some("bad id".into()))]
        );
        assert_eq!(
            parse_claude(
                r#"{"type":"result","subtype":"success","is_error":false,"result":"x","total_cost_usd":0.5,"usage":{"input_tokens":2,"cache_creation_input_tokens":10,"cache_read_input_tokens":100,"output_tokens":7}}"#
            ),
            vec![
                AgentEvent::Usage {
                    input: 112,
                    output: 7,
                    cost: Some(0.5)
                },
                AgentEvent::Done
            ]
        );
        assert_eq!(
            parse_claude(r#"{"type":"result","is_error":true,"result":"Not logged in"}"#),
            vec![AgentEvent::Error {
                message: "Not logged in".into()
            }]
        );
        // Hook chatter, rate limits and half-written lines are ignored.
        assert!(parse_claude(r#"{"type":"system","subtype":"hook_started"}"#).is_empty());
        assert!(parse_claude(r#"{"type":"rate_limit_event"}"#).is_empty());
        assert!(parse_claude("not json").is_empty());
    }

    #[test]
    fn codex_session_text_tools_and_turns() {
        assert_eq!(
            parse_codex(r#"{"type":"thread.started","thread_id":"th1"}"#),
            vec![AgentEvent::Session { id: "th1".into() }]
        );
        assert_eq!(
            parse_codex(
                r#"{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"Hi"}}"#
            ),
            vec![AgentEvent::Text { text: "Hi".into() }]
        );
        assert_eq!(
            parse_codex(
                r#"{"type":"item.started","item":{"id":"item_1","type":"mcp_tool_call","server":"binfera","tool":"get_project","arguments":{"project_id":"p"},"result":null,"error":null,"status":"in_progress"}}"#
            ),
            vec![tool(
                "item_1",
                "get_project",
                json!({"project_id":"p"}),
                "running",
                None
            )]
        );
        assert_eq!(
            parse_codex(
                r#"{"type":"item.completed","item":{"id":"item_1","type":"mcp_tool_call","server":"binfera","tool":"get_project","arguments":{},"result":{"content":[{"type":"text","text":"ready"}]},"error":null,"status":"completed"}}"#
            ),
            vec![tool(
                "item_1",
                "get_project",
                json!({}),
                "done",
                Some("ready".into())
            )]
        );
        assert_eq!(
            parse_codex(
                r#"{"type":"item.completed","item":{"id":"item_2","type":"mcp_tool_call","tool":"x","arguments":{},"result":null,"error":{"message":"denied"},"status":"failed"}}"#
            ),
            vec![tool(
                "item_2",
                "x",
                json!({}),
                "error",
                Some("denied".into())
            )]
        );
        assert_eq!(
            parse_codex(
                r#"{"type":"turn.completed","usage":{"input_tokens":50,"output_tokens":4}}"#
            ),
            vec![
                AgentEvent::Usage {
                    input: 50,
                    output: 4,
                    cost: None
                },
                AgentEvent::Done
            ]
        );
        assert_eq!(
            parse_codex(r#"{"type":"turn.failed","error":{"message":"quota"}}"#),
            vec![AgentEvent::Error {
                message: "quota".into()
            }]
        );
        // Reconnect notices are not failures.
        assert!(parse_codex(r#"{"type":"error","message":"Reconnecting 1/5"}"#).is_empty());
    }

    #[test]
    fn models_are_read_from_each_agents_own_list() {
        let claude = json!({"type": "control_response", "response": {"subtype": "success", "request_id": "models", "response": {"models": [
            {"value": "default", "displayName": "Default (recommended)", "description": "x"},
            {"value": "opus", "displayName": "Opus 5.5", "description": "For complex work", "supportedEffortLevels": ["low", "high", "max"]},
            {"value": "claude-haiku-4-5", "displayName": "Haiku 4.5", "description": "Fast"}
        ]}}});
        let models = parse_claude_models(&claude);
        assert_eq!(
            models.len(),
            2,
            "the settings-driven default row is not a model"
        );
        assert_eq!(
            (models[0].id.as_str(), models[0].name.as_str()),
            ("opus", "Opus 5.5")
        );
        assert_eq!(models[0].efforts, ["low", "high", "max"]);
        assert!(models[1].efforts.is_empty());

        let codex = json!({"id": 2, "result": {"data": [
            {"id": "gpt-6.1-sol", "displayName": "GPT-6.1-Sol", "description": "d", "hidden": false, "isDefault": true, "defaultReasoningEffort": "low",
             "supportedReasoningEfforts": [{"reasoningEffort": "low"}, {"reasoningEffort": "ultra"}]},
            {"id": "gpt-reserve", "displayName": "Reserve", "hidden": true, "supportedReasoningEfforts": []}
        ], "nextCursor": null}});
        let models = parse_codex_models(&codex);
        assert_eq!(models.len(), 1, "hidden models are not offered");
        assert!(models[0].is_default);
        assert_eq!(models[0].default_effort.as_deref(), Some("low"));
        assert_eq!(models[0].efforts, ["low", "ultra"]);
    }

    #[test]
    fn defaults_come_from_each_agents_own_configuration() {
        let claude = json!({"response": {"response": {"models": [
            {"value": "default", "resolvedModel": "claude-opus-5-5"},
            {"value": "opus", "resolvedModel": "claude-opus-5-5", "supportedEffortLevels": ["low", "medium", "high"]},
            {"value": "haiku", "resolvedModel": "claude-haiku-5-5", "supportedEffortLevels": ["low"]}
        ]}}});
        let mut models = parse_claude_models(&claude);
        assert!(models[0].is_default && !models[1].is_default);
        let configured = claude_configured(None, Some(r#"{"effortLevel": "medium"}"#));
        assert_eq!(configured.effort.as_deref(), Some("medium"));
        apply_configured(&mut models, &configured);
        assert_eq!(models[0].default_effort.as_deref(), Some("medium"));
        assert_eq!(models[1].default_effort, None, "haiku has no medium level");
        // The environment wins over the settings file.
        assert_eq!(
            claude_configured(Some("HIGH".into()), Some(r#"{"effortLevel": "low"}"#)).effort,
            Some("high".into())
        );

        let codex = json!({"result": {"data": [
            {"id": "a", "isDefault": true, "defaultReasoningEffort": "low", "supportedReasoningEfforts": [{"reasoningEffort": "low"}, {"reasoningEffort": "high"}]},
            {"id": "b", "isDefault": false, "supportedReasoningEfforts": [{"reasoningEffort": "high"}]}
        ]}});
        let mut models = parse_codex_models(&codex);
        let configured = codex_configured(Some(
            "model = \"b\"\nmodel_reasoning_effort = \"high\"\n[profiles.x]\nmodel = \"a\"\n",
        ));
        apply_configured(&mut models, &configured);
        assert!(!models[0].is_default && models[1].is_default);
        assert_eq!(models[0].default_effort.as_deref(), Some("high"));
        assert_eq!(
            codex_configured(Some(
                "model = \"a\"\nprofile = \"x\"\n[profiles.x]\nmodel = \"b\"\n"
            ))
            .model,
            Some("b".into())
        );
        // A model the agent does not list leaves its own default in place.
        let mut models = parse_codex_models(&codex);
        apply_configured(&mut models, &codex_configured(Some("model = \"gone\"")));
        assert!(models[0].is_default);
    }

    /// Needs the real CLIs, signed in: `cargo test -- --ignored real_model_lists`.
    #[test]
    #[ignore]
    fn real_model_lists() {
        for (name, list) in [
            ("claude", claude_models as fn(PathBuf) -> _),
            ("codex", codex_models),
        ] {
            let Some(program) = find(name) else { continue };
            let started = std::time::Instant::now();
            let models = list(program).unwrap();
            println!("{name}: {} models in {:?}", models.len(), started.elapsed());
            for m in models.iter().take(4) {
                println!(
                    "  {} ({}) {:?} default={}",
                    m.name, m.id, m.efforts, m.is_default
                );
            }
            assert!(!models.is_empty());
        }
    }

    #[test]
    fn arguments_attach_only_binfera_and_resume() {
        let none = Choice::default();
        let claude = claude_args("/App/binfera", Some("s1"), &none);
        assert!(claude.windows(2).any(|w| w == ["--tools", ""]));
        assert!(claude.contains(&"--strict-mcp-config".to_string()));
        assert!(claude.windows(2).any(|w| w == ["--resume", "s1"]));
        let config = claude.iter().find(|a| a.starts_with('{')).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(config).unwrap()["mcpServers"]["binfera"]["command"],
            "/App/binfera"
        );
        assert!(!claude_args("b", None, &none).contains(&"--resume".to_string()));
        assert!(
            !claude.contains(&"--model".to_string()) && !claude.contains(&"--effort".to_string())
        );

        let codex = codex_args("/App/my binfera", None, &none);
        assert_eq!(&codex[..3], ["exec", "--json", "--skip-git-repo-check"]);
        assert!(codex.contains(&"mcp_servers.binfera.command=\"/App/my binfera\"".to_string()));
        assert!(codex.contains(&"sandbox_mode=\"read-only\"".to_string()));
        assert_eq!(
            &codex_args("b", Some("th1"), &none)[..3],
            ["exec", "resume", "th1"]
        );
    }

    #[test]
    fn model_and_effort_are_passed_only_when_chosen_and_valid() {
        let pick = choice(Some(" opus[1m] "), Some("high")).unwrap();
        assert_eq!(
            pick,
            Choice {
                model: Some("opus[1m]"),
                effort: Some("high")
            }
        );
        let claude = claude_args("b", None, &pick);
        assert!(claude.windows(2).any(|w| w == ["--model", "opus[1m]"]));
        assert!(claude.windows(2).any(|w| w == ["--effort", "high"]));
        let codex = codex_args("b", Some("th1"), &pick);
        assert!(codex.windows(2).any(|w| w == ["-m", "opus[1m]"]));
        assert!(codex.contains(&"model_reasoning_effort=\"high\"".to_string()));
        // Blank means "the agent's own default".
        assert_eq!(choice(Some("  "), Some("")).unwrap(), Choice::default());
        // Nothing that could be read as another option or a shell/TOML fragment.
        assert!(choice(Some("--dangerously-skip-permissions"), None).is_err());
        assert!(choice(Some("m\" -c x=1"), None).is_err());
        assert!(choice(None, Some("high; rm")).is_err());
        assert!(choice(None, Some("ultra")).is_ok());
    }
}
