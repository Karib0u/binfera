//! Adapter for the Vibe app server shipped with the CLI and the macOS app.

use super::{
    ask_agent, choice, content_text, find, tool, AgentEvent, AgentRequest, ModelInfo, LIST_TIMEOUT,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::Sender;
use std::time::Duration;

/// The app server answers `initialize` in about a second; detection waits no longer than this.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn find_server() -> Option<PathBuf> {
    find("vibe-app-server").or_else(|| {
        #[cfg(target_os = "macos")]
        {
            let executable = "Vibe.app/Contents/Resources/bin/vibe-app-server/vibe-app-server";
            let system = Path::new("/Applications").join(executable);
            if system.is_file() {
                return Some(system);
            }
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join("Applications").join(executable))
                .filter(|path| path.is_file())
        }
        #[cfg(not(target_os = "macos"))]
        None
    })
}

pub(super) fn configure(command: &mut Command) {
    command
        .env("VIBE_ENABLE_CONNECTORS", "false")
        .env("VIBE_ENABLE_SUBAGENTS", "false")
        .env("VIBE_ENABLE_BACKGROUND_PROCESSES", "false");
}

fn request(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn initialize() -> Value {
    request(
        1,
        "initialize",
        json!({
            "clientInfo": {"name": "binfera", "version": env!("CARGO_PKG_VERSION"), "entrypoint": "programmatic"}
        }),
    )
}

fn initialized() -> Value {
    json!({"jsonrpc": "2.0", "method": "initialized", "params": {}})
}

pub(super) fn version(program: PathBuf) -> Option<String> {
    ask_agent(
        program,
        &[],
        vec![initialize().to_string()],
        VERSION_TIMEOUT,
        |message| {
            message["result"]["serverInfo"]["version"]
                .as_str()
                .map(String::from)
        },
    )
    .ok()
}

pub(super) fn models(program: PathBuf) -> Result<Vec<ModelInfo>, String> {
    ask_agent(
        program,
        &[],
        vec![
            initialize().to_string(),
            initialized().to_string(),
            request(2, "config/read", json!({})).to_string(),
        ],
        LIST_TIMEOUT,
        |message| {
            (message["id"] == 2).then(|| {
                let config = &rpc_result(message)?["config"];
                let active = &config["activeModel"]["alias"];
                Ok(config["models"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|model| {
                        let alias = model["alias"].as_str()?;
                        if !model["requires"].is_null() {
                            return None;
                        }
                        Some(ModelInfo {
                            id: alias.into(),
                            name: model["displayName"]
                                .as_str()
                                .filter(|s| !s.is_empty())
                                .unwrap_or(alias)
                                .into(),
                            description: String::new(),
                            efforts: model["thinkingLevels"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(|level| level.as_str().map(String::from))
                                .collect(),
                            default_effort: model["thinking"].as_str().map(String::from),
                            is_default: active == alias,
                        })
                    })
                    .collect())
            })
        },
    )?
}

fn rpc_result(message: &Value) -> Result<&Value, String> {
    if message["error"]["code"] == "unauthorized" {
        return Err("Install the Mistral Vibe CLI if needed, then sign in with `vibe --setup`. You can also provide the API key in the environment that launches Binfera.".into());
    }
    if let Some(error) = message["error"]["message"].as_str() {
        return Err(format!("Mistral Vibe: {error}"));
    }
    message
        .get("result")
        .ok_or_else(|| "Mistral Vibe did not return a result".into())
}

/// Requests go to a writer thread that owns the server's stdin, so a long prompt never blocks
/// the reading below while the server's own output fills its pipe.
struct Connection<R> {
    lines: std::io::Lines<BufReader<R>>,
    input: Sender<String>,
}

impl<R: Read> Connection<R> {
    fn send(&mut self, message: Value) -> Result<(), String> {
        self.input
            .send(message.to_string())
            .map_err(|_| "could not write to Mistral Vibe".into())
    }

    fn read(&mut self) -> Result<Value, String> {
        for line in self.lines.by_ref() {
            let line = line.map_err(|e| format!("could not read from Mistral Vibe: {e}"))?;
            if let Ok(message) = serde_json::from_str(&line) {
                return Ok(message);
            }
        }
        Err("Mistral Vibe closed the connection".into())
    }

    fn reply(&mut self, id: u64) -> Result<Value, String> {
        loop {
            let message = self.read()?;
            if message["id"] == id && message.get("method").is_none() {
                rpc_result(&message)?;
                return Ok(message);
            }
        }
    }

    fn call(&mut self, id: u64, method: &str, params: Value) -> Result<Value, String> {
        self.send(request(id, method, params))?;
        self.reply(id)
    }
}

/// Runs one turn: `input` takes each line for the server's stdin, `stdout` is the server's output.
pub(super) fn run(
    input: Sender<String>,
    stdout: impl Read,
    cwd: &Path,
    engine: &str,
    turn: &AgentRequest,
    emit: &mut impl FnMut(AgentEvent),
) -> Result<(), String> {
    let mut conn = Connection {
        lines: BufReader::new(stdout).lines(),
        input,
    };
    conn.send(initialize())?;
    conn.reply(1)?;
    conn.send(initialized())?;

    let pick = choice(turn.model.as_deref(), turn.effort.as_deref())?;
    let config = json!({
        "cwd": cwd,
        "headless": true,
        "agent": "accept-edits",
        "autoApprove": true,
        "enabledTools": ["binfera_*"],
        "mcpServers": [{"name": "binfera", "transport": "stdio", "command": engine, "args": ["mcp"]}]
    });
    let opened = if let Some(id) = &turn.session {
        conn.call(
            2,
            "session/resume",
            json!({"sessionId": id, "agentConfig": config, "historyLimit": 1}),
        )?
    } else {
        conn.call(2, "session/start", json!({
            "agentConfig": config, "model": pick.model, "reasoningEffort": pick.effort, "sessionOnly": true
        }))?
    };
    let session = &opened["result"]["state"]["session"];
    let id = session["id"]
        .as_str()
        .ok_or("Mistral Vibe did not return a session id")?;
    if turn.session.is_some() && (pick.model.is_some() || pick.effort.is_some()) {
        conn.call(3, "config/model/write", json!({
            "sessionId": id, "modelAlias": pick.model, "reasoningEffort": pick.effort, "sessionOnly": true
        }))?;
    }
    conn.call(
        4,
        "session/ready/wait",
        json!({"sessionId": id, "integrations": true}),
    )?;
    let runtime = conn.call(5, "runtime/read", json!({"sessionId": id}))?;
    check_tools(&runtime["result"]["runtime"])?;
    emit(AgentEvent::Session { id: id.into() });

    // Notifications can arrive before the reply, so start reading both together.
    conn.send(request(
        6,
        "turn/start",
        json!({
            "sessionId": id, "message": [{"type": "text", "text": turn.prompt}]
        }),
    ))?;
    let mut entries = HashMap::new();
    let mut stats = Value::Null;
    loop {
        let message = conn.read()?;
        if message["id"] == 6 && message.get("method").is_none() {
            rpc_result(&message)?;
        }
        let params = &message["params"];
        if params["sessionId"] != id {
            continue;
        }
        match message["method"].as_str() {
            Some("history/entryAdded" | "history/entryUpdated") => {
                if let Some(event) = history_event(&message, &mut entries) {
                    emit(event);
                }
            }
            Some("session/statsUpdated") => stats = params["stats"].clone(),
            Some("turn/completed") => {
                let turn = &params["turn"];
                if turn["status"] != "completed" {
                    return Err(turn["error"]["message"]
                        .as_str()
                        .unwrap_or("Mistral Vibe stopped before finishing the turn")
                        .into());
                }
                if !stats.is_null() {
                    let previous = &session["tokenUsage"];
                    let input = stats["sessionPromptTokens"]
                        .as_u64()
                        .unwrap_or(0)
                        .saturating_sub(previous["inputTokens"].as_u64().unwrap_or(0));
                    let output = stats["sessionCompletionTokens"]
                        .as_u64()
                        .unwrap_or(0)
                        .saturating_sub(previous["outputTokens"].as_u64().unwrap_or(0));
                    emit(AgentEvent::Usage {
                        input,
                        output,
                        cost: None,
                    });
                }
                // The answer is complete; the stop only lets Vibe close cleanly, and the
                // process is ended either way.
                let _ = conn.call(7, "session/stop", json!({"sessionId": id}));
                return Ok(());
            }
            _ => {}
        }
    }
}

fn check_tools(runtime: &Value) -> Result<(), String> {
    let tools = runtime["tools"]
        .as_array()
        .ok_or("Mistral Vibe did not list its active tools")?;
    if tools.iter().any(|tool| {
        !tool["name"]
            .as_str()
            .is_some_and(|name| name.starts_with("binfera_"))
    }) {
        return Err("Mistral Vibe did not apply Binfera's tool filter".into());
    }
    let mut binfera_available = false;
    for source in runtime["mcp"]["sources"].as_array().into_iter().flatten() {
        let enabled = source["tools"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|tool| tool["enabled"] == true);
        if enabled && source["name"] != "binfera" {
            return Err("Mistral Vibe enabled MCP tools outside Binfera".into());
        }
        binfera_available |= enabled;
    }
    if !binfera_available {
        return Err("Mistral Vibe could not load Binfera's MCP tools".into());
    }
    Ok(())
}

fn visible(entry: &Value) -> bool {
    (entry["type"] == "message" && entry["role"] == "assistant")
        || (entry["type"] == "effect" && tool_name(entry).is_some())
}

fn tool_name(entry: &Value) -> Option<&str> {
    let name = entry["detail"]["toolName"].as_str()?;
    name.strip_prefix("mcp_binfera.")
        .or_else(|| name.strip_prefix("binfera_"))
}

/// An entry still being generated, and whether the panel has been shown it yet.
struct Pending {
    entry: Value,
    shown: bool,
}

/// Follows the history: Vibe sends each entry whole once, then as patches against what it sent.
/// Every unfinished entry is kept, since one can become visible later (an effect learns its tool
/// name in a patch). An update that cannot be applied drops that entry rather than the turn.
fn history_event(message: &Value, entries: &mut HashMap<String, Pending>) -> Option<AgentEvent> {
    let params = &message["params"];
    if message["method"] == "history/entryAdded" {
        let entry = &params["entry"];
        let id = entry["id"].as_str()?;
        let shown = visible(entry);
        let event = shown.then(|| entry_event(id, entry)).flatten();
        if entry["generationStatus"] != "completed" {
            entries.insert(
                id.into(),
                Pending {
                    entry: entry.clone(),
                    shown: event.is_some(),
                },
            );
        }
        return event;
    }

    let id = params["entryId"].as_str()?;
    let pending = entries.get_mut(id)?;
    let ops = params["patch"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    if apply_patch(&mut pending.entry, ops).is_err() {
        entries.remove(id);
        return None;
    }
    if pending.entry["generationStatus"] == "completed" {
        let pending = entries.remove(id)?;
        return visible(&pending.entry)
            .then(|| entry_event(id, &pending.entry))
            .flatten();
    }
    // A tool call that has just become visible is shown as running.
    if !pending.shown && visible(&pending.entry) {
        let event = entry_event(id, &pending.entry);
        pending.shown = event.is_some();
        return event;
    }
    None
}

/// JSON Patch, plus Vibe's `append`, which extends a string (or an array) in place.
fn apply_patch(entry: &mut Value, ops: &[Value]) -> Result<(), ()> {
    for op in ops {
        if op["op"] == "append" {
            let path = op["path"].as_str().ok_or(())?;
            match (entry.pointer_mut(path), &op["value"]) {
                (Some(Value::String(text)), Value::String(more)) => text.push_str(more),
                (Some(Value::Array(items)), value) => items.push(value.clone()),
                // Nothing there yet: the appended value is the whole of it.
                (None, value) => {
                    let add = json!({"op": "add", "path": path, "value": value});
                    let add = serde_json::from_value(add).map_err(|_| ())?;
                    json_patch::patch(entry, &[add]).map_err(|_| ())?;
                }
                _ => return Err(()),
            }
        } else {
            let op = serde_json::from_value(op.clone()).map_err(|_| ())?;
            json_patch::patch(entry, &[op]).map_err(|_| ())?;
        }
    }
    Ok(())
}

fn entry_event(id: &str, entry: &Value) -> Option<AgentEvent> {
    let completed = entry["generationStatus"] == "completed";
    if entry["type"] == "message" {
        if !completed || entry["outcome"]["type"] == "discarded" {
            return None;
        }
        let text = content_text(&entry["content"]);
        return (!text.trim().is_empty()).then_some(AgentEvent::Text { text });
    }
    let name = tool_name(entry)?;
    let input = entry["detail"]["input"].clone();
    let state = &entry["state"];
    let outcome = if !completed {
        return Some(tool(id, name, input, "running", None));
    } else if state["status"] == "completed" && state["display"]["success"] != false {
        "done"
    } else {
        "error"
    };
    let output = state["error"]["message"]
        .as_str()
        .or_else(|| state["reason"].as_str())
        .or_else(|| state["outputText"].as_str().filter(|text| !text.is_empty()))
        .map(String::from)
        .or_else(|| (!state["output"].is_null()).then(|| state["output"].to_string()));
    Some(tool(id, name, input, outcome, output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_a_vibe_turn_and_resumes_with_session_scope() {
        let request = AgentRequest {
            id: 1,
            provider: "vibe".into(),
            prompt: "Look at this file".into(),
            session: Some("s1".into()),
            model: Some("mistral-large-4-0".into()),
            effort: Some("high".into()),
        };
        let replies = concat!(
            r#"{"id":1,"result":{}}"#,
            "\n",
            r#"{"id":2,"result":{"state":{"session":{"id":"s1","tokenUsage":{"inputTokens":11,"outputTokens":5}}}}}"#,
            "\n",
            r#"{"id":3,"result":{}}"#,
            "\n",
            r#"{"id":4,"result":{"ready":true}}"#,
            "\n",
            r#"{"id":5,"result":{"runtime":{"tools":[],"mcp":{"sources":[{"name":"binfera","tools":[{"name":"get_project","enabled":true}]}]}}}}"#,
            "\n",
            r#"{"method":"history/entryAdded","params":{"sessionId":"s1","entry":{"id":"t1","type":"effect","generationStatus":"in_progress","detail":{"toolName":"mcp_binfera.get_project","input":{"project_id":"p1"}},"state":{"status":"running","outputText":""}}}}"#,
            "\n",
            r#"{"id":6,"result":{"turn":{"id":"a1"}}}"#,
            "\n",
            r#"{"method":"history/entryUpdated","params":{"sessionId":"s1","entryId":"t1","patch":[{"op":"add","path":"/state/display","value":{"success":true}},{"op":"append","path":"/state/outputText","value":"Ready"},{"op":"replace","path":"/state/status","value":"completed"},{"op":"replace","path":"/generationStatus","value":"completed"}]}}"#,
            "\n",
            r#"{"method":"history/entryAdded","params":{"sessionId":"s1","entry":{"id":"m1","type":"message","role":"assistant","generationStatus":"completed","content":[{"type":"text","text":"I found it."}]}}}"#,
            "\n",
            r#"{"method":"session/statsUpdated","params":{"sessionId":"s1","stats":{"sessionPromptTokens":23,"sessionCompletionTokens":8}}}"#,
            "\n",
            r#"{"method":"turn/completed","params":{"sessionId":"s1","turn":{"id":"a1","status":"completed"}}}"#,
            "\n",
            r#"{"id":7,"result":{}}"#,
            "\n",
        );
        let (input, sent) = std::sync::mpsc::channel();
        let mut events = Vec::new();
        run(
            input,
            replies.as_bytes(),
            Path::new("/tmp/binfera-agent"),
            "/App/my binfera",
            &request,
            &mut |event| events.push(event),
        )
        .unwrap();
        assert_eq!(
            events,
            vec![
                AgentEvent::Session { id: "s1".into() },
                tool(
                    "t1",
                    "get_project",
                    json!({"project_id": "p1"}),
                    "running",
                    None
                ),
                tool(
                    "t1",
                    "get_project",
                    json!({"project_id": "p1"}),
                    "done",
                    Some("Ready".into())
                ),
                AgentEvent::Text {
                    text: "I found it.".into()
                },
                AgentEvent::Usage {
                    input: 12,
                    output: 3,
                    cost: None
                },
            ]
        );
        let sent: Vec<Value> = sent
            .try_iter()
            .map(|line| serde_json::from_str(&line).unwrap())
            .collect();
        assert_eq!(sent[2]["method"], "session/resume");
        let config = &sent[2]["params"]["agentConfig"];
        assert_eq!(config["enabledTools"], json!(["binfera_*"]));
        assert_eq!(config["mcpServers"][0]["command"], "/App/my binfera");
        assert_eq!(sent[3]["params"]["sessionOnly"], true);
        assert_eq!(sent[6]["params"]["message"][0]["text"], request.prompt);
    }

    fn added(entry: Value) -> Value {
        json!({"method": "history/entryAdded", "params": {"sessionId": "s1", "entry": entry}})
    }

    fn updated(id: &str, patch: Value) -> Value {
        json!({"method": "history/entryUpdated", "params": {"sessionId": "s1", "entryId": id, "patch": patch}})
    }

    #[test]
    fn a_tool_call_named_after_it_starts_is_still_shown() {
        let mut entries = HashMap::new();
        let effect = json!({"id": "e1", "type": "effect", "generationStatus": "in_progress", "detail": {}, "state": {"status": "running"}});
        assert_eq!(history_event(&added(effect), &mut entries), None);
        let named = updated(
            "e1",
            json!([{"op": "add", "path": "/detail/toolName", "value": "binfera_list_functions"}]),
        );
        assert_eq!(
            history_event(&named, &mut entries),
            Some(tool("e1", "list_functions", Value::Null, "running", None))
        );
        let done = updated(
            "e1",
            json!([
                {"op": "append", "path": "/state/outputText", "value": "12 functions"},
                {"op": "replace", "path": "/state/status", "value": "completed"},
                {"op": "replace", "path": "/generationStatus", "value": "completed"}
            ]),
        );
        assert_eq!(
            history_event(&done, &mut entries),
            Some(tool(
                "e1",
                "list_functions",
                Value::Null,
                "done",
                Some("12 functions".into())
            ))
        );
        assert!(entries.is_empty());
    }

    #[test]
    fn a_patch_that_does_not_apply_drops_only_that_entry() {
        let mut entries = HashMap::new();
        let message = json!({"id": "m1", "type": "message", "role": "assistant", "generationStatus": "in_progress", "content": [{"type": "text", "text": "Hel"}]});
        history_event(&added(message), &mut entries);
        let streamed = updated(
            "m1",
            json!([{"op": "append", "path": "/content/0/text", "value": "lo"}]),
        );
        assert_eq!(history_event(&streamed, &mut entries), None);
        assert_eq!(entries["m1"].entry["content"][0]["text"], "Hello");
        let bad = updated(
            "m1",
            json!([{"op": "replace", "path": "/missing/field", "value": 1}]),
        );
        assert_eq!(history_event(&bad, &mut entries), None);
        assert!(entries.is_empty());
    }

    #[test]
    fn a_failed_stop_after_a_finished_turn_is_not_an_error() {
        let request = AgentRequest {
            id: 1,
            provider: "vibe".into(),
            prompt: "Hi".into(),
            session: None,
            model: None,
            effort: None,
        };
        let replies = [
            json!({"id": 1, "result": {}}),
            json!({"id": 2, "result": {"state": {"session": {"id": "s1"}}}}),
            json!({"id": 4, "result": {}}),
            json!({"id": 5, "result": {"runtime": {"tools": [], "mcp": {"sources": [{"name": "binfera", "tools": [{"enabled": true}]}]}}}}),
            json!({"id": 6, "result": {}}),
            json!({"method": "turn/completed", "params": {"sessionId": "s1", "turn": {"status": "completed"}}}),
        ]
        .map(|m| m.to_string() + "\n")
        .concat();
        let (input, _sent) = std::sync::mpsc::channel();
        let mut events = Vec::new();
        run(
            input,
            replies.as_bytes(),
            Path::new("/tmp"),
            "binfera",
            &request,
            &mut |event| events.push(event),
        )
        .unwrap();
        assert_eq!(events, vec![AgentEvent::Session { id: "s1".into() }]);
    }
}
