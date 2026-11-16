//! Minimal MCP (JSON-RPC 2.0, newline-delimited) over stdio: initialize, ping and tools.
//! Logs go to stderr; stdout carries only protocol messages.
use serde_json::{json, Value};
use std::io::{BufRead, Write};

pub const PROTOCOL_VERSION: &str = "2025-06-18";

pub trait Handler {
    fn tools(&self) -> Value;
    /// `Ok` is the tool's JSON result; `Err` is reported as an `isError` tool result.
    fn call_tool(&mut self, name: &str, args: &Value) -> Result<Value, String>;
    fn instructions(&self) -> &str;
}

fn reply(id: &Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}
fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

/// Handles one decoded message; returns the response to send, if any (notifications get none).
pub fn handle(handler: &mut dyn Handler, message: &Value) -> Option<Value> {
    let id = message.get("id")?.clone();
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    Some(match method {
        "initialize" => {
            let requested = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(PROTOCOL_VERSION);
            reply(
                &id,
                json!({
                    "protocolVersion": requested,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "binfera", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": handler.instructions(),
                }),
            )
        }
        "ping" => reply(&id, json!({})),
        "tools/list" => reply(&id, json!({"tools": handler.tools()})),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let result = match handler.call_tool(name, &args) {
                Ok(value) => json!({
                    "content": [{"type":"text","text": serde_json::to_string_pretty(&value).unwrap_or_default()}],
                    "structuredContent": value,
                    "isError": false,
                }),
                Err(message) => json!({"content":[{"type":"text","text":message}],"isError":true}),
            };
            reply(&id, result)
        }
        _ => error(&id, -32601, "method not found"),
    })
}

pub fn serve(
    handler: &mut dyn Handler,
    input: impl BufRead,
    mut output: impl Write,
) -> std::io::Result<()> {
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(message) => handle(handler, &message),
            Err(e) => Some(error(&Value::Null, -32700, &format!("parse error: {e}"))),
        };
        if let Some(response) = response {
            writeln!(output, "{response}")?;
            output.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Stub;
    impl Handler for Stub {
        fn tools(&self) -> Value {
            json!([{"name":"echo"}])
        }
        fn call_tool(&mut self, name: &str, args: &Value) -> Result<Value, String> {
            if name == "echo" {
                Ok(args.clone())
            } else {
                Err("unknown".into())
            }
        }
        fn instructions(&self) -> &str {
            "hi"
        }
    }

    #[test]
    fn protocol_basics() {
        let mut h = Stub;
        let init = handle(&mut h, &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}})).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert!(handle(
            &mut h,
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .is_none());
        let call = handle(&mut h, &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"a":1}}})).unwrap();
        assert_eq!(call["result"]["structuredContent"]["a"], 1);
        assert_eq!(call["result"]["isError"], false);
        let bad = handle(
            &mut h,
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope"}}),
        )
        .unwrap();
        assert_eq!(bad["result"]["isError"], true);
        assert_eq!(
            handle(&mut h, &json!({"jsonrpc":"2.0","id":4,"method":"zzz"})).unwrap()["error"]
                ["code"],
            -32601
        );
    }

    #[test]
    fn serve_survives_garbage_lines() {
        let mut out = Vec::new();
        serve(
            &mut Stub,
            "not json\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n".as_bytes(),
            &mut out,
        )
        .unwrap();
        let lines: Vec<&str> = std::str::from_utf8(&out).unwrap().lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("-32700"));
    }
}
