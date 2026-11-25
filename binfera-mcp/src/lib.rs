//! Local Model Context Protocol server for Binfera, spoken over stdio.
//!
//! The server owns no analysis logic: it asks the `binfera` executable (in isolated child
//! processes) for recovery, decompilation and code origin, caches the results on disk, and stores annotations
//! and reports in a `binfera-project` database that the desktop app shares.
#![forbid(unsafe_code)]

mod code_origin;
mod engine;
mod rpc;
mod tools;

pub use engine::Engine;
use std::path::PathBuf;

/// An MCP server instance: one project database plus the engine used for analysis.
pub struct Server(tools::Tools);

impl Server {
    /// `exe` is the `binfera` executable used for analysis, normally the running one.
    pub fn new(
        exe: PathBuf,
        data_dir: &std::path::Path,
        engine_version: &str,
    ) -> std::io::Result<Server> {
        let store = binfera_project::Store::open(&data_dir.join("projects.sqlite3"))
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let engine = Engine::new(exe, data_dir.join("cache"), engine_version.to_string());
        Ok(Server(tools::Tools::new(
            store,
            engine,
            engine_version.to_string(),
        )))
    }

    /// Handles one JSON-RPC message; notifications produce no response.
    pub fn handle(&mut self, message: &serde_json::Value) -> Option<serde_json::Value> {
        rpc::handle(&mut self.0, message)
    }
}

/// Runs the server on stdin/stdout until the client closes the stream. Logs go to stderr only.
pub fn serve_stdio(exe: PathBuf, engine_version: &str) -> std::io::Result<()> {
    let mut server = Server::new(exe, &binfera_project::data_dir(), engine_version)?;
    let stdin = std::io::stdin();
    rpc::serve(&mut server.0, stdin.lock(), std::io::stdout().lock())
}
