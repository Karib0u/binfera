//! Binfera desktop: the web UI in a native window, with the engine running natively.
//!
//! The UI is the same code as the browser build (`web/src`). Instead of compiling the engine to
//! WebAssembly, the desktop build bundles the native `binfera` binary as a sidecar and the
//! frontend calls it through the commands in [`engine`]. That removes the browser's limits (4 GB
//! of memory, no threads, a downloaded engine) and lets `--jobs` use every core.

mod agent;
mod cache;
mod drop;
mod engine;
mod folder;
mod project;

pub fn run() {
    std::thread::spawn(|| {
        let _ = binfera_project::prune_cache(
            &binfera_project::data_dir().join("cache"),
            binfera_project::cache_max_bytes(),
        );
    });
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(engine::Engine::new())
        .manage(project::Projects::default())
        .manage(agent::Agents::default())
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::DragDrop(drag) = event {
                drop::handle(window, drag);
            }
        })
        .invoke_handler(tauri::generate_handler![
            engine::stage_sample,
            engine::release_sample,
            engine::run_engine,
            engine::cancel_engine,
            agent::agent_detect,
            agent::agent_models,
            agent::agent_run,
            agent::agent_cancel,
            project::project_load,
            project::project_revision,
            project::project_path,
            project::project_apply,
            project::project_remove,
            project::project_undo,
            project::project_activity,
            project::project_reports,
            project::project_report,
            project::mcp_setup,
            project::project_recent,
            project::project_forget,
            project::file_pick,
            project::file_read,
            project::file_reveal,
            folder::folder_pick,
            folder::folder_scan,
            folder::folder_open,
        ])
        .build(tauri::generate_context!())
        .expect("error while building the Binfera window")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                tauri::Manager::state::<engine::Engine>(app).shutdown();
                tauri::Manager::state::<agent::Agents>(app).shutdown();
            }
        });
}
