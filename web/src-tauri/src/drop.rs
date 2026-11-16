//! Files dropped on the window.
//!
//! With the webview's own drag and drop a dropped file reaches the page as bytes only, so the
//! history could not remember where it came from. The window therefore handles drops natively:
//! the real paths are registered here (hash, history entry, permission to read them) and the page
//! is told where the pointer is and which files arrived. The page is never the source of a path.
use crate::project::Projects;
use serde::Serialize;
use tauri::{DragDropEvent, Emitter, Manager, Window};

#[derive(Serialize, Clone)]
struct Drag {
    /// `over`, `leave` or `drop`.
    kind: &'static str,
    /// Pointer position in physical pixels.
    x: f64,
    y: f64,
    /// For `drop`: the registered files, as `file_read` takes them.
    files: Vec<Dropped>,
    /// For `drop`: why some files were left out.
    errors: Vec<String>,
    /// For `drop` of a folder: its executables, scanned here.
    folder: Option<crate::folder::Folder>,
}

#[derive(Serialize, Clone)]
struct Dropped {
    path: String,
    name: String,
}

pub fn handle(window: &Window, event: &DragDropEvent) {
    let send = |payload: Drag| {
        let _ = window.emit_to(window.label(), "binfera-drag", payload);
    };
    let empty = |kind, x, y| Drag {
        kind,
        x,
        y,
        files: Vec::new(),
        errors: Vec::new(),
        folder: None,
    };
    match event {
        DragDropEvent::Enter { position, .. } | DragDropEvent::Over { position } => {
            send(empty("over", position.x, position.y));
        }
        DragDropEvent::Leave => send(empty("leave", 0.0, 0.0)),
        DragDropEvent::Drop { paths, position } => {
            let (paths, window, position) = (paths.clone(), window.clone(), *position);
            // Hashing a large file takes a moment: not on the event loop.
            std::thread::spawn(move || {
                let projects = window.state::<Projects>();
                let mut drag = empty("drop", position.x, position.y);
                // A folder opens as a tree; it takes the drop whatever else came with it.
                if let Some(dir) = paths.iter().find(|p| p.is_dir()) {
                    match projects.open_folder(dir) {
                        Ok(f) => drag.folder = Some(f),
                        Err(e) => drag.errors.push(e),
                    }
                    let _ = window.emit_to(window.label(), "binfera-drag", drag);
                    return;
                }
                for path in &paths {
                    match projects.register(path) {
                        Ok(p) => drag.files.push(Dropped {
                            path: p.path,
                            name: p.name,
                        }),
                        Err(e) => drag.errors.push(format!(
                            "{}: {e}",
                            path.file_name()
                                .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
                        )),
                    }
                }
                let _ = window.emit_to(window.label(), "binfera-drag", drag);
            });
        }
        _ => {}
    }
}
