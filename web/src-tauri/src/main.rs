// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // The AppImage bundles its own GTK, which aborts on recent Wayland desktops (seen on Ubuntu
    // 26.04: an assertion on the cursor theme in GDK's Wayland backend). Run it through XWayland
    // instead, unless the user chose a GTK backend. The .deb and .rpm use the system GTK.
    #[cfg(target_os = "linux")]
    if std::env::var_os("APPIMAGE").is_some()
        && std::env::var_os("GDK_BACKEND").is_none()
        && std::env::var_os("WAYLAND_DISPLAY").is_some()
        && std::env::var_os("DISPLAY").is_some()
    {
        std::env::set_var("GDK_BACKEND", "x11");
    }
    binfera_desktop::run();
}
