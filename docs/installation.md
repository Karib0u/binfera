# Installation

Binfera needs no installation to try: [binfera.io](https://binfera.io) runs the whole engine in your browser. Install it when you want the desktop app, the command line, or an AI agent connection.

All downloads are on the [Releases page](https://github.com/Karib0u/binfera/releases). Command-line releases are tagged `v*`; desktop releases are tagged `desktop-v*`.

## Command-line tool

`binfera` is a single executable that includes the capa rules and the decompiler.

=== "macOS and Linux"

    ```sh
    curl -fsSL https://binfera.io/install.sh | sh
    ```

=== "Windows (PowerShell)"

    ```powershell
    irm https://binfera.io/install.ps1 | iex
    ```

The script downloads the archive for your machine, checks it against the release's `SHA256SUMS`, and installs to `~/.binfera/bin` (`%LOCALAPPDATA%\binfera\bin` on Windows). Nothing outside that folder is touched. Add the folder to your `PATH` as the last line of the output says.

| Variable | Effect |
|---|---|
| `BINFERA_VERSION` | Install a specific release tag, such as `v1.0.0`, instead of the latest |
| `BINFERA_HOME` | Install somewhere other than `~/.binfera` |

To install by hand, download the archive for your platform from Releases, check it against `SHA256SUMS`, and unpack it anywhere.

| Platform | Archive |
|---|---|
| Linux x86-64 (glibc 2.35 or newer) | `binfera-<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux arm64 (glibc 2.35 or newer) | `binfera-<version>-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Apple silicon | `binfera-<version>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `binfera-<version>-x86_64-apple-darwin.tar.gz` |
| Windows x86-64 | `binfera-<version>-x86_64-pc-windows-msvc.zip` |

## Desktop app

Download the installer for your system from a `desktop-v*` release and run it. The desktop app keeps your renames, comments and recent files, and shares its project database with the command-line MCP server.

| Platform | Installer |
|---|---|
| macOS | `.dmg` (Apple silicon or Intel) |
| Windows | `.exe` (NSIS) or `.msi` |
| Linux | `.deb`, `.rpm` or `.AppImage` |

## Code signing

- **macOS:** the app and the command-line tool are signed with a Developer ID certificate and notarised by Apple.
- **Windows:** the installers and `binfera.exe` are **not signed**. Windows SmartScreen shows a warning the first time; choose **More info**, then **Run anyway**. Check the download against the release's `SHA256SUMS` first.
- **Linux:** packages are not signed. Check them against `SHA256SUMS`.

## Antivirus warnings

Binfera is a malware analysis tool: it ships capa's detection rules and FLIRT signatures, and you will be opening malicious files with it. Some antivirus products flag analysis tools or the samples you handle. Binfera never executes the file it analyzes; [function emulation](emulation.md) runs in an isolated emulator and only when you ask for it.

## Build from source

You need Rust 1.87 or newer, a C++ toolchain and git (zlib on macOS and Linux, Visual Studio Build Tools on Windows).

```sh
git clone https://github.com/Karib0u/binfera.git
cd binfera
git submodule update --init rules
cargo build --release -p binfera-cli --features decompiler
target/release/binfera --version
```

With the rules submodule present, the build embeds the rules in the binary. The web and desktop builds are described in [Development](development.md).

## Update and uninstall

Run the install script again to update. To uninstall the command-line tool, delete `~/.binfera`. Saved projects live in the user data directory described under [What is stored](mcp.md#what-is-stored); delete that folder too if you want them gone.
