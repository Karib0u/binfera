# Mach-O language fixtures

Rebuild with `sh build.sh` on macOS with Xcode command-line tools, Swift and Go. The fixtures are source-built test programs and are never executed by analysis tests.

- `objc-*`: stripped Objective-C classes, categories, scalar method encodings and selectors; modern chained fixups and ARM64 selector-specific message stubs.
- `classic-*`: the same sources using classic dyld bindings and indirect symbols.
- `swift-arm64.dylib`: a Swift 5 type descriptor and metadata accessor.
- `go-x86_64`: Go register ABI, function-table names and embedded DWARF parameter names.

Category merging is disabled to retain an independent category list. Local symbols are stripped from Objective-C/Swift fixtures to exercise metadata recovery. Toolchain changes may alter addresses and bytes; tests derive function addresses from symbols or metadata.
