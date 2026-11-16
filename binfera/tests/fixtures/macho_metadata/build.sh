#!/bin/sh
set -eu
cd "$(dirname "$0")"
for arch in x86_64 arm64; do
    xcrun clang -arch "$arch" -O1 -Wl,-no_objc_category_merging fixture.m -lobjc -o "objc-$arch"
    xcrun strip -x "objc-$arch"
    xcrun clang -arch "$arch" -O1 -Wl,-no_objc_category_merging fixture.m -lobjc -Wl,-no_fixup_chains -o "classic-$arch"
    xcrun strip -x "classic-$arch"
done
xcrun swiftc -emit-library -module-name Audit -O -target arm64-apple-macosx13.0 fixture.swift -o swift-arm64.dylib
xcrun strip -x swift-arm64.dylib
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -o go-x86_64 fixture.go
