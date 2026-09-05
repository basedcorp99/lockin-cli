#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
    echo "lockin requires macOS." >&2
    exit 1
fi
if [ "$#" -gt 1 ]; then
    echo "Usage: ./build.sh [output-directory]" >&2
    exit 1
fi
if ! command -v go >/dev/null 2>&1; then
    echo "Install Go 1.26 or newer: brew install go" >&2
    exit 1
fi
if ! xcrun --find clang >/dev/null 2>&1 || ! xcrun --sdk macosx --show-sdk-path >/dev/null 2>&1; then
    echo "Install Apple's Command Line Tools: xcode-select --install (full Xcode is not required)." >&2
    exit 1
fi

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=${1:-"$project_dir/build"}
mkdir -p "$out"
out=$(CDPATH= cd -- "$out" && pwd)
bundle="$out/Lockin Alerts.app"
mkdir -p "$bundle/Contents/MacOS"
(cd "$project_dir" && CGO_ENABLED=0 go build -trimpath -o "$out/lockin" .)
(cd "$project_dir" && \
    MACOSX_DEPLOYMENT_TARGET=12.0 CGO_ENABLED=1 \
    CGO_CFLAGS="${CGO_CFLAGS:--O2 -g} -mmacosx-version-min=12.0" \
    CGO_LDFLAGS="${CGO_LDFLAGS:--O2 -g} -mmacosx-version-min=12.0" \
    go build -trimpath -o "$bundle/Contents/MacOS/lockin-notify" ./cmd/lockin-notify)
cp "$project_dir/packaging/LockinAlerts-Info.plist" "$bundle/Contents/Info.plist"
/usr/bin/codesign --force --sign - --identifier local.lockin.notifications "$bundle"
/usr/bin/codesign --verify --strict "$bundle"
printf 'Built %s\nBuilt and locally signed %s\n' "$out/lockin" "$bundle"
