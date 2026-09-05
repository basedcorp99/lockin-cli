#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
    echo "lockin requires macOS." >&2
    exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
    echo "Run ./install.sh as your normal user; it invokes sudo only for installation." >&2
    exit 1
fi
if ! command -v go >/dev/null 2>&1; then
    echo "Install Go 1.26 or newer first: brew install go" >&2
    exit 1
fi
if [ "$#" -gt 1 ]; then
    echo "Usage: ./install.sh [configuration-path]" >&2
    exit 1
fi

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
config=${1:-"$HOME/.config/lockin/config.json"}
case "$config" in
    /*) ;;
    *) config="$PWD/$config" ;;
esac
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/lockin-build.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM

"$project_dir/build.sh" "$build_dir"
if [ ! -e "$config" ]; then
    mkdir -p "$(dirname -- "$config")"
    # noclobber also protects against a file appearing after the existence check.
    (umask 077; set -C; cat "$project_dir/config.example.json" > "$config")
    echo "Created $config (example schedule is disabled)."
fi
"$build_dir/lockin" check --config "$config"
sudo "$build_dir/lockin" install --owner "$(id -u)" --config "$config" --notifications-bundle "$build_dir/Lockin Alerts.app"
"/usr/local/bin/lockin" reload --config "$config"
"/usr/local/bin/lockin" status
printf '\nConfiguration: %s\nEdit it, then run: lockin reload --config "%s"\n' "$config" "$config"
echo 'Native notifications remain opt-in. When ready, run: lockin alerts authorize'
case ":$PATH:" in
    *:/usr/local/bin:*) ;;
    *) echo 'Add /usr/local/bin to your shell PATH to invoke lockin by name.' ;;
esac
