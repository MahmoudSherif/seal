#!/usr/bin/env bash
# verify.sh — verify that a deployed seal page is running unmodified code.
#
# Usage:
#   ./verify.sh                                # verify the local web/ folder
#   ./verify.sh https://you.github.io/seal/    # verify a deployed site
#
# This script computes the SHA-256 of all the JS files (vendored libraries
# plus our app code) concatenated in load order, and compares it against
# the value in INTEGRITY.txt. The deployed page also computes and displays
# this same hash in the "Verify this page" badge, so:
#
#   1. Run this script with the deployed URL.
#   2. Open the deployed page and read the badge.
#   3. Compare the two hashes — if they match, the page is running exactly
#      the bytes in this repository.

set -euo pipefail

SOURCE="${1:-./}"
SCRIPTS=(
    "vendor/scrypt.js"
    "vendor/pako.min.js"
    "tar.js"
    "zip.js"
    "seal.js"
    "app.js"
)

cleanup() { [[ -n "${TMPDIR:-}" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; }
trap cleanup EXIT

if [[ "$SOURCE" =~ ^https?:// ]]; then
    # Strip trailing slash for clean URL building.
    BASE="${SOURCE%/}"
    TMPDIR=$(mktemp -d)
    echo "fetching from $BASE/"
    for f in "${SCRIPTS[@]}"; do
        target="$TMPDIR/$f"
        mkdir -p "$(dirname "$target")"
        if ! curl -sSf -o "$target" "$BASE/$f"; then
            echo "error: failed to fetch $BASE/$f" >&2
            exit 1
        fi
        printf "  fetched %-22s (%s bytes)\n" "$f" "$(wc -c < "$target")"
    done
    PREFIX="$TMPDIR"
else
    PREFIX="${SOURCE%/}"
    if [[ ! -d "$PREFIX" ]]; then
        echo "error: $PREFIX is not a directory" >&2
        exit 1
    fi
    for f in "${SCRIPTS[@]}"; do
        if [[ ! -f "$PREFIX/$f" ]]; then
            echo "error: $PREFIX/$f does not exist" >&2
            exit 1
        fi
    done
fi

# Concatenate all files in order and hash.
HASH=$(cat "${SCRIPTS[@]/#/$PREFIX/}" | sha256sum | awk '{print $1}')

echo
echo "computed SHA-256 of concatenated scripts:"
echo "  $HASH"

INTEGRITY_FILE="$(dirname "$0")/INTEGRITY.txt"
if [[ -f "$INTEGRITY_FILE" ]]; then
    EXPECTED=$(grep -oE '^[a-f0-9]{64}' "$INTEGRITY_FILE" | head -1 || true)
    echo
    echo "expected hash from INTEGRITY.txt:"
    echo "  $EXPECTED"
    echo
    if [[ "$HASH" == "$EXPECTED" ]]; then
        echo "✓ MATCH — these files match the published integrity hash."
        exit 0
    else
        echo "✗ MISMATCH — the files differ from INTEGRITY.txt."
        echo
        echo "This could mean one of:"
        echo "  • The repo has changed since INTEGRITY.txt was written"
        echo "    (regenerate it with: cd web && bash verify.sh > INTEGRITY.txt)"
        echo "  • The deployed site has been tampered with"
        echo "  • The vendored libraries were updated"
        exit 1
    fi
else
    echo
    echo "(no INTEGRITY.txt found at $INTEGRITY_FILE — write one with:)"
    echo "  echo \"$HASH  seal web app\" > $INTEGRITY_FILE"
fi
