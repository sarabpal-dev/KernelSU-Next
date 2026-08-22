#!/bin/bash
set -e

# ==============================================================================
# ksud Automated Build Script
# Targets: arm64-v8a (default), x86_64, armeabi-v7a, x86, or all
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Detect Android NDK
if [ -z "$ANDROID_NDK_HOME" ] && [ -z "$ANDROID_NDK_ROOT" ]; then
    NDK_CANDIDATES=(
        "$HOME/Android/Sdk/ndk/27.2.12479018"
        "$HOME/Android/Sdk/ndk/29.0.14206865"
        "$HOME/android-ndk-r23"
        "$HOME/Android/Sdk/ndk"/*
        "$HOME/android-ndk-"*
        "/opt/android-ndk"
        "/opt/android-sdk/ndk"/*
    )
    for cand in "${NDK_CANDIDATES[@]}"; do
        if [ -d "$cand" ] && [ -f "$cand/source.properties" ]; then
            export ANDROID_NDK_HOME="$cand"
            export ANDROID_NDK_ROOT="$cand"
            break
        fi
    done
fi

if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "[-] Error: Android NDK not found! Please set ANDROID_NDK_HOME or install NDK."
    exit 1
fi
echo "[+] Using Android NDK: $ANDROID_NDK_HOME"

# 2. Check cargo-ndk
if ! command -v cargo-ndk &>/dev/null; then
    if [ -f "$HOME/.cargo/bin/cargo-ndk" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        echo "[*] cargo-ndk not found. Installing cargo-ndk..."
        cargo install cargo-ndk
    fi
fi

# 3. Parse target argument
TARGET_ARG="${1:-arm64-v8a}"
API_LEVEL="${API_LEVEL:-26}" # API 26+ required for __system_property_read_callback

case "$TARGET_ARG" in
    arm64|arm64-v8a|aarch64)
        TARGETS=("arm64-v8a")
        RUST_TARGETS=("aarch64-linux-android")
        ;;
    x86_64|x64)
        TARGETS=("x86_64")
        RUST_TARGETS=("x86_64-linux-android")
        ;;
    arm|armeabi-v7a|armv7)
        TARGETS=("armeabi-v7a")
        RUST_TARGETS=("armv7-linux-androideabi")
        ;;
    x86|i686)
        TARGETS=("x86")
        RUST_TARGETS=("i686-linux-android")
        ;;
    all)
        TARGETS=("arm64-v8a" "x86_64" "armeabi-v7a" "x86")
        RUST_TARGETS=("aarch64-linux-android" "x86_64-linux-android" "armv7-linux-androideabi" "i686-linux-android")
        ;;
    *)
        echo "[-] Unknown target: $TARGET_ARG"
        echo "    Supported targets: arm64-v8a, x86_64, armeabi-v7a, x86, all"
        exit 1
        ;;
esac

# 4. Build target(s)
OUT_DIR="$SCRIPT_DIR/out"
mkdir -p "$OUT_DIR"

for i in "${!TARGETS[@]}"; do
    TARGET="${TARGETS[$i]}"
    RUST_TARGET="${RUST_TARGETS[$i]}"

    echo ""
    echo "=========================================================="
    echo "  Building ksud for $TARGET (Target: $RUST_TARGET, API: $API_LEVEL)"
    echo "=========================================================="

    # Ensure rustup target is installed
    if ! rustup target list | grep -q "$RUST_TARGET (installed)"; then
        echo "[*] Adding rust target $RUST_TARGET..."
        rustup target add "$RUST_TARGET" || true
    fi

    # Run cargo ndk build with minimum API 26
    cargo ndk -t "$TARGET" -P "$API_LEVEL" build --release

    BIN_PATH="target/$RUST_TARGET/release/ksud"
    if [ -f "$BIN_PATH" ]; then
        DEST="$OUT_DIR/ksud-$TARGET"
        cp "$BIN_PATH" "$DEST"
        chmod +x "$DEST"
        
        # Also copy as default ksud if single target
        if [ "$TARGET_ARG" != "all" ]; then
            cp "$BIN_PATH" "$SCRIPT_DIR/ksud"
            chmod +x "$SCRIPT_DIR/ksud"
        fi

        echo "[✓] Successfully built: $DEST"
        ls -lh "$DEST"
    else
        echo "[-] Error: Expected binary not found at $BIN_PATH"
        exit 1
    fi
done

echo ""
echo "=========================================================="
echo "  Build Completed Successfully!"
echo "=========================================================="
if [ "$TARGET_ARG" != "all" ]; then
    echo "  -> Output binary: $SCRIPT_DIR/ksud"
fi
ls -lh "$OUT_DIR"/ksud-*
